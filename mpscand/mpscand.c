// mpscand - persistent scanning daemon built on loadlibrary.
//
// Derived from mpclient.c in taviso/loadlibrary.
// Copyright (C) 2017 Tavis Ormandy  (original mpclient.c)
// Modifications Copyright (C) 2026 scintilla083
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License (see mpscand/LICENSE) for more details.
//
// Boots the Defender engine once, then serves scan requests from stdin so a
// front-end (mpcheck) can scan thousands of in-memory buffers without paying
// the engine boot cost each time. This is what makes gocheck-style signature
// bisection practical on Linux.
//
// Protocol (all little-endian), engine chatter goes to stderr:
//   request  (stdin) : u32 length, then <length> bytes of file content.
//                      length == 0xFFFFFFFF  -> quit.
//   response (stdout): u8 detected (0/1), u8 namelen, <namelen> name bytes.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"

const struct rlimit kUsageLimits[] = {
    [RLIMIT_CPU]    = { .rlim_cur = 3600, .rlim_max = RLIM_INFINITY },
    [RLIMIT_CORE]   = { .rlim_cur = 0,    .rlim_max = 0 },
};

DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

// Current request buffer and the result captured by the scan callback.
static const uint8_t *g_buffer;
static uint64_t       g_length;
static int            g_detected;
static char           g_threat[sizeof(((PSCANSTRUCT)0)->VirusName)];

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    // Same threat masks mpclient uses.
    if ((Scan->Flags & 0x08000022)
     || (Scan->Flags & 0x40010000) == 0x40010000) {
        g_detected = 1;
        // Keep the first (top level) threat name we see.
        if (g_threat[0] == '\0')
            snprintf(g_threat, sizeof g_threat, "%s", Scan->VirusName);
    }
    return 0;
}

static DWORD MemRead(PVOID this, uint64_t Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    uint64_t avail = Offset < g_length ? g_length - Offset : 0;
    DWORD n = Size < avail ? Size : (DWORD) avail;
    if (n)
        memcpy(Buffer, g_buffer + Offset, n);
    *SizeRead = n;
    return TRUE;
}

static DWORD MemGetSize(PVOID this, uint64_t *FileSize)
{
    *FileSize = g_length;
    return TRUE;
}

static PWCHAR MemGetName(PVOID this)
{
    return L"input";
}

static bool read_exact(void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(STDIN_FILENO, p, n);
        if (r <= 0)
            return false;
        p += r;
        n -= r;
    }
    return true;
}

static bool write_exact(const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = write(STDOUT_FILENO, p, n);
        if (r <= 0)
            return false;
        p += r;
        n -= r;
    }
    return true;
}

int main(int argc, char **argv, char **envp)
{
    HANDLE KernelHandle;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    SCAN_REPLY ScanReply;
    DWORD Result;
    struct pe_image image = {
        .entry = NULL,
        .name  = "engine/mpengine.dll",
    };

    if (pe_load_library(image.name, &image.image, &image.size) == false)
        errx(EXIT_FAILURE, "failed to load %s (run from the loadlibrary dir)", image.name);

    link_pe_images(&image, 1);
    process_extra_exports(image.image, ((PIMAGE_NT_HEADERS)(image.image +
        ((PIMAGE_DOS_HEADER)image.image)->e_lfanew))->OptionalHeader.BaseOfCode,
        "engine/mpengine.map");

    if (get_export("__rsignal", &__rsignal) == -1)
        errx(EXIT_FAILURE, "failed to resolve mpengine entrypoint");

    EXCEPTION_DISPOSITION ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord,
            struct _EXCEPTION_FRAME *EstablisherFrame,
            struct _CONTEXT *ContextRecord,
            struct _EXCEPTION_FRAME **DispatcherContext)
    {
        LogMessage("Toplevel Exception Handler Caught Exception");
        abort();
    }

    setup_nt_threadinfo(ExceptionHandler);
    image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);

    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);

    BootParams.ClientVersion     = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes        = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"engine";
    BootParams.ProductName       = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"quarantine";
    EngineConfig.Inclusions         = L"*.*";
    EngineConfig.EngineFlags        = 1 << 1;
    BootParams.EngineInfo   = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    if ((Result = __rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams)) != 0)
        errx(EXIT_FAILURE, "RSIG_BOOTENGINE failed %#x", Result);

    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(&ScanReply, sizeof ScanReply);
    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C            = 0x7fffffff;
    ScanDescriptor.Read    = MemRead;
    ScanDescriptor.GetSize = MemGetSize;
    ScanDescriptor.GetName = MemGetName;

    // Signal readiness: one zero byte so the parent knows boot succeeded.
    uint8_t ready = 0;
    write_exact(&ready, 1);

    for (;;) {
        uint32_t len;
        if (!read_exact(&len, sizeof len))
            break;
        if (len == 0xFFFFFFFFu)
            break;

        uint8_t *buf = len ? malloc(len) : (uint8_t *) "";
        if (len && !read_exact(buf, len))
            break;

        g_buffer   = buf;
        g_length   = len;
        g_detected = 0;
        g_threat[0] = '\0';

        __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);

        uint8_t out[2 + sizeof g_threat];
        uint8_t namelen = (uint8_t) strnlen(g_threat, sizeof g_threat);
        out[0] = g_detected ? 1 : 0;
        out[1] = namelen;
        memcpy(out + 2, g_threat, namelen);
        if (!write_exact(out, 2 + namelen))
            break;

        if (len)
            free(buf);
    }

    return 0;
}
