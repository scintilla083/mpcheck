# bash completion for mpcheck
#
# Install (any one):
#   - copy to ~/.local/share/bash-completion/completions/mpcheck
#   - or: source /path/to/mpcheck.bash  (e.g. from ~/.bashrc)

_mpcheck()
{
    local cur prev subcmds flags
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    subcmds="scan locate"
    flags="--engine --verbose"

    # --engine takes a directory
    if [[ "$prev" == "--engine" ]]; then
        COMPREPLY=( $(compgen -d -- "$cur") )
        return 0
    fi

    # locate the subcommand already on the line, if any
    local i word cmd=""
    for (( i=1; i < COMP_CWORD; i++ )); do
        word="${COMP_WORDS[i]}"
        if [[ "$word" == "--engine" ]]; then
            (( i++ ))                      # skip its value
        elif [[ "$word" == "scan" || "$word" == "locate" ]]; then
            cmd="$word"
            break
        fi
    done

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return 0
    fi

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") )
    else
        # scan/locate take file arguments
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
    return 0
}
complete -o filenames -F _mpcheck mpcheck
