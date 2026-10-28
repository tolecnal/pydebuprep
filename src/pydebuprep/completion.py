"""bash and zsh completion scripts, generated from the argument parser and check registry.

The packaged files under completions/ are the output of these functions; a test fails
if they drift, so new commands, flags, checks and options are always completed.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field

from pydebuprep import checks

# How to complete an option's value, by argparse dest.
VALUE_KINDS = {
    "config": "file",
    "output": "file",
    "baseline": "file",
    "output_dir": "dir",
    "snapshot_dir": "dir",
    "checks": "checks",
    "skip": "checks",
    "check_option": "check-options",
}


@dataclass
class OptionSpec:
    flags: list[str]
    help: str
    takes_value: bool
    kind: str = ""  # file, dir, checks, check-options, choices or "" (free text)
    choices: list[str] = field(default_factory=list)
    repeatable: bool = False
    exclusive: list[str] = field(default_factory=list)  # flags it can't be combined with


@dataclass
class CommandSpec:
    name: str
    help: str
    options: list[OptionSpec]
    positional_choices: list[str] = field(default_factory=list)


@dataclass
class CompletionSpec:
    commands: dict[str, CommandSpec]
    global_flags: list[OptionSpec]
    check_ids: list[str]
    check_options: list[str]
    # "check.option" -> values worth offering after the '=' (booleans only, for now)
    check_option_values: dict[str, list[str]] = field(default_factory=dict)


# Words written into the scripts unquoted (commands, flags, choices, check ids and options).
SAFE_WORD = re.compile(r"^[A-Za-z0-9._,/:=+@-]+$")


def _safe(word: str) -> str:
    if not SAFE_WORD.match(word):
        raise ValueError(
            f"{word!r} cannot be completed safely: completion words may only contain "
            "letters, digits and ._,/:=+@-"
        )
    return word


def _help(action: argparse.Action, prog: str) -> str:
    """Expand %(default)s-style placeholders the way argparse's help output does."""
    text = action.help or ""
    params = dict(vars(action), prog=prog)
    if params.get("choices") is not None:
        params["choices"] = ", ".join(str(c) for c in params["choices"])
    try:
        return text % params
    except (KeyError, TypeError, ValueError):
        return text


def _option(action: argparse.Action, prog: str, exclusive: list[str]) -> OptionSpec:
    takes_value = action.nargs != 0
    choices = [_safe(str(c)) for c in action.choices] if action.choices else []
    kind = "choices" if choices else (VALUE_KINDS.get(action.dest, "") if takes_value else "")
    return OptionSpec(
        flags=[
            _safe(f)
            for f in sorted(action.option_strings, key=lambda f: (not f.startswith("--"), f))
        ],
        help=_help(action, prog),
        takes_value=takes_value,
        kind=kind,
        choices=choices,
        repeatable=isinstance(action, argparse._AppendAction),
        exclusive=exclusive,
    )


def _exclusions(parser: argparse.ArgumentParser) -> dict[argparse.Action, list[str]]:
    excluded: dict[argparse.Action, list[str]] = {}
    for group in parser._mutually_exclusive_groups:
        flags = [f for a in group._group_actions for f in a.option_strings]
        for action in group._group_actions:
            excluded[action] = [f for f in flags if f not in action.option_strings]
    return excluded


def completion_spec() -> CompletionSpec:
    # Relies on argparse internals (_actions, _choices_actions, _SubParsersAction,
    # _AppendAction), stable from 3.10 to 3.14; test_spec_covers_every_command_and_option
    # and the drift tests catch a change.
    from pydebuprep.cli import build_parser

    parser = build_parser()
    commands: dict[str, CommandSpec] = {}
    global_flags: list[OptionSpec] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            helps = {a.dest: a.help or "" for a in action._choices_actions}
            for name, sub in action.choices.items():
                options, positional = [], []
                excluded = _exclusions(sub)
                for sub_action in sub._actions:
                    if sub_action.option_strings:
                        options.append(
                            _option(sub_action, parser.prog, excluded.get(sub_action, []))
                        )
                    elif sub_action.choices:
                        positional = [_safe(str(c)) for c in sub_action.choices]
                commands[_safe(name)] = CommandSpec(name, helps.get(name, ""), options, positional)
        elif action.option_strings:
            global_flags.append(_option(action, parser.prog, []))
    return CompletionSpec(
        commands=commands,
        global_flags=global_flags,
        check_ids=sorted(_safe(cls.id) for cls in checks.ALL_CHECKS),
        check_options=sorted(
            _safe(f"{cls.id}.{o.name}=") for cls in checks.ALL_CHECKS for o in cls.options
        ),
        check_option_values={
            f"{cls.id}.{o.name}": ["true", "false"]
            for cls in checks.ALL_CHECKS
            for o in cls.options
            if isinstance(o.default, bool)
        },
    )


HEADER = "generated by `pydebuprep completion {shell}`; do not edit by hand"


def _words(items: list[str]) -> str:
    return " ".join(items)


def bash_completion() -> str:
    spec = completion_spec()
    # One `case $prev` arm per completion action; the script can't tell commands apart
    # there, so a flag must complete the same way everywhere.
    flag_action: dict[str, str] = {}
    value_cases: dict[str, list[str]] = {}
    for command in spec.commands.values():
        for opt in command.options:
            if not opt.takes_value:
                continue
            action = _value_action_bash(opt, spec)
            for flag in opt.flags:
                if flag_action.setdefault(flag, action) != action:
                    raise ValueError(f"{flag} completes differently in different commands")
                if flag not in value_cases.setdefault(action, []):
                    value_cases[action].append(flag)
    cases = "\n".join(
        f"        {'|'.join(flags)})\n            {action}\n            return\n            ;;"
        for action, flags in value_cases.items()
    )
    per_command = "\n".join(
        f'        {c.name}) opts="{_words(sorted(f for o in c.options for f in o.flags))}" ;;'
        for c in spec.commands.values()
    )
    positional = "\n".join(
        f'        {c.name}) words_for_cmd="{_words(c.positional_choices)}" ;;'
        for c in spec.commands.values()
        if c.positional_choices
    )
    global_flags = _words(sorted(f for o in spec.global_flags for f in o.flags))
    option_values = "\n".join(
        f'        {key}) values="{_words(vals)}" ;;'
        for key, vals in sorted(spec.check_option_values.items())
    )
    return f"""# bash completion for pydebuprep -- {HEADER.format(shell="bash")}
#
# Installed packages load this automatically through bash-completion. Elsewhere:
#   source <(pydebuprep completion bash)

_pydebuprep_files() {{
    # Use bash-completion's _filedir when available, plain compgen otherwise.
    if declare -F _filedir >/dev/null; then
        _filedir "$@"
    elif [[ $1 == -d ]]; then
        COMPREPLY=($(compgen -d -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}}

_pydebuprep_check_option() {{
    if [[ $cur == *=* ]]; then
        # readline replaces only the text after '=', so reply with values alone.
        local values=""
        case ${{cur%%=*}} in
{option_values}
        esac
        COMPREPLY=($(compgen -W "$values" -- "${{cur#*=}}"))
        return
    fi
    COMPREPLY=($(compgen -W "{_words(spec.check_options)}" -- "$cur"))
    compopt -o nospace 2>/dev/null
}}

_pydebuprep_list() {{
    # Complete one item of a comma-separated list, leaving out items already given.
    local prefix="" word="$cur" item remaining=""
    if [[ $cur == *,* ]]; then
        prefix="${{cur%,*}},"
        word="${{cur##*,}}"
    fi
    for item in $1; do
        [[ ",$prefix" == *",$item,"* ]] || remaining="$remaining $item"
    done
    COMPREPLY=($(compgen -P "$prefix" -W "$remaining" -- "$word"))
    compopt -o nospace 2>/dev/null
}}

_pydebuprep() {{
    local cur prev words cword
    if declare -F _init_completion >/dev/null; then
        _init_completion -n =: || return
    else
        cur=${{COMP_WORDS[COMP_CWORD]}}
        prev=${{COMP_WORDS[COMP_CWORD - 1]}}
        words=("${{COMP_WORDS[@]}}")
        cword=$COMP_CWORD
    fi

    # --flag=value: complete the value; readline replaces only the text after '='.
    if [[ $cur == --*=* ]]; then
        prev=${{cur%%=*}}
        cur=${{cur#*=}}
    fi

    # Like the CLI: a command is only recognised as the first word.
    local commands="{_words(list(spec.commands))}"
    local cmd=""
    if ((cword > 1)); then
        case " $commands " in
            *" ${{words[1]}} "*) cmd=${{words[1]}} ;;
        esac
    fi

    case $prev in
{cases}
    esac

    local opts words_for_cmd=""
    case ${{cmd:-report}} in
{per_command}
    esac
    case $cmd in
{positional}
    esac

    if [[ $cur == -* ]]; then
        ((cword == 1)) && opts="$opts {global_flags}"
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    elif ((cword == 1)); then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
    elif [[ -n $words_for_cmd ]]; then
        COMPREPLY=($(compgen -W "$words_for_cmd" -- "$cur"))
    fi
}}

complete -F _pydebuprep pydebuprep
"""


def _value_action_bash(opt: OptionSpec, spec: CompletionSpec) -> str:
    if opt.kind == "choices":
        return f'COMPREPLY=($(compgen -W "{_words(opt.choices)}" -- "$cur"))'
    if opt.kind == "file":
        return "_pydebuprep_files"
    if opt.kind == "dir":
        return "_pydebuprep_files -d"
    if opt.kind == "checks":
        return f'_pydebuprep_list "{_words(spec.check_ids)}"'
    if opt.kind == "check-options":
        return "_pydebuprep_check_option"
    return ":"


def _zsh_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("'", "'\\''")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace(":", "\\:")
    )


def _zsh_action(opt: OptionSpec) -> str:
    if opt.kind == "choices":
        return f"({' '.join(opt.choices)})"
    return {
        "file": "_files",
        "dir": "_files -/",
        "checks": "_pydebuprep_checks",
        "check-options": "_pydebuprep_check_options",
    }.get(opt.kind, " ")


def _zsh_specs(options: list[OptionSpec]) -> list[str]:
    specs = []
    for opt in options:
        help_text = _zsh_escape(opt.help.split(" (default")[0])
        # Exclude the option's own aliases (unless repeatable) and its argparse group.
        excluded = sorted(set(opt.exclusive) | (set() if opt.repeatable else set(opt.flags)))
        exclusive = f"({' '.join(excluded)})" if len(excluded) > 1 or opt.exclusive else ""
        prefix = "*" if opt.repeatable else ""
        value = f":{opt.flags[0].lstrip('-')}:{_zsh_action(opt)}" if opt.takes_value else ""
        for flag in opt.flags:
            # "--flag=" accepts the value either after '=' or as the next word.
            name = f"{flag}=" if opt.takes_value and flag.startswith("--") else flag
            specs.append(f"'{exclusive}{prefix}{name}[{help_text}]{value}'")
    return specs


def zsh_completion() -> str:
    spec = completion_spec()
    command_lines = "\n".join(
        f"        '{c.name}:{_zsh_escape(c.help)}'" for c in spec.commands.values()
    )
    functions = []
    for c in spec.commands.values():
        specs = _zsh_specs(c.options)
        if c.positional_choices:
            specs.append(f"'1:{c.name}:({' '.join(c.positional_choices)})'")
        body = " \\\n        ".join(specs) if specs else ""
        functions.append(
            f"_pydebuprep_{c.name.replace('-', '_')}() {{\n"
            f"    _arguments -s -S \\\n        {body}\n}}"
            if body
            else f"_pydebuprep_{c.name.replace('-', '_')}() {{\n    _message 'no options'\n}}"
        )
    report = spec.commands["report"]
    own = {f for o in report.options for f in o.flags}
    first_specs = _zsh_specs(report.options) + _zsh_specs(
        [o for o in spec.global_flags if not set(o.flags) & own]
    )
    first = " \\\n        ".join(first_specs)
    option_values = "\n".join(
        f"        {key}) values=({' '.join(vals)}) ;;"
        for key, vals in sorted(spec.check_option_values.items())
    )
    check_ids = " ".join(spec.check_ids)
    check_options = " ".join(spec.check_options)
    return f"""#compdef pydebuprep
# zsh completion for pydebuprep -- {HEADER.format(shell="zsh")}
#
# Installed packages put this in a directory on $fpath. Elsewhere, after compinit:
#   source <(pydebuprep completion zsh)

_pydebuprep_checks() {{
    _values -s , 'check' {check_ids}
}}

_pydebuprep_check_options() {{
    if [[ $PREFIX == *=* ]]; then
        local -a values
        case ${{PREFIX%%=*}} in
{option_values}
        esac
        compset -P '*='
        compadd -a values
        return
    fi
    local -a opts
    opts=({check_options})
    compadd -S '' -a opts
}}

# Options valid when they come first, i.e. for the implicit report command; only
# here are the top-level flags (--version, --help) allowed.
_pydebuprep_first() {{
    _arguments -s -S \\
        {first}
}}

{chr(10).join(chr(10).join([f, ""]) for f in functions)}
_pydebuprep() {{
    local -a commands
    commands=(
{command_lines}
    )
    if (( CURRENT == 2 )) && [[ $PREFIX != -* ]]; then
        _describe -t commands 'pydebuprep command' commands
        return
    fi
    if (( CURRENT == 2 )); then
        _pydebuprep_first
        return
    fi
    local cmd=report
    if (( ${{commands[(I)${{words[2]}}:*]}} )); then
        cmd=${{words[2]}}
        shift words
        (( CURRENT-- ))
    fi
    _pydebuprep_${{cmd//-/_}}
}}

# Autoloaded from fpath (packaged install) or sourced: source <(pydebuprep completion zsh)
if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
    _pydebuprep "$@"
else
    compdef _pydebuprep pydebuprep
fi
"""
