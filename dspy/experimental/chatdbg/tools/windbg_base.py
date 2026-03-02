"""Core WinDbg debugging tools: debug command execution and source code display."""

import re
from typing import Callable


def windbg_command_is_safe(cmd: str) -> bool:
    """Check if a WinDbg command is safe (read-only)."""
    cmd = cmd.strip()
    if not cmd:
        return False
    command_name = cmd.split()[0].lower()

    # Allowed unconditionally: read-only commands.
    safe_commands = {
        "k",
        "kb",
        "kp",
        "kn",
        "kv",
        "kd",
        "kc",  # Stack
        ".frame",  # Frame
        "lm",
        "x",
        "ln",  # Modules and symbols
        "u",
        "uf",
        "ub",  # Disassembly
        "dv",
        "dt",  # Variables and types
        "db",
        "dw",
        "dd",
        "dq",
        "dp",
        "da",
        "du",  # Memory display
        "!analyze",
        ".ecxr",
        ".exr",
        ".lastevent",  # Analysis
        "!clrstack",
        "!dumpobj",
        "!dumpstackobjects",
        "!dumpheap",  # SOS/CLR
        "!dumpmt",
        "!name2ee",
        "!eestack",
        "!threads",
        "!gcroot",
        "!pe",
        "!syncblk",
        "!finalizequeue",
        "!dumparray",
        "!threadpool",
        "!dumpasync",
        "!dumpvc",
        "!dumpdomain",
        "!dumpmodule",
        "!tt",
        "!positions",  # TTD
        "version",
        "vertarget",
        "!peb",
        "!teb",  # Info
        ".scriptproviders",
        ".scriptlist",  # Script provider queries
    }

    if command_name in safe_commands:
        return True

    if command_name == "?":
        args = cmd[1:].strip()
        return re.fullmatch(r"[\w@$+\-*/() .]+", args) is not None

    if command_name == "r":
        args = cmd[len(cmd.split()[0]) :].strip()
        return "=" not in args

    if command_name == "dx":
        args = cmd[len(cmd.split()[0]) :].strip()
        return re.fullmatch(r"[\w@$.\[\] ]+", args) is not None

    return False


def make_base_tools(bridge, unsafe: bool = False) -> list[Callable]:
    """Create base debugging tools bound to a CDBBridge instance.

    Args:
        bridge: CDBBridge instance for command execution.
        unsafe: If True, skip safety checks on commands.

    Returns:
        List of tool functions for DSPy ReAct.
    """

    def debug(command: str) -> str:
        """Run a WinDbg/CDB command on the stopped program and get the response.

        Useful commands: 'k' (stack trace), 'dv' (local variables), 'dt <type> <addr>' (display type),
        'dx <expr>' (evaluate expression), '!analyze -v' (crash analysis), 'r' (registers),
        'u <addr>' (disassemble), 'db/dd/dq <addr>' (memory display), 'ln <addr>' (nearest symbol),
        '.frame <n>' (select frame), 'x <pattern>' (search symbols).
        """
        if not unsafe and not windbg_command_is_safe(command):
            return f"Command `{command}` is not allowed."
        return bridge.run_command(command)

    def get_code_surrounding(filename: str, line_number: int) -> str:
        """Return source code surrounding the given line number in the specified file.

        Shows approximately 10 lines of context (7 before, 3 after the target line).
        """
        try:
            import llm_utils

            lines, first = llm_utils.read_lines(filename, line_number - 7, line_number + 3)
            return llm_utils.number_group_of_lines(lines, first)
        except ImportError:
            # Fallback if llm_utils not available
            try:
                with open(filename, "r") as f:
                    all_lines = f.readlines()
                start = max(0, line_number - 8)
                end = min(len(all_lines), line_number + 3)
                result = []
                for i in range(start, end):
                    marker = ">>>" if i == line_number - 1 else "   "
                    result.append(f"{marker} {i + 1:4d} {all_lines[i].rstrip()}")
                return "\n".join(result)
            except FileNotFoundError:
                return f"file '{filename}' not found."

    return [debug, get_code_surrounding]
