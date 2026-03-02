"""JavaScript scripting tool for WinDbg/CDB JsProvider."""

import os
import re
import tempfile
from typing import Callable


_JS_TEMPLATE = """\
"use strict";

function run() {{
{code}
}}
"""

_DANGEROUS_PATTERNS = [
    (r'ExecuteCommand\s*\(\s*["\']e[bwd]\s', "memory write (eb/ew/ed)"),
    (r'ExecuteCommand\s*\(\s*["\'](?:g|p|t)\s*["\']', "execution resume (g/p/t)"),
    (r'ExecuteCommand\s*\(\s*["\']r\s+\w+=', "register write (r reg=)"),
    (r'ExecuteCommand\s*\(\s*["\']\.kill', "kill target (.kill)"),
    (r'ExecuteCommand\s*\(\s*["\']\.detach', "detach target (.detach)"),
    (r'ExecuteCommand\s*\(\s*["\']\.restart', "restart target (.restart)"),
    (r'ExecuteCommand\s*\(\s*["\']bp\s', "set breakpoint (bp)"),
]

_COMPILED_PATTERNS = [(re.compile(pat, re.IGNORECASE), desc) for pat, desc in _DANGEROUS_PATTERNS]


def _check_js_safety(code: str) -> str | None:
    """Scan JS code for dangerous patterns. Returns None if safe, or description of violation."""
    for pattern, description in _COMPILED_PATTERNS:
        if pattern.search(code):
            return description
    return None


def make_js_tools(bridge, unsafe: bool = False) -> list[Callable]:
    """Create JavaScript scripting tools bound to a CDBBridge instance."""

    def run_js(code: str) -> str:
        """Execute custom JavaScript code inside CDB's JsProvider for multi-step analysis.

        Write the function body (not the function declaration) — it will be wrapped in a
        run() function automatically. Use `return` to send results back.

        Available APIs: host.currentProcess, host.currentThread, host.currentSession,
        host.memory, host.parseInt64(), host.namespace.Debugger,
        host.diagnostics.debugLog(). Use
        host.namespace.Debugger.Utility.Control.ExecuteCommand() to run CDB commands
        and capture output.

        IMPORTANT: ExecuteCommand() returns an iterable of lines, NOT a string — collect
        with for...of into an array. Use for...of (not for...in) for all host objects.
        host.parseInt64() takes a STRING argument (e.g. '0x1000'), not a number.
        """
        if not unsafe:
            violation = _check_js_safety(code)
            if violation:
                return f"Code blocked by safety check: {violation}. Use unsafe=True to bypass."

        indented = "\n".join("    " + line for line in code.splitlines())
        js_content = _JS_TEMPLATE.format(code=indented)

        fd, tmp_path = tempfile.mkstemp(suffix=".js", prefix="chatdbg_js_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(js_content)

            load_output = bridge.run_command(f'.scriptload "{tmp_path}"')
            if load_output and any(err in load_output.lower() for err in ["error", "failed", "cannot", "unable"]):
                return f"Script load failed:\n{load_output}"

            try:
                output = bridge.run_command("dx @$scriptContents.run()")
            except Exception as e:
                output = f"Error executing script: {e}"

            try:
                bridge.run_command(f'.scriptunload "{tmp_path}"')
            except Exception:
                pass

            return output
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return [run_js]
