"""WinDbg JavaScript extension discovery, loading, and tool generation.

Discovers JS extensions installed on the system, loads them into WinDbg via
.scriptload, and generates DSPy-compatible tool functions for each extension
function. Extensions are called via dx @$scriptContents.<func>().
"""

import os
from typing import Callable


# ---------------------------------------------------------------------------
# Extension registry
# ---------------------------------------------------------------------------

JS_EXTENSION_REGISTRY = [
    {
        "name": "lldext",
        "script_paths": ["lldext/lldext.js", "lldext.js"],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "analyze",
                "tool_name": "js_lldext_analyze",
                "description": (
                    "Run lldext full analysis on the current debug target. "
                    "Provides function discovery, call path analysis, and TTD-aware diagnostics."
                ),
                "parameters": {},
            },
            {
                "js_func": "callpath",
                "tool_name": "js_lldext_callpath",
                "description": (
                    "Trace the call path to the current position using lldext. "
                    "Shows how execution reached the current point."
                ),
                "parameters": {},
            },
            {
                "js_func": "funcdiscover",
                "tool_name": "js_lldext_funcdiscover",
                "description": (
                    "Discover functions in the current module using lldext. "
                    "Lists functions with entry points and sizes."
                ),
                "parameters": {},
            },
        ],
    },
    {
        "name": "WinDbgCookbook",
        "script_paths": [
            "WinDbgCookbook/StackCorruptionDetection.js",
            "StackCorruptionDetection.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "detectStackCorruption",
                "tool_name": "js_detect_stack_corruption",
                "description": (
                    "Detect stack corruption by analyzing stack frames for "
                    "inconsistencies, overwritten return addresses, and canary violations."
                ),
                "parameters": {},
            },
        ],
    },
    {
        "name": "WinDbgCookbook_CallGraph",
        "script_paths": [
            "WinDbgCookbook/CallGraph.js",
            "CallGraph.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "collectCallGraph",
                "tool_name": "js_collect_call_graph",
                "description": (
                    "Collect and display the call graph for the current execution context. "
                    "Shows function call relationships."
                ),
                "parameters": {},
            },
        ],
    },
    {
        "name": "telescope",
        "script_paths": [
            "windbg-scripts/telescope/telescope.js",
            "telescope.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "telescope",
                "tool_name": "js_telescope",
                "description": (
                    "GEF-style memory telescope. Recursively dereferences pointers from "
                    "a given address, showing the chain of values. Useful for exploring "
                    "stack and heap layouts."
                ),
                "parameters": {
                    "address": {
                        "type": "string",
                        "description": "Memory address to telescope from (e.g., '@rsp', '0x7ffe1234').",
                    },
                },
                "required": ["address"],
            },
        ],
    },
    {
        "name": "codeCoverage",
        "script_paths": [
            "windbg-scripts/codecoverage/TTDcodecoverage.js",
            "TTDcodecoverage.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "codeCoverage",
                "tool_name": "js_ttd_code_coverage",
                "description": (
                    "Compute code coverage from a TTD (Time Travel Debugging) trace. "
                    "Shows which functions and code blocks were executed during the recording."
                ),
                "parameters": {},
            },
        ],
    },
]


# Standard locations where WinDbg JS extensions might be installed
_STANDARD_SEARCH_DIRS = [
    os.path.expandvars(r"%LOCALAPPDATA%\DBG\Scripts"),
    os.path.expandvars(r"%LOCALAPPDATA%\DBG\Extensions"),
    os.path.expandvars(r"%USERPROFILE%\Documents\WinDbg Scripts"),
    os.path.expandvars(r"%PROGRAMFILES%\Windows Kits\10\Debuggers\x64\winext"),
]


# ---------------------------------------------------------------------------
# Argument formatting
# ---------------------------------------------------------------------------


def _format_js_arg(value):
    """Format a Python value for use in a WinDbg dx JS function call."""
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _format_js_args(params_spec, kwargs):
    """Build the argument list string for a JS function call."""
    if not params_spec:
        return ""
    parts = []
    for name in params_spec:
        if name in kwargs:
            parts.append(_format_js_arg(kwargs[name]))
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_js_extensions(bridge, config_paths=""):
    """Discover available JS extensions.

    Args:
        bridge: CDBBridge instance for command execution.
        config_paths: Semicolon-separated extra search paths.

    Returns:
        List of extension dicts with resolved script_path.
        Empty list if JsProvider is not available.
    """
    if not bridge.detect_jsprovider():
        return []

    search_dirs = []
    if config_paths:
        search_dirs.extend(d.strip() for d in config_paths.split(";") if d.strip())
    search_dirs.extend(_STANDARD_SEARCH_DIRS)

    available = []
    for ext in JS_EXTENSION_REGISTRY:
        resolved_path = _find_script(ext["script_paths"], search_dirs)
        if resolved_path:
            available.append(
                {
                    "name": ext["name"],
                    "script_path": resolved_path,
                    "namespace": ext["namespace"],
                    "tools": ext["tools"],
                }
            )

    return available


def _find_script(relative_paths, search_dirs):
    """Search for a JS script file in the given directories."""
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for rel_path in relative_paths:
            full_path = os.path.join(search_dir, rel_path)
            if os.path.isfile(full_path):
                return full_path
    return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_js_extensions(bridge, extensions):
    """Load discovered JS extensions into WinDbg.

    Args:
        bridge: CDBBridge instance for command execution.
        extensions: List from discover_js_extensions().

    Returns:
        Dict of extension name -> True/False (success/failure).
    """
    results = {}
    for ext in extensions:
        script_path = ext["script_path"]
        try:
            output = bridge.run_command(f'.scriptload "{script_path}"')
            if output and any(
                err in output.lower() for err in ["error", "failed", "cannot", "unable"]
            ):
                results[ext["name"]] = False
            else:
                results[ext["name"]] = True
        except Exception:
            results[ext["name"]] = False
    return results


# ---------------------------------------------------------------------------
# Tool function factory
# ---------------------------------------------------------------------------


def _make_extension_tool(bridge, ext_name, namespace, js_func, tool_name, description, params, required=None):
    """Generate a DSPy-compatible tool function for a JS extension function.

    Returns a closure that calls bridge.run_command() to invoke the JS function.
    """
    if required is None:
        required = list(params.keys()) if params else []

    if params:
        # Tool with parameters — generate function with typed args
        # For simplicity, all params are strings since WinDbg dx uses string formatting
        param_names = list(params.keys())

        def tool_func(**kwargs) -> str:
            args_str = _format_js_args(params, kwargs)
            cmd = f"dx {namespace}.{js_func}({args_str})"
            try:
                return bridge.run_command(cmd)
            except Exception as e:
                return f"Error calling {ext_name}.{js_func}: {e}"

        # Build a proper docstring from the description and parameter descriptions
        doc_parts = [description]
        if params:
            doc_parts.append("\nArgs:")
            for p_name, p_spec in params.items():
                p_desc = p_spec.get("description", "")
                doc_parts.append(f"    {p_name}: {p_desc}")
        tool_func.__doc__ = "\n".join(doc_parts)

        # Set proper annotations for DSPy Tool extraction
        annotations = {}
        for p_name in param_names:
            annotations[p_name] = str
        annotations["return"] = str
        tool_func.__annotations__ = annotations
    else:
        # No-parameter tool
        def tool_func() -> str:
            cmd = f"dx {namespace}.{js_func}()"
            try:
                return bridge.run_command(cmd)
            except Exception as e:
                return f"Error calling {ext_name}.{js_func}: {e}"

        tool_func.__doc__ = description

    tool_func.__name__ = tool_name
    tool_func.__qualname__ = tool_name

    return tool_func


def make_extension_tools(bridge, extensions) -> list[Callable]:
    """Generate DSPy tool functions for loaded JS extensions.

    Args:
        bridge: CDBBridge instance for command execution.
        extensions: List of extension dicts (from discover_js_extensions,
                    filtered to only those that loaded successfully).

    Returns:
        List of callable tool functions for DSPy ReAct.
    """
    tools = []
    for ext in extensions:
        for tool_def in ext["tools"]:
            func = _make_extension_tool(
                bridge=bridge,
                ext_name=ext["name"],
                namespace=ext["namespace"],
                js_func=tool_def["js_func"],
                tool_name=tool_def["tool_name"],
                description=tool_def["description"],
                params=tool_def.get("parameters", {}),
                required=tool_def.get("required"),
            )
            tools.append(func)
    return tools
