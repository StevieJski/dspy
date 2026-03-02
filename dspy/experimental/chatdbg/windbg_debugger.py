"""WinDbg/CDB debugging module using DSPy ReAct."""

import dspy

from dspy.experimental.chatdbg.cdb_bridge import CDBBridge
from dspy.experimental.chatdbg.instructions import DOTNET_COOKBOOK, JS_COOKBOOK, WINDBG_INSTRUCTIONS
from dspy.experimental.chatdbg.tools.windbg_base import make_base_tools
from dspy.experimental.chatdbg.tools.windbg_dotnet import make_dotnet_tools
from dspy.experimental.chatdbg.tools.windbg_js import make_js_tools
from dspy.experimental.chatdbg.tools.windbg_extensions import (
    discover_js_extensions,
    load_js_extensions,
    make_extension_tools,
)
from dspy.experimental.chatdbg.tools.windbg_ttd import make_ttd_tools


class WinDbgDebugger(dspy.Module):
    """DSPy-based debugging assistant for WinDbg/CDB.

    Uses ReAct (Reasoning and Acting) to iteratively analyze crashes
    by executing debugger commands and reasoning about results.

    Example:
        ```python
        import dspy
        from dspy.experimental.chatdbg import WinDbgDebugger, CDBBridge

        dspy.configure(lm=dspy.LM("chatgpt/gpt-5.3-codex"))
        bridge = CDBBridge(pykd_module=pykd)
        debugger = WinDbgDebugger(bridge)
        result = debugger(
            error_context="Access violation reading 0x00000000",
            stack_trace="myapp!main+0x42\\nkernel32!BaseThreadInitThunk+0x14"
        )
        print(result.diagnosis)
        print(result.recommendation)
        ```
    """

    def __init__(
        self,
        bridge: CDBBridge,
        unsafe: bool = False,
        max_iters: int = 15,
        js_extension_paths: str = "",
    ):
        super().__init__()
        self.bridge = bridge

        # Build tool list based on detected capabilities
        tools = make_base_tools(bridge, unsafe=unsafe)

        if bridge.detect_dotnet():
            tools.extend(make_dotnet_tools(bridge))

        if bridge.detect_ttd():
            tools.extend(make_ttd_tools(bridge))

        if bridge.detect_jsprovider():
            tools.extend(make_js_tools(bridge, unsafe=unsafe))

        # Discover and load JS extensions
        extensions = discover_js_extensions(bridge, js_extension_paths)
        if extensions:
            load_results = load_js_extensions(bridge, extensions)
            loaded = [ext for ext in extensions if load_results.get(ext["name"])]
            if loaded:
                tools.extend(make_extension_tools(bridge, loaded))

        # Build signature with appropriate instructions
        instructions = WINDBG_INSTRUCTIONS
        if bridge.detect_dotnet():
            instructions += "\n\n" + DOTNET_COOKBOOK
        if bridge.detect_jsprovider():
            instructions += "\n\n" + JS_COOKBOOK

        # Create signature class dynamically with full instructions as docstring
        signature = dspy.Signature(
            {
                "error_context": dspy.InputField(desc="Error message and crash analysis output"),
                "stack_trace": dspy.InputField(desc="Stack trace from the crashed program"),
                "diagnosis": dspy.OutputField(desc="Root cause analysis"),
                "recommendation": dspy.OutputField(desc="Fix or next debugging steps"),
            },
            instructions,
        )

        self.react = dspy.ReAct(signature=signature, tools=tools, max_iters=max_iters)

    def forward(self, error_context: str = None, stack_trace: str = None):
        """Analyze a crash and produce diagnosis and recommendation.

        If error_context or stack_trace are not provided, they are automatically
        collected from the debugger bridge (requires an active debug session).

        Args:
            error_context: Error message, crash analysis (!analyze -v output), etc.
                If None, auto-collects via !analyze -v and .ecxr.
            stack_trace: Stack trace from the crashed program.
                If None, auto-collects via 'k 20'.

        Returns:
            dspy.Prediction with fields: diagnosis, recommendation, trajectory
        """
        if error_context is None:
            error_context = self._collect_error_context()
        if stack_trace is None:
            stack_trace = self._collect_stack_trace()

        return self.react(error_context=error_context, stack_trace=stack_trace)

    def _collect_error_context(self) -> str:
        """Auto-collect error context from the debugger."""
        parts = []

        # Command line
        cmdline = self.bridge.get_command_line()
        if cmdline:
            parts.append(f"Command line: {cmdline}")

        # Crash analysis
        analysis = self.bridge.get_crash_analysis()
        if analysis:
            parts.append(analysis)

        # Exception context record
        ecxr = self.bridge.get_exception_context()
        if ecxr:
            parts.append(f"Exception context:\n{ecxr}")

        return "\n\n".join(parts) if parts else "Unknown error"

    def _collect_stack_trace(self) -> str:
        """Auto-collect stack trace from the debugger."""
        return self.bridge.get_stack(20) or "No stack trace available"
