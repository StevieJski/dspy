"""WinDbg/CDB debugging module using DSPy ReAct."""

import dspy

from dspy.experimental.chatdbg.cdb_bridge import CDBBridge
from dspy.experimental.chatdbg.instructions import DOTNET_COOKBOOK, JS_COOKBOOK, WINDBG_INSTRUCTIONS
from dspy.experimental.chatdbg.tools.windbg_base import make_base_tools
from dspy.experimental.chatdbg.tools.windbg_dotnet import make_dotnet_tools
from dspy.experimental.chatdbg.tools.windbg_js import make_js_tools
from dspy.experimental.chatdbg.tools.windbg_ttd import make_ttd_tools


class WinDbgDebugger(dspy.Module):
    """DSPy-based debugging assistant for WinDbg/CDB.

    Uses ReAct (Reasoning and Acting) to iteratively analyze crashes
    by executing debugger commands and reasoning about results.

    Example:
        ```python
        import dspy
        from dspy.experimental.chatdbg import WinDbgDebugger, CDBBridge

        dspy.configure(lm=dspy.LM("openai/gpt-5.3-codex"))
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

    def forward(self, error_context: str, stack_trace: str):
        """Analyze a crash and produce diagnosis and recommendation.

        Args:
            error_context: Error message, crash analysis (!analyze -v output), etc.
            stack_trace: Stack trace from the crashed program.

        Returns:
            dspy.Prediction with fields: diagnosis, recommendation, trajectory
        """
        return self.react(error_context=error_context, stack_trace=stack_trace)
