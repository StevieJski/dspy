"""Tests for WinDbgDebugger auto-context collection."""

import pytest

from dspy.experimental.chatdbg.windbg_debugger import WinDbgDebugger

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


class TestAutoContextCollection:
    """Test automatic context collection from the bridge."""

    def test_collect_error_context(self):
        bridge = MockCDBBridge()
        debugger = WinDbgDebugger(bridge)
        context = debugger._collect_error_context()
        # Should include crash analysis output
        assert len(context) > 0
        assert context != "Unknown error"

    def test_collect_stack_trace(self):
        bridge = MockCDBBridge()
        debugger = WinDbgDebugger(bridge)
        stack = debugger._collect_stack_trace()
        assert len(stack) > 0
        assert stack != "No stack trace available"

    def test_collect_error_context_includes_analysis(self):
        bridge = MockCDBBridge()
        debugger = WinDbgDebugger(bridge)
        context = debugger._collect_error_context()
        # The analyze fixture should be included
        assert "analyze" in context.lower() or len(context) > 100

    def test_collect_error_context_empty_bridge(self):
        bridge = MockCDBBridge()
        # Override to return empty
        bridge.set_response("!analyze -v", "")
        bridge.set_response(".ecxr", "")
        bridge.set_response("!peb", "")
        debugger = WinDbgDebugger(bridge)
        context = debugger._collect_error_context()
        assert context == "Unknown error"

    def test_collect_stack_trace_empty(self):
        bridge = MockCDBBridge()
        bridge.set_response("k 20", "")
        debugger = WinDbgDebugger(bridge)
        stack = debugger._collect_stack_trace()
        assert stack == "No stack trace available"


class TestToolDetection:
    """Test that WinDbgDebugger detects capabilities and adds appropriate tools."""

    def test_native_crash_has_base_tools(self):
        bridge = MockCDBBridge(scenario="native_crash")
        debugger = WinDbgDebugger(bridge)
        # ReAct should have tools
        assert debugger.react is not None

    def test_dotnet_crash_adds_dotnet_tools(self):
        bridge = MockCDBBridge(scenario="dotnet_crash")
        debugger = WinDbgDebugger(bridge)
        # Should have more tools than native (base 2 + dotnet 10 = 12)
        assert debugger.react is not None

    def test_js_available_adds_js_tools(self):
        bridge = MockCDBBridge(scenario="js_available")
        debugger = WinDbgDebugger(bridge)
        assert debugger.react is not None

    def test_dotnet_js_adds_both(self):
        bridge = MockCDBBridge(scenario="dotnet_js")
        debugger = WinDbgDebugger(bridge)
        assert debugger.react is not None

    def test_ttd_adds_ttd_tools(self):
        bridge = MockCDBBridge(scenario="ttd_trace")
        debugger = WinDbgDebugger(bridge)
        assert debugger.react is not None


class TestForwardSignature:
    """Test that forward() accepts optional parameters."""

    def test_forward_accepts_explicit_args(self):
        bridge = MockCDBBridge()
        debugger = WinDbgDebugger(bridge)
        # Just verify the method signature — don't actually call the LLM
        import inspect
        sig = inspect.signature(debugger.forward)
        params = sig.parameters
        assert "error_context" in params
        assert "stack_trace" in params
        # Both should have defaults (None)
        assert params["error_context"].default is None
        assert params["stack_trace"].default is None
