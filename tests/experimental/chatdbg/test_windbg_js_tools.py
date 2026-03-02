"""Tests for JavaScript scripting tools."""

import pytest

from dspy.experimental.chatdbg.tools.windbg_js import make_js_tools, _check_js_safety

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


@pytest.fixture
def bridge():
    return MockCDBBridge(scenario="js_available")


@pytest.fixture
def tools(bridge):
    return make_js_tools(bridge)


@pytest.fixture
def run_js(tools):
    return tools[0]


class TestJSToolCount:
    def test_returns_one_tool(self, tools):
        assert len(tools) == 1

    def test_tool_name(self, tools):
        assert tools[0].__name__ == "run_js"


class TestJSSafetyChecker:
    """Tests for _check_js_safety() standalone."""

    def test_safe_code(self):
        assert _check_js_safety("var x = host.currentProcess;") is None

    @pytest.mark.parametrize("code,desc_fragment", [
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand("eb 0x1000 90")', "memory write"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand("g")', "execution resume"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand("r rax=0")', "register write"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand(".kill")', "kill target"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand(".detach")', "detach target"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand(".restart")', "restart target"),
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand("bp 0x401000")', "set breakpoint"),
    ])
    def test_dangerous_patterns(self, code, desc_fragment):
        result = _check_js_safety(code)
        assert result is not None
        assert desc_fragment in result

    def test_safe_execute_command(self):
        # ExecuteCommand with safe commands should pass
        code = 'host.namespace.Debugger.Utility.Control.ExecuteCommand("k 20")'
        assert _check_js_safety(code) is None

    def test_case_insensitive(self):
        code = 'host.namespace.Debugger.Utility.Control.ExecuteCommand("EB 0x1000 90")'
        assert _check_js_safety(code) is not None


class TestRunJS:
    """Tests for the run_js() tool function."""

    def test_executes_safe_code(self, run_js, bridge):
        result = run_js("var x = 1; return x;")
        # Should have loaded a script, executed it, and unloaded
        log = bridge.get_command_log()
        assert any(".scriptload" in cmd for cmd in log)
        assert any("@$scriptContents.run()" in cmd for cmd in log)
        assert any(".scriptunload" in cmd for cmd in log)

    def test_blocks_dangerous_code(self, run_js, bridge):
        result = run_js('host.namespace.Debugger.Utility.Control.ExecuteCommand("g")')
        assert "blocked" in result.lower()
        # Should NOT have loaded a script
        log = bridge.get_command_log()
        assert not any(".scriptload" in cmd for cmd in log)

    def test_unsafe_mode_allows_dangerous(self, bridge):
        tools = make_js_tools(bridge, unsafe=True)
        run_js = tools[0]
        result = run_js('host.namespace.Debugger.Utility.Control.ExecuteCommand("g")')
        # Should proceed (not blocked)
        assert "blocked" not in result.lower()

    def test_script_load_error(self, run_js, bridge):
        bridge.set_response(".scriptload", "")
        # Override to simulate error
        original = bridge.run_command

        def mock_run(cmd):
            if ".scriptload" in cmd:
                return "Error: unable to load script"
            return original(cmd)

        bridge.run_command = mock_run
        result = run_js("var x = 1;")
        assert "failed" in result.lower()

    def test_cleans_up_temp_file(self, run_js):
        import os
        import glob
        import tempfile

        # Get temp dir listing before
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "chatdbg_js_*.js")))
        run_js("var x = 1;")
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "chatdbg_js_*.js")))
        # No new temp files should remain
        assert after == before


class TestRunJSTemplateWrapping:
    """Verify the JS code is properly wrapped in a run() function."""

    def test_multiline_code_indented(self, run_js, bridge):
        code = "var x = 1;\nvar y = 2;\nreturn x + y;"
        # The tool should wrap this — we verify by checking that script load happened
        result = run_js(code)
        log = bridge.get_command_log()
        assert any(".scriptload" in cmd for cmd in log)
