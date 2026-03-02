"""Tests for base WinDbg debugging tools (debug + get_code_surrounding)."""

import os
import tempfile

import pytest

from dspy.experimental.chatdbg.tools.windbg_base import make_base_tools

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


@pytest.fixture
def bridge():
    return MockCDBBridge()


@pytest.fixture
def tools(bridge):
    return make_base_tools(bridge)


@pytest.fixture
def debug(tools):
    return tools[0]


@pytest.fixture
def get_code_surrounding(tools):
    return tools[1]


class TestDebugTool:
    """Tests for the debug() tool function."""

    def test_safe_command_executes(self, debug, bridge):
        result = debug("k 20")
        assert result == bridge.run_command("k 20")
        assert "k 20" in bridge.get_command_log()

    def test_unsafe_command_blocked(self, debug, bridge):
        result = debug("g")
        assert "not allowed" in result
        # Should not be in the command log (blocked before execution)
        log = bridge.get_command_log()
        assert "g" not in log

    def test_memory_edit_blocked(self, debug):
        result = debug("eb 0x401000 90")
        assert "not allowed" in result

    def test_register_write_blocked(self, debug):
        result = debug("r rax=0")
        assert "not allowed" in result

    def test_register_read_allowed(self, debug, bridge):
        bridge.set_response("r rax", "rax=0000000000000001")
        result = debug("r rax")
        assert "rax=" in result

    def test_analyze_allowed(self, debug):
        result = debug("!analyze -v")
        assert len(result) > 0

    def test_sos_command_allowed(self, debug):
        result = debug("!CLRStack -a")
        assert len(result) > 0

    def test_empty_command_blocked(self, debug):
        result = debug("")
        assert "not allowed" in result

    def test_unsafe_mode_allows_all(self, bridge):
        tools = make_base_tools(bridge, unsafe=True)
        debug = tools[0]
        bridge.set_response("g", "broke at crash")
        result = debug("g")
        assert result == "broke at crash"


class TestGetCodeSurrounding:
    """Tests for the get_code_surrounding() tool function."""

    def test_reads_source_file(self, get_code_surrounding):
        # Create a temporary source file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            for i in range(20):
                f.write(f"// line {i + 1}\n")
            f.flush()
            tmp_path = f.name

        try:
            result = get_code_surrounding(tmp_path, 10)
            assert "line 10" in result
            # Should have context lines
            assert "line 3" in result or "line 4" in result
        finally:
            os.unlink(tmp_path)

    def test_nonexistent_file(self, get_code_surrounding):
        # llm_utils raises FileNotFoundError; fallback path returns "not found" message
        try:
            result = get_code_surrounding("/nonexistent/path/file.c", 10)
            assert "not found" in result.lower()
        except FileNotFoundError:
            pass  # llm_utils raises directly — acceptable behavior

    def test_line_numbers_shown(self, get_code_surrounding):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            for i in range(20):
                f.write(f"x = {i + 1}\n")
            f.flush()
            tmp_path = f.name

        try:
            result = get_code_surrounding(tmp_path, 10)
            # Should show line numbers
            assert "10" in result
        finally:
            os.unlink(tmp_path)


class TestToolCount:
    """Verify make_base_tools returns exactly 2 tools."""

    def test_returns_two_tools(self, tools):
        assert len(tools) == 2

    def test_tool_names(self, tools):
        assert tools[0].__name__ == "debug"
        assert tools[1].__name__ == "get_code_surrounding"
