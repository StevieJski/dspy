"""Tests for Time Travel Debugging (TTD) tools."""

import pytest

from dspy.experimental.chatdbg.tools.windbg_ttd import make_ttd_tools

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


@pytest.fixture
def bridge():
    return MockCDBBridge(scenario="ttd_trace")


@pytest.fixture
def tools(bridge):
    return make_ttd_tools(bridge)


class TestTTDToolCount:
    def test_returns_four_tools(self, tools):
        assert len(tools) == 4

    def test_tool_names(self, tools):
        names = [t.__name__ for t in tools]
        assert "ttd_step_back" in names
        assert "ttd_travel_to" in names
        assert "ttd_query_exceptions" in names
        assert "ttd_query_calls" in names


class TestTTDStepBack:
    def test_single_step(self, tools, bridge):
        ttd_step_back = tools[0]
        result = ttd_step_back(steps=1)
        assert len(result) > 0
        assert "t-" in bridge.get_command_log()

    def test_multiple_steps(self, tools, bridge):
        ttd_step_back = tools[0]
        result = ttd_step_back(steps=3)
        log = bridge.get_command_log()
        assert log.count("t-") == 3

    def test_zero_steps_becomes_one(self, tools, bridge):
        ttd_step_back = tools[0]
        ttd_step_back(steps=0)
        assert "t-" in bridge.get_command_log()

    def test_negative_steps_becomes_one(self, tools, bridge):
        ttd_step_back = tools[0]
        ttd_step_back(steps=-5)
        log = bridge.get_command_log()
        assert log.count("t-") == 1


class TestTTDTravelTo:
    def test_travel_to_position(self, tools, bridge):
        ttd_travel_to = tools[1]
        result = ttd_travel_to("35:12")
        assert "35:12" in result
        assert "!tt 35:12" in bridge.get_command_log()


class TestTTDQueryExceptions:
    def test_queries_exceptions(self, tools, bridge):
        ttd_query_exceptions = tools[2]
        result = ttd_query_exceptions()
        assert len(result) > 0
        assert any("Exception" in cmd for cmd in bridge.get_command_log())


class TestTTDQueryCalls:
    def test_passes_function_name(self, tools, bridge):
        ttd_query_calls = tools[3]
        result = ttd_query_calls("kernel32!CreateFileW")
        log = bridge.get_command_log()
        assert any("kernel32!CreateFileW" in cmd for cmd in log)
