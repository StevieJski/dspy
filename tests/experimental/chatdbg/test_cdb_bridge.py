"""Tests for CDBBridge detection and context helper methods."""

import pytest

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


class TestDetection:
    """Test CDBBridge detection methods with different scenarios."""

    def test_detect_dotnet_with_coreclr(self):
        bridge = MockCDBBridge(scenario="dotnet_crash")
        assert bridge.detect_dotnet() is True

    def test_detect_dotnet_without_clr(self):
        bridge = MockCDBBridge(scenario="native_crash")
        assert bridge.detect_dotnet() is False

    def test_detect_ttd_available(self):
        bridge = MockCDBBridge(scenario="ttd_trace")
        assert bridge.detect_ttd() is True

    def test_detect_ttd_not_available(self):
        bridge = MockCDBBridge(scenario="native_crash")
        assert bridge.detect_ttd() is False

    def test_detect_jsprovider_available(self):
        bridge = MockCDBBridge(scenario="js_available")
        assert bridge.detect_jsprovider() is True

    def test_detect_jsprovider_not_available(self):
        bridge = MockCDBBridge(scenario="native_crash")
        assert bridge.detect_jsprovider() is False

    def test_dotnet_js_both_detected(self):
        bridge = MockCDBBridge(scenario="dotnet_js")
        assert bridge.detect_dotnet() is True
        assert bridge.detect_jsprovider() is True
        assert bridge.detect_ttd() is False


class TestContextHelpers:
    """Test CDBBridge context collection helpers."""

    def test_get_stack(self):
        bridge = MockCDBBridge()
        stack = bridge.get_stack(20)
        assert len(stack) > 0
        assert "k 20" in bridge.get_command_log()

    def test_get_crash_analysis(self):
        bridge = MockCDBBridge()
        analysis = bridge.get_crash_analysis()
        assert len(analysis) > 0

    def test_get_crash_analysis_truncation(self):
        bridge = MockCDBBridge()
        short = bridge.get_crash_analysis(max_chars=50)
        assert len(short) <= 50

    def test_get_command_line(self):
        bridge = MockCDBBridge()
        cmdline = bridge.get_command_line()
        # Depends on peb fixture having a CommandLine
        if cmdline is not None:
            assert isinstance(cmdline, str)


class TestCommandLogging:
    """Test that commands are properly logged."""

    def test_commands_logged(self):
        bridge = MockCDBBridge()
        bridge.run_command("k 20")
        bridge.run_command("!analyze -v")
        log = bridge.get_command_log()
        assert log == ["k 20", "!analyze -v"]

    def test_clear_log(self):
        bridge = MockCDBBridge()
        bridge.run_command("k 20")
        bridge.clear_command_log()
        assert bridge.get_command_log() == []

    def test_custom_response(self):
        bridge = MockCDBBridge()
        bridge.set_response("custom_cmd", "custom output")
        assert bridge.run_command("custom_cmd") == "custom output"


class TestScenarios:
    """Test that scenarios properly configure fixtures."""

    def test_native_crash_has_basic_fixtures(self):
        bridge = MockCDBBridge(scenario="native_crash")
        assert len(bridge.run_command("k 20")) > 0
        assert len(bridge.run_command("!analyze -v")) > 0
        assert len(bridge.run_command("lm")) > 0

    def test_dotnet_crash_has_coreclr_in_lm(self):
        bridge = MockCDBBridge(scenario="dotnet_crash")
        lm = bridge.run_command("lm")
        assert "coreclr" in lm.lower()

    def test_js_available_has_scriptproviders(self):
        bridge = MockCDBBridge(scenario="js_available")
        sp = bridge.run_command(".scriptproviders")
        assert "javascript" in sp.lower()

    def test_ttd_has_ttd_object(self):
        bridge = MockCDBBridge(scenario="ttd_trace")
        ttd = bridge.run_command("dx @$curprocess.TTD")
        assert "Lifetime" in ttd

    def test_is_alive_always_true(self):
        bridge = MockCDBBridge()
        assert bridge.is_alive is True
