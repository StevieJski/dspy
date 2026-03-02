"""Tests for .NET/SOS diagnostic tools."""

import pytest

from dspy.experimental.chatdbg.tools.windbg_dotnet import make_dotnet_tools

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


@pytest.fixture
def bridge():
    return MockCDBBridge(scenario="dotnet_crash")


@pytest.fixture
def tools(bridge):
    return make_dotnet_tools(bridge)


class TestDotnetToolCount:
    def test_returns_ten_tools(self, tools):
        assert len(tools) == 10

    def test_tool_names(self, tools):
        names = [t.__name__ for t in tools]
        assert "managed_stack" in names
        assert "inspect_object" in names
        assert "dump_stack_objects" in names
        assert "print_exception" in names
        assert "dump_heap_stat" in names
        assert "dump_heap_type" in names
        assert "gc_root" in names
        assert "managed_threads" in names
        assert "ee_stack" in names
        assert "name_to_ee" in names


class TestManagedStack:
    def test_returns_clrstack_output(self, tools, bridge):
        managed_stack = tools[0]
        result = managed_stack()
        assert len(result) > 0
        assert "!CLRStack -a" in bridge.get_command_log()


class TestInspectObject:
    def test_passes_address(self, tools, bridge):
        inspect_object = tools[1]
        result = inspect_object("000001c4a8032fd0")
        assert len(result) > 0
        assert "!DumpObj 000001c4a8032fd0" in bridge.get_command_log()


class TestDumpStackObjects:
    def test_returns_output(self, tools, bridge):
        dump_stack_objects = tools[2]
        result = dump_stack_objects()
        assert len(result) > 0
        assert "!DumpStackObjects" in bridge.get_command_log()


class TestPrintException:
    def test_returns_pe_output(self, tools, bridge):
        print_exception = tools[3]
        result = print_exception()
        assert len(result) > 0
        assert "!pe -nested" in bridge.get_command_log()


class TestDumpHeapStat:
    def test_returns_heap_stats(self, tools, bridge):
        dump_heap_stat = tools[4]
        result = dump_heap_stat()
        assert len(result) > 0
        assert "!DumpHeap -stat" in bridge.get_command_log()


class TestDumpHeapType:
    def test_passes_typename(self, tools, bridge):
        dump_heap_type = tools[5]
        result = dump_heap_type("System.String")
        assert len(result) > 0
        assert "!DumpHeap -type System.String" in bridge.get_command_log()


class TestGCRoot:
    def test_passes_address(self, tools, bridge):
        gc_root = tools[6]
        result = gc_root("000001c4a8033040")
        assert len(result) > 0
        assert "!GCRoot 000001c4a8033040" in bridge.get_command_log()


class TestManagedThreads:
    def test_returns_threads(self, tools, bridge):
        managed_threads = tools[7]
        result = managed_threads()
        assert len(result) > 0
        assert "!Threads" in bridge.get_command_log()


class TestEEStack:
    def test_returns_all_stacks(self, tools, bridge):
        ee_stack = tools[8]
        result = ee_stack()
        assert len(result) > 0
        assert "!EEStack" in bridge.get_command_log()


class TestName2EE:
    def test_passes_module_and_type(self, tools, bridge):
        name_to_ee = tools[9]
        result = name_to_ee("System.Private.CoreLib", "System.String")
        assert len(result) > 0
        assert "!Name2EE System.Private.CoreLib System.String" in bridge.get_command_log()
