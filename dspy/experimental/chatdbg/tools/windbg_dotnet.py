""".NET/SOS diagnostic tools for WinDbg debugging."""

from typing import Callable


def make_dotnet_tools(bridge) -> list[Callable]:
    """Create .NET/SOS diagnostic tools bound to a CDBBridge instance."""

    def managed_stack() -> str:
        """Get the managed (.NET) call stack with arguments and local variables.
        Shows CLR stack frames with method names and parameter values."""
        return bridge.run_command("!CLRStack -a")

    def inspect_object(address: str) -> str:
        """Inspect a .NET object at the given memory address.
        Shows the object's type, fields, values, method table, and size.

        Args:
            address: Memory address of the .NET object (e.g., '000001c4a8032fd0').
        """
        return bridge.run_command(f"!DumpObj {address}")

    def dump_stack_objects() -> str:
        """List all .NET objects on the current thread's stack.
        Useful for finding managed objects relevant to the current error."""
        return bridge.run_command("!DumpStackObjects")

    def print_exception() -> str:
        """Print the current managed exception with the full inner exception chain.
        Use this first when a .NET exception is the crash cause — shows exception type,
        message, HResult, and nested inner exceptions."""
        return bridge.run_command("!pe -nested")

    def dump_heap_stat() -> str:
        """Show .NET managed heap statistics grouped by type.
        Displays object count and total size. Useful for identifying memory leaks."""
        return bridge.run_command("!DumpHeap -stat")

    def dump_heap_type(typename: str) -> str:
        """Find all instances of a specific .NET type on the managed heap.
        Returns addresses, method tables, and sizes.

        Args:
            typename: Full .NET type name (e.g., 'System.String' or 'MyApp.Config').
        """
        return bridge.run_command(f"!DumpHeap -type {typename}")

    def gc_root(address: str) -> str:
        """Trace GC roots for a .NET object — shows why the object is alive.
        Displays reference chain from root to target object. Essential for memory leaks.

        Args:
            address: Memory address of the .NET object (e.g., '000001c4a8033040').
        """
        return bridge.run_command(f"!GCRoot {address}")

    def managed_threads() -> str:
        """List all managed .NET threads with state, GC mode, exception info,
        apartment type, and lock count. Find threads with unhandled exceptions."""
        return bridge.run_command("!Threads")

    def ee_stack() -> str:
        """Show managed call stacks for ALL .NET threads at once.
        Useful for deadlock analysis and getting a complete picture of thread activity."""
        return bridge.run_command("!EEStack")

    def name_to_ee(module: str, typename: str) -> str:
        """Resolve a .NET type or method name to its internal runtime addresses.
        Returns MethodTable and EEClass addresses.

        Args:
            module: Module containing the type (e.g., 'System.Private.CoreLib').
            typename: Full type or method name (e.g., 'System.String').
        """
        return bridge.run_command(f"!Name2EE {module} {typename}")

    return [
        managed_stack,
        inspect_object,
        dump_stack_objects,
        print_exception,
        dump_heap_stat,
        dump_heap_type,
        gc_root,
        managed_threads,
        ee_stack,
        name_to_ee,
    ]
