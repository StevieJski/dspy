"""Time Travel Debugging (TTD) tools for WinDbg."""

from typing import Callable


def make_ttd_tools(bridge) -> list[Callable]:
    """Create TTD tools bound to a CDBBridge instance."""

    def ttd_step_back(steps: int = 1) -> str:
        """Step backward in the TTD trace by the specified number of steps.
        Use to rewind execution and verify hypotheses about when values changed.

        Args:
            steps: Number of steps to go backward. Defaults to 1.
        """
        steps = max(1, int(steps))
        output = ""
        for _ in range(steps):
            output = bridge.run_command("t-")
        return output

    def ttd_travel_to(position: str) -> str:
        """Travel to a specific position in the TTD trace timeline.

        Args:
            position: Timeline position in 'N:N' format (e.g., '35:12').
        """
        return bridge.run_command(f"!tt {position}")

    def ttd_query_exceptions() -> str:
        """Query all exceptions that occurred during the recorded TTD trace.
        Returns exception types, codes, and timeline positions."""
        return bridge.run_command('dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception")')

    def ttd_query_calls(function_name: str) -> str:
        """Query all calls to a specific function recorded in the TTD trace.
        Returns arguments, return values, and timeline positions.

        Args:
            function_name: Function name to query (e.g., 'kernel32!CreateFileW').
        """
        return bridge.run_command(f'dx @$curprocess.TTD.Calls("{function_name}")')

    return [ttd_step_back, ttd_travel_to, ttd_query_exceptions, ttd_query_calls]
