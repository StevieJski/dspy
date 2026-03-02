"""CDB/WinDbg command execution bridge.

Supports two modes:
- pykd mode: Direct execution inside WinDbg/CDB via pykd.dbgCommand()
- subprocess mode: Launching CDB as a subprocess for standalone usage
"""

import re
from typing import Optional


class CDBBridge:
    """Bridge for executing CDB/WinDbg debugger commands."""

    def __init__(self, pykd_module=None, cdb_path: str = "cdb.exe", target: str = None):
        """Initialize CDB bridge.

        Args:
            pykd_module: The pykd module if running inside WinDbg. None for subprocess mode.
            cdb_path: Path to CDB executable for subprocess mode.
            target: Target executable or dump file for subprocess mode.
        """
        self._pykd = pykd_module
        self._cdb_path = cdb_path
        self._target = target
        self._process = None
        self._is_dotnet = None
        self._is_ttd = None
        self._has_js_provider = None

    def run_command(self, command: str) -> str:
        """Execute a debugger command and return the output."""
        if self._pykd is not None:
            return self._run_pykd(command)
        else:
            return self._run_subprocess(command)

    def _run_pykd(self, command: str) -> str:
        try:
            result = self._pykd.dbgCommand(command)
            return result if result else ""
        except Exception as e:
            return str(e)

    def _run_subprocess(self, command: str) -> str:
        """Run a command via CDB subprocess.

        Note: Full subprocess mode requires an active CDB session.
        This is a placeholder for future implementation.
        """
        raise NotImplementedError(
            "Subprocess mode is not yet implemented. " "Use pykd mode by passing a pykd module instance."
        )

    def detect_dotnet(self) -> bool:
        """Detect if the target is a .NET application."""
        if self._is_dotnet is None:
            try:
                lm_output = self.run_command("lm")
                self._is_dotnet = "clr" in lm_output.lower() or "coreclr" in lm_output.lower()
            except Exception:
                self._is_dotnet = False
        return self._is_dotnet

    def detect_ttd(self) -> bool:
        """Detect if Time Travel Debugging is available."""
        if self._is_ttd is None:
            try:
                result = self.run_command("dx @$curprocess.TTD")
                self._is_ttd = "Error" not in result and result.strip() != ""
            except Exception:
                self._is_ttd = False
        return self._is_ttd

    def detect_jsprovider(self) -> bool:
        """Detect if JavaScript Provider is available."""
        if self._has_js_provider is None:
            try:
                output = self.run_command(".scriptproviders")
                self._has_js_provider = output is not None and "javascript" in output.lower()
            except Exception:
                self._has_js_provider = False
        return self._has_js_provider

    def get_stack(self, depth: int = 20) -> str:
        """Get the current call stack."""
        return self.run_command(f"k {depth}")

    def get_crash_analysis(self, max_chars: int = 2048) -> str:
        """Get crash analysis output."""
        result = self.run_command("!analyze -v")
        return result[:max_chars] if result else ""

    def get_exception_context(self) -> Optional[str]:
        """Get exception context record."""
        result = self.run_command(".ecxr")
        if result and "not stored" not in result.lower():
            return result
        return None
