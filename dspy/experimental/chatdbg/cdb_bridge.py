"""CDB/WinDbg command execution bridge.

Supports two modes:
- pykd mode: Direct execution inside WinDbg/CDB via pykd.dbgCommand()
- subprocess mode: Launching CDB as a subprocess for standalone usage
"""

import shutil
from typing import Optional


class CDBBridge:
    """Bridge for executing CDB/WinDbg debugger commands.

    Two usage patterns:

    **pykd mode** (inside WinDbg)::

        import pykd
        bridge = CDBBridge(pykd_module=pykd)

    **subprocess mode** (standalone)::

        bridge = CDBBridge()
        bridge.launch("MyApp.exe", target_args=["arg1"], dotnet=True)
        # ... use bridge ...
        bridge.close()
    """

    def __init__(self, pykd_module=None, cdb_path: str = None):
        """Initialize CDB bridge.

        Args:
            pykd_module: The pykd module if running inside WinDbg. None for subprocess mode.
            cdb_path: Path to CDB executable for subprocess mode. Auto-detected if None.
        """
        self._pykd = pykd_module
        self._cdb_path = cdb_path
        self._session = None
        self._is_dotnet = None
        self._is_ttd = None
        self._has_js_provider = None

    def launch(
        self,
        target: str = None,
        target_args: list = None,
        dump_file: str = None,
        dotnet: bool = False,
        initial_commands: list = None,
    ):
        """Launch CDB as a subprocess and run to the first break.

        Args:
            target: Path to the executable to debug.
            dump_file: Path to a crash dump file (alternative to target).
            target_args: Arguments to pass to the target executable.
            dotnet: If True, suppress first-chance CLR exceptions before running.
            initial_commands: Extra commands to run before returning control.
                If not provided, defaults to ["g"] for live targets (run to crash).
        """
        if self._pykd is not None:
            raise RuntimeError("Cannot launch subprocess in pykd mode.")
        if self._session is not None:
            raise RuntimeError("Session already active. Call close() first.")
        if not target and not dump_file:
            raise ValueError("Either target or dump_file is required.")

        from dspy.experimental.chatdbg.cdb_session import CDBSession

        cdb_exe = self._cdb_path or self._find_cdb()

        # Build initial command sequence
        cmds = list(initial_commands or [])
        if dotnet:
            cmds.insert(0, "sxd e0434352")  # suppress first-chance CLR exceptions
        if not dump_file and not any(c.strip().split()[0].lower() in ("g", "go") for c in cmds):
            cmds.append("g")  # run to crash for live targets

        self._session = CDBSession(
            target_exe=target,
            target_args=target_args,
            cdb_exe=cdb_exe,
            initial_commands=cmds,
            dump_file=dump_file,
        )

    def close(self):
        """Close the CDB subprocess session."""
        if self._session is not None:
            self._session.close()
            self._session = None
        # Reset detection caches
        self._is_dotnet = None
        self._is_ttd = None
        self._has_js_provider = None

    @property
    def is_alive(self) -> bool:
        """True if a subprocess session is active."""
        if self._pykd is not None:
            return True
        return self._session is not None and self._session.is_alive

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
        """Run a command via CDB subprocess."""
        if self._session is None:
            raise RuntimeError("No active CDB session. Call launch() first.")
        return self._session.execute(command)

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

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
        if result:
            lower = result.lower()
            if "not stored" in lower or "unable to get" in lower:
                return None
            return result
        return None

    def get_command_line(self) -> Optional[str]:
        """Get the debugged process command line from !peb."""
        try:
            peb_output = self.run_command("!peb")
            if peb_output:
                for line in peb_output.split("\n"):
                    if "CommandLine:" in line:
                        return line.split("CommandLine:")[1].strip().strip("'\"")
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _find_cdb() -> str:
        """Find CDB on PATH or in standard Windows SDK locations."""
        import os

        for name in ("cdb", "cdbX64.exe", "cdbX86.exe"):
            path = shutil.which(name)
            if path:
                return name
        # Common Windows SDK locations
        for p in [
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        ]:
            if os.path.exists(p):
                return p
        return "cdb"  # fall back and let the OS error explain what's missing
