"""Mock CDBBridge for testing WinDbg debugging tools without CDB installed.

Usage:
    from tests.experimental.chatdbg.mock_bridge import MockCDBBridge
    bridge = MockCDBBridge(scenario="dotnet_crash")
    tools = make_base_tools(bridge)
"""

import os


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "windbg")


def _load_fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return ""


# Preloaded fixture data keyed by command prefix
_FIXTURES = {
    "k 20": _load_fixture("k_output.txt"),
    "!analyze -v": _load_fixture("analyze_v_output.txt"),
    "!CLRStack -a": _load_fixture("clrstack_output.txt"),
    "!CLRStack -p": _load_fixture("clrstack_output.txt"),
    "!DumpObj": _load_fixture("dumpobj_output.txt"),
    "!DumpStackObjects": _load_fixture("dumpstackobjects_output.txt"),
    "!pe -nested": _load_fixture("pe_output.txt"),
    "!DumpHeap -stat": _load_fixture("dumpheap_stat_output.txt"),
    "!DumpHeap -type": _load_fixture("dumpheap_type_output.txt"),
    "!GCRoot": _load_fixture("gcroot_output.txt"),
    "!Threads": _load_fixture("threads_output.txt"),
    "!EEStack": _load_fixture("eestack_output.txt"),
    "!Name2EE": _load_fixture("name2ee_output.txt"),
    "!peb": _load_fixture("peb_output.txt"),
    ".ecxr": _load_fixture("ecxr_output.txt"),
    "dv /t": _load_fixture("dv_output.txt"),
    "lm": (
        "start             end                 module name\n"
        "00007ff7`12340000 00007ff7`12350000   crash_sample   (deferred)\n"
        "00007ff8`23450000 00007ff8`23550000   KERNEL32   (deferred)\n"
        "00007ff8`34560000 00007ff8`34750000   ntdll      (deferred)\n"
    ),
}


class MockCDBBridge:
    """Mock CDBBridge supporting multiple scenarios for testing.

    Scenarios:
    - native_crash: Basic native code crash (default)
    - dotnet_crash: .NET runtime with coreclr loaded
    - js_available: JavaScript provider available
    - dotnet_js: .NET + JavaScript provider
    - ttd_trace: Time Travel Debugging available
    """

    def __init__(self, scenario="native_crash"):
        self.scenario = scenario
        self._command_log = []
        self._custom_responses = {}

        # Build scenario-specific fixtures
        self._fixtures = dict(_FIXTURES)

        if scenario in ("dotnet_crash", "dotnet_js"):
            self._fixtures["lm"] = (
                "start             end                 module name\n"
                "00007ff7`12340000 00007ff7`12350000   DotnetCrash   (deferred)\n"
                "00007ff8`10000000 00007ff8`10500000   coreclr   (deferred)\n"
                "00007ff8`23450000 00007ff8`23550000   KERNEL32   (deferred)\n"
            )

        if scenario in ("js_available", "dotnet_js"):
            self._fixtures[".scriptproviders"] = (
                "Available Script Providers:\n"
                "    NatVis (NatVis Visualizer)\n"
                "    JavaScript (JsProvider)\n"
            )
            self._fixtures[".scriptlist"] = "Loaded Script List:\n    (none)\n"

        if scenario == "ttd_trace":
            self._fixtures["dx @$curprocess.TTD"] = (
                "@$curprocess.TTD\n"
                "    Lifetime         : [0:0, 50:0]\n"
                "    Threads\n"
                "    Events\n"
            )
            self._fixtures['dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception")'] = (
                _load_fixture("ttd_exceptions_output.txt")
            )
            self._fixtures["dx @$curprocess.TTD.Calls"] = _load_fixture("ttd_calls_output.txt")

    def set_response(self, command, response):
        """Set a custom response for a specific command."""
        self._custom_responses[command] = response

    def run_command(self, command: str) -> str:
        """Execute a debugger command and return mock output."""
        self._command_log.append(command)

        # Check custom responses first
        if command in self._custom_responses:
            return self._custom_responses[command]

        # Exact match
        if command in self._fixtures:
            return self._fixtures[command]

        # Prefix match for commands with arguments
        for key in self._fixtures:
            if command.startswith(key):
                return self._fixtures[key]

        # Handle .scriptload commands
        if command.startswith(".scriptload"):
            if self.scenario in ("js_available", "dotnet_js"):
                return "JavaScript script successfully loaded."
            return "Error: no JavaScript provider"

        # Handle .scriptunload commands
        if command.startswith(".scriptunload"):
            return ""

        # Handle dx @$scriptContents
        if "@$scriptContents" in command:
            return "@$scriptContents.run()\n    result: analysis complete\n"

        # Handle TTD dx when not in TTD scenario
        if "TTD" in command and self.scenario != "ttd_trace":
            return "Error: unable to resolve"

        # Handle t- (step back)
        if command == "t-":
            return "eax=00000001 ebx=00000000\ncrash_sample!main+0x10:\n00007ff7`12340010 8b01  mov eax,dword ptr [rcx]"

        # Handle !tt (travel to position)
        if command.startswith("!tt "):
            pos = command[4:].strip()
            return f"Setting position to {pos}\nTime Travel Position: {pos}"

        return ""

    def detect_dotnet(self) -> bool:
        lm_output = self.run_command("lm")
        return "clr" in lm_output.lower() or "coreclr" in lm_output.lower()

    def detect_ttd(self) -> bool:
        result = self.run_command("dx @$curprocess.TTD")
        return "Error" not in result and result.strip() != ""

    def detect_jsprovider(self) -> bool:
        output = self.run_command(".scriptproviders")
        return output is not None and "javascript" in output.lower()

    def get_stack(self, depth=20):
        return self.run_command(f"k {depth}")

    def get_crash_analysis(self, max_chars=2048):
        result = self.run_command("!analyze -v")
        return result[:max_chars] if result else ""

    def get_exception_context(self):
        result = self.run_command(".ecxr")
        if result:
            lower = result.lower()
            if "not stored" in lower or "unable to get" in lower:
                return None
            return result
        return None

    def get_command_line(self):
        peb_output = self.run_command("!peb")
        if peb_output:
            for line in peb_output.split("\n"):
                if "CommandLine:" in line:
                    return line.split("CommandLine:")[1].strip().strip("'\"")
        return None

    def get_command_log(self):
        return list(self._command_log)

    def clear_command_log(self):
        self._command_log.clear()

    @property
    def is_alive(self):
        return True
