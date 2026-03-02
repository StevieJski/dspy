"""Instruction text constants for WinDbg debugging, ported from ChatDBG."""

WINDBG_INSTRUCTIONS = """\
You are a debugging assistant for WinDbg. You will be given a stack
trace or exception context for a crash and answer questions related
to the root cause of the error.

Call any provided functions as many times as you would like.

The root cause of any error is likely due to a problem in the source
code from the user.

When analyzing crashes, pay attention to common Windows exception
codes:
* 0xC0000005 — Access violation (null pointer dereference, bad
  pointer, use-after-free)
* 0xC00000FD — Stack overflow (unbounded recursion, large stack
  allocations)
* 0xC0000374 — Heap corruption (buffer overrun, double free,
  use-after-free on heap memory)

For .NET applications, distinguish CLR runtime frames from user
code. Focus on user frames for root cause analysis. Common managed
exceptions include NullReferenceException, StackOverflowException,
AccessViolationException, and ObjectDisposedException. Use SOS
commands to inspect managed objects and their fields. Start with
`print_exception` to see the full exception chain including inner
exceptions. Use `managed_threads` for thread overview and
`ee_stack` for all managed stacks (helpful for deadlocks). For
heap analysis, use `dump_heap_stat` to find suspicious type counts,
`dump_heap_type` to list instances, and `gc_root` to trace why an
object is still alive.

If Time Travel Debugging (TTD) is available, use TTD tools to
travel backward in execution and verify hypotheses about when and
where variable values changed. This is especially useful for
use-after-free and heap corruption issues.

If JavaScript extension tools are available (prefixed with js_),
use them for advanced analysis such as stack corruption detection,
call graph collection, memory telescoping, and code coverage from
TTD traces. These tools invoke community WinDbg JavaScript
extensions and provide higher-level analysis than raw debugger
commands.

If the `run_js` tool is available, use it for multi-step analysis
that cannot be done with individual debugger commands — for example,
walking data structures, correlating heap metadata, iterating over
threads or modules, or building summaries from multiple queries.
Write the function body only (it will be wrapped in `function run()
{ ... }` automatically). Use `return` to send results back.
Available APIs include: `host.currentProcess`, `host.currentThread`,
`host.currentSession`, `host.memory`, `host.parseInt64()`,
`host.namespace.Debugger.Utility.Control.ExecuteCommand()` to run
CDB commands and capture output. Write read-only analysis code
only — do not modify memory, registers, or execution state.

Explain why each variable contributing to the error has been set
to the value that it has.

Continue with your explanations until you reach the root cause of
the error. Your answer may be as long as necessary.

End your answer with a section titled "##### Recommendation\\n" that
contains one of:
* a fix if you have identified the root cause
* a numbered list of 1-3 suggestions for how to continue debugging if
  you have not"""

DOTNET_COOKBOOK = """\
## .NET Debugging Reference (SOS)

### Recommended Investigation Workflow

Follow this order for efficient .NET crash diagnosis:

1. `print_exception` — get exception type, message, and inner exception chain
2. `managed_stack` — CLR frames with arguments/locals on the faulting thread
3. `managed_threads` — overview of all threads; find threads with exceptions
4. `dump_stack_objects` — find managed objects on the current stack
5. `inspect_object <addr>` — drill into specific objects found above
6. For memory leaks: `dump_heap_stat` → `dump_heap_type <type>` → `gc_root <addr>`
7. For deadlocks/hangs: `ee_stack` to see all managed stacks at once
8. `name_to_ee` — resolve type names to MethodTable addresses

### Additional SOS Commands (via `debug` tool)

These are not wrapped as dedicated tools but are available via the `debug` tool:

- `!DumpArray <addr>` — dump array contents
- `!DumpVC <MT> <addr>` — dump value type (struct) at address
- `!DumpDomain` — list all AppDomains and loaded assemblies
- `!DumpModule <addr>` — module details including metadata token ranges
- `!FinalizeQueue` — objects waiting for finalization (leak indicator)
- `!SyncBlk` — monitor lock info for deadlock diagnosis
- `!ThreadPool` — thread pool stats (queue length, workers, timers)
- `!DumpAsync` — async state machine details (.NET Core 3+)

### Interpreting SOS Output

**MethodTable (MT) addresses:** First column in `!DumpHeap` output. Use with
`!DumpObj -mt <MT>` to inspect objects of that type.

**`!pe` output:** Read HResult for Win32 error mapping. Follow the
InnerException chain — the root cause is usually the innermost exception.

**`!Threads` flags:** Lock count > 0 indicates held locks. The exception
column shows unhandled exceptions per thread.

**`!GCRoot` output:**
- "Pinned handle" = P/Invoke or fixed buffer
- "Strong handle" = static reference
- "Local variable" on a thread stack = still in scope

### Common .NET Crash Patterns

**NullReferenceException:** Check which object reference is null in
`managed_stack` locals. Use `inspect_object` on surrounding objects to find
which field was expected to be initialized.

**ObjectDisposedException:** Look for disposed flags (e.g., `_disposed = True`)
in `inspect_object`. Trace disposal with `gc_root` to find who holds a
reference to the disposed object.

**StackOverflowException:** Look for recursive calls in `ee_stack`. The
repeating frame pattern reveals the unbounded recursion.

**OutOfMemoryException:** Use `dump_heap_stat` to find type accumulation.
Use `gc_root` on a sample instance to find why objects are retained. Check
`!FinalizeQueue` for finalizer thread blockage.

**Deadlocks:** Use `managed_threads` to find threads with lock count > 0.
Use `!SyncBlk` to see which threads own which monitors. Cross-reference
with `ee_stack` to see where each thread is waiting.

### Note on Extensions

PSSCOR2/PSSCOR4 and SOSEX are .NET Framework-only and not available for
.NET Core/6/8+. The built-in SOS extension covers all modern .NET scenarios.
MEX (`!dae`, `!us`) provides useful additions but requires separate
installation — if available, these commands can be run via the `debug` tool."""

JS_COOKBOOK = """\
## WinDbg JavaScript Scripting Reference (JsProvider)

### Core Host Object Model

- `host.currentProcess` — current debuggee process; `.Threads`, `.Modules`
- `host.currentThread` — current thread; `.Stack.Frames` for stack frames
- `host.currentSession` — debugger session; `.Attributes.Target`
- `host.memory` — `readMemoryValues(addr, count, size)` returns typed array
- `host.parseInt64("0xABCD")` — parse string to Int64 (**must be a string, not a number**)
- `host.Int64(lo, hi)` — construct 64-bit integer; supports `.add()`, `.subtract()`, `.bitwiseAnd()`
- `host.diagnostics.debugLog(msg)` — print debug output

### Executing CDB Commands

`host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd)` returns an
**iterable of lines**, not a string. Collect output like this:

```js
var lines = [];
for (var line of host.namespace.Debugger.Utility.Control.ExecuteCommand("k")) {
    lines.push(line);
}
return lines.join("\\n");
```

### Recipes

**Thread + stack enumeration:**
```js
var results = [];
for (var thread of host.currentProcess.Threads) {
    try {
        var frames = [];
        for (var frame of thread.Stack.Frames) {
            frames.push(frame.toString());
        }
        results.push("Thread " + thread.Id + ":\\n" + frames.join("\\n"));
    } catch(e) { /* thread may not be accessible */ }
}
return results.join("\\n\\n");
```

**Module listing:**
```js
var mods = [];
for (var mod of host.currentProcess.Modules) {
    mods.push(mod.Name + " @ " + mod.BaseAddress.toString(16));
}
return mods.join("\\n");
```

**Memory reading (bytes to string):**
```js
var addr = host.parseInt64("0x7FFE0000");
var bytes = host.memory.readMemoryValues(addr, 64, 1);
var chars = [];
for (var b of bytes) {
    if (b === 0) break;
    chars.push(String.fromCharCode(b));
}
return chars.join("");
```

**CDB command output capture and parsing:**
```js
var heapLines = [];
for (var line of host.namespace.Debugger.Utility.Control.ExecuteCommand("!heap -s")) {
    if (line.indexOf("Heap") !== -1) heapLines.push(line.trim());
}
return heapLines.join("\\n");
```

**Pointer chain walking (telescope):**
```js
var addr = host.parseInt64("0x...");
var chain = [];
for (var i = 0; i < 8; i++) {
    try {
        var val = host.memory.readMemoryValues(addr, 1, 8)[0];
        chain.push(addr.toString(16) + " -> " + val.toString(16));
        addr = val;
    } catch(e) { chain.push(addr.toString(16) + " -> ???"); break; }
}
return chain.join("\\n");
```

### Common Pitfalls

1. **ExecuteCommand returns iterable, not string.**
   Wrong: `var s = ExecuteCommand("k"); s.indexOf(...)`
   Right: collect lines with `for...of` into an array, then `.join("\\n")`

2. **Use `for...of`, not `for...in` for host objects.**
   Wrong: `for (var t in host.currentProcess.Threads)`
   Right: `for (var t of host.currentProcess.Threads)`

3. **`host.parseInt64()` takes a string, not a number.**
   Wrong: `host.parseInt64(0x1000)`
   Right: `host.parseInt64("0x1000")`

4. **Int64 arithmetic uses methods, not operators.**
   Wrong: `addr + 8`
   Right: `addr.add(host.parseInt64("8"))`

5. **Host objects may throw on inaccessible state.**
   Always wrap per-thread and per-frame iteration in try/catch.

### Error Handling Pattern

```js
var output = [];
for (var thread of host.currentProcess.Threads) {
    try {
        // per-thread work
    } catch(e) {
        output.push("Thread " + thread.Id + ": error - " + e.message);
    }
}
return output.join("\\n");
```"""
