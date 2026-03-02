"""DSPy signatures for WinDbg debugging tasks."""

import dspy

from dspy.experimental.chatdbg.instructions import WINDBG_INSTRUCTIONS


class DebugCrash(dspy.Signature):
    """You are a debugging assistant for WinDbg. You will be given a stack
    trace or exception context for a crash and answer questions related
    to the root cause of the error.

    Call any provided functions as many times as you would like.

    The root cause of any error is likely due to a problem in the source
    code from the user.

    When analyzing crashes, pay attention to common Windows exception
    codes:
    * 0xC0000005 -- Access violation (null pointer dereference, bad
      pointer, use-after-free)
    * 0xC00000FD -- Stack overflow (unbounded recursion, large stack
      allocations)
    * 0xC0000374 -- Heap corruption (buffer overrun, double free,
      use-after-free on heap memory)

    For .NET applications, distinguish CLR runtime frames from user
    code. Focus on user frames for root cause analysis. Common managed
    exceptions include NullReferenceException, StackOverflowException,
    AccessViolationException, and ObjectDisposedException. Use SOS
    commands to inspect managed objects and their fields. Start with
    print_exception to see the full exception chain including inner
    exceptions. Use managed_threads for thread overview and
    ee_stack for all managed stacks (helpful for deadlocks). For
    heap analysis, use dump_heap_stat to find suspicious type counts,
    dump_heap_type to list instances, and gc_root to trace why an
    object is still alive.

    If Time Travel Debugging (TTD) is available, use TTD tools to
    travel backward in execution and verify hypotheses about when and
    where variable values changed. This is especially useful for
    use-after-free and heap corruption issues.

    If JavaScript extension tools are available, use them for advanced
    analysis such as stack corruption detection, call graph collection,
    memory telescoping, and code coverage from TTD traces.

    If the run_js tool is available, use it for multi-step analysis
    that cannot be done with individual debugger commands.

    Explain why each variable contributing to the error has been set
    to the value that it has.

    Continue with your explanations until you reach the root cause of
    the error. Your answer may be as long as necessary."""

    error_context: str = dspy.InputField(desc="Error message and crash analysis output from !analyze -v")
    stack_trace: str = dspy.InputField(desc="Stack trace from the crashed program")
    diagnosis: str = dspy.OutputField(
        desc="Root cause analysis explaining why each variable contributing to the error has its value"
    )
    recommendation: str = dspy.OutputField(
        desc="A fix if root cause is identified, or 1-3 numbered debugging suggestions"
    )


class DebugFollowup(dspy.Signature):
    """Continue debugging based on previous analysis and new information."""

    previous_diagnosis: str = dspy.InputField(desc="Previous diagnosis from the initial analysis")
    command_history: str = dspy.InputField(desc="History of debugger commands run and their output")
    question: str = dspy.InputField(desc="Follow-up question from the user")
    diagnosis: str = dspy.OutputField(desc="Updated root cause analysis")
    recommendation: str = dspy.OutputField(desc="Updated fix or debugging suggestions")
