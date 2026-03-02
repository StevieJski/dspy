"""DSPy-based debugging module for WinDbg/CDB.

Reimplements ChatDBG's WinDbg debugging capabilities on top of DSPy's ReAct module,
gaining prompt optimization, model-agnostic orchestration, and native tool calling.
"""

from dspy.experimental.chatdbg.cdb_bridge import CDBBridge
from dspy.experimental.chatdbg.signatures import DebugCrash, DebugFollowup
from dspy.experimental.chatdbg.windbg_debugger import WinDbgDebugger

__all__ = [
    "CDBBridge",
    "DebugCrash",
    "DebugFollowup",
    "WinDbgDebugger",
]
