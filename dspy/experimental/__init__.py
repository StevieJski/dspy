from dspy.adapters.types.citation import Citations
from dspy.adapters.types.document import Document

__all__ = [
    "Citations",
    "Document",
]


# Lazy import for chatdbg module (has optional dependencies)
def __getattr__(name):
    if name == "chatdbg":
        from dspy.experimental import chatdbg as _chatdbg

        return _chatdbg
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
