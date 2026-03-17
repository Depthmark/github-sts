"""
Request-scoped context for trace ID propagation.

Uses Python's ``contextvars`` so the trace ID is available across all
``await`` boundaries without explicit parameter passing.  Every module
that logs via the standard ``logging`` library will automatically
include the trace ID through the enriched ``JSONFormatter``.
"""

from contextvars import ContextVar

_trace_id_var: ContextVar[str] = ContextVar("trace_id", default="no-trace")


def get_trace_id() -> str:
    """Return the current request's trace ID (or ``'no-trace'``)."""
    return _trace_id_var.get()


def set_trace_id(value: str) -> None:
    """Set the trace ID for the current async context."""
    _trace_id_var.set(value)
