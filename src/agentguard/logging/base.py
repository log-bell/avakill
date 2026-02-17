"""Abstract base class for audit loggers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.models import AuditEvent


class AuditLogger(ABC):
    """Abstract base class for audit loggers."""

    @abstractmethod
    async def log(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: The event to log.
        """

    @abstractmethod
    async def query(
        self,
        filters: dict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Query logged events.

        Args:
            filters: Optional filter criteria (e.g. tool_name, action, etc.).
            limit: Maximum number of events to return.
            offset: Number of events to skip for pagination.

        Returns:
            A list of matching audit events.
        """

    @abstractmethod
    async def count(self, filters: dict | None = None) -> int:
        """Count events matching the given filters.

        Args:
            filters: Optional filter criteria.

        Returns:
            The number of matching events.
        """

    @abstractmethod
    async def stats(self) -> dict:
        """Return summary statistics.

        Returns:
            A dict with keys like total, denied, allowed, by_tool, etc.
        """

    async def close(self) -> None:  # noqa: B027
        """Clean up resources. Override if needed."""
