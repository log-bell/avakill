"""Analytics engine over audit log data."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from avakill.logging.sqlite_logger import SQLiteLogger


class AuditAnalytics:
    """Analytics queries over the audit log.

    Usage::

        async with SQLiteLogger("/tmp/audit.db") as logger:
            analytics = AuditAnalytics(logger)
            trend = await analytics.denial_trend(hours=24)
    """

    def __init__(self, logger: SQLiteLogger) -> None:
        self._logger = logger

    async def denial_trend(self, hours: int = 24, bucket_minutes: int = 60) -> list[dict]:
        """Return denial counts bucketed by time interval.

        Args:
            hours: How far back to look.
            bucket_minutes: Size of each time bucket in minutes.

        Returns:
            List of dicts with ``bucket`` (ISO timestamp) and ``count`` keys.
        """
        await self._logger.flush()
        db = await self._logger._ensure_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        cursor = await db.execute(
            "SELECT "
            "  strftime('%Y-%m-%dT%H:', timestamp) || "
            "    printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) "
            "      / ?) * ?) || ':00' AS bucket, "
            "  COUNT(*) AS cnt "
            "FROM events "
            "WHERE decision_allowed = 0 AND timestamp >= ? "
            "GROUP BY bucket "
            "ORDER BY bucket",
            (bucket_minutes, bucket_minutes, cutoff),
        )
        rows = await cursor.fetchall()
        return [{"bucket": row[0], "count": row[1]} for row in rows]

    async def tool_usage_summary(self) -> dict[str, dict[str, int]]:
        """Return per-tool counts of allowed vs denied decisions.

        Returns:
            Dict mapping tool_name -> {"allowed": N, "denied": N}.
        """
        await self._logger.flush()
        db = await self._logger._ensure_db()
        cursor = await db.execute(
            "SELECT tool_name, decision_allowed, COUNT(*) AS cnt "
            "FROM events GROUP BY tool_name, decision_allowed "
            "ORDER BY tool_name"
        )
        rows = await cursor.fetchall()
        summary: dict[str, dict[str, int]] = {}
        for tool_name, allowed, count in rows:
            if tool_name not in summary:
                summary[tool_name] = {"allowed": 0, "denied": 0}
            key = "allowed" if allowed else "denied"
            summary[tool_name][key] = count
        return summary

    async def agent_risk_scores(self) -> dict[str, float]:
        """Compute a simple risk score per agent based on denial rate.

        Risk score = denied / total for each agent_id.
        Higher score = more denials = higher risk.

        Returns:
            Dict mapping agent_id -> risk score (0.0 to 1.0).
        """
        await self._logger.flush()
        db = await self._logger._ensure_db()
        cursor = await db.execute(
            "SELECT agent_id, "
            "  SUM(CASE WHEN decision_allowed = 0 THEN 1 ELSE 0 END) AS denied, "
            "  COUNT(*) AS total "
            "FROM events "
            "WHERE agent_id IS NOT NULL "
            "GROUP BY agent_id"
        )
        rows = await cursor.fetchall()
        scores: dict[str, float] = {}
        for agent_id, denied, total in rows:
            scores[agent_id] = round(denied / total, 4) if total else 0.0
        return scores

    async def policy_effectiveness(self) -> dict[str, dict]:
        """Analyze how often each policy rule triggers.

        Returns:
            Dict mapping policy_name -> {"matches": N, "denials": N, "allows": N}.
        """
        await self._logger.flush()
        db = await self._logger._ensure_db()
        cursor = await db.execute(
            "SELECT decision_policy, decision_allowed, COUNT(*) AS cnt "
            "FROM events "
            "WHERE decision_policy IS NOT NULL "
            "GROUP BY decision_policy, decision_allowed "
            "ORDER BY decision_policy"
        )
        rows = await cursor.fetchall()
        effectiveness: dict[str, dict] = {}
        for policy_name, allowed, count in rows:
            if policy_name not in effectiveness:
                effectiveness[policy_name] = {
                    "matches": 0,
                    "denials": 0,
                    "allows": 0,
                }
            effectiveness[policy_name]["matches"] += count
            if allowed:
                effectiveness[policy_name]["allows"] += count
            else:
                effectiveness[policy_name]["denials"] += count
        return effectiveness
