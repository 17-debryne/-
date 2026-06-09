from __future__ import annotations

from typing import Any, Mapping, Sequence


def fuzzy_match_incidents(
    query: str,
    incidents: Sequence[Mapping[str, Any]],
    *,
    keys: Sequence[str] = ("title", "summary", "id", "tags"),
) -> list[Mapping[str, Any]]:
    q = (query or "").strip().lower()
    if not q:
        return list(incidents)
    out: list[Mapping[str, Any]] = []
    for inc in incidents:
        hay = " ".join(str(inc.get(k) or "") for k in keys).lower()
        if q in hay:
            out.append(inc)
    return out


def filter_incidents_by_conditions(
    incidents: Sequence[Mapping[str, Any]],
    conditions: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    if not conditions:
        return list(incidents)
    out: list[Mapping[str, Any]] = []
    for inc in incidents:
        ok = True
        for k, v in conditions.items():
            if inc.get(k) != v:
                ok = False
                break
        if ok:
            out.append(inc)
    return out
