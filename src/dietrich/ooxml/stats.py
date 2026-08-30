"""Mutable removal accounting internal to the OOXML rewrite pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from dietrich.domain.models import RemovalCounts


@dataclass
class PartStats:
    """Accumulate transformer hits and project them into the public result model."""

    counts: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, count: int = 1) -> None:
        if count:
            self.counts[key] = self.counts.get(key, 0) + count

    def to_removal_counts(self) -> RemovalCounts:
        return RemovalCounts(
            worksheet_protections=self.counts.get("sheetProtection", 0),
            workbook_protections=self.counts.get("workbookProtection", 0),
            document_protections=self.counts.get("documentProtection", 0),
            modify_verifiers=self.counts.get("modifyVerifier", 0),
            mark_as_final=self.counts.get("markAsFinal", 0),
            signatures_stripped=self.counts.get("signatures", 0),
            vba_unlocked=self.counts.get("vba", 0),
            other=self.counts.get("other", 0),
        )


__all__ = ["PartStats"]
