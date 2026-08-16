"""Evidence Store와 분리된 Knowledge Plane 검색·발행 계약."""

from __future__ import annotations

from typing import Protocol, Sequence

from hacklipse.domain import KnowledgeCase, KnowledgeQuery


class KnowledgeBase(Protocol):
    """대상 Evidence와 의도적으로 분리한 Knowledge Plane 경계."""

    def search(self, query: KnowledgeQuery) -> Sequence[KnowledgeCase]: ...

    def publish(self, case: KnowledgeCase) -> None: ...
