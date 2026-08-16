"""도메인 불변식 위반을 표현하는 공통 예외."""


class DomainInvariantError(ValueError):
    """시스템의 핵심 도메인 규칙을 위반하려 할 때 발생한다."""
