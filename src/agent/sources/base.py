from dataclasses import dataclass, field
from typing import Protocol, Iterator


@dataclass(frozen=True)
class Artifact:
    id: str
    source_type: str
    locator: str
    content_type: str
    language: str
    size: int
    content_hash: str
    content: str = field(repr=False)


class Source(Protocol):
    def prepare(self) -> None: ...
    def artifacts(self) -> Iterator[Artifact]: ...
    def cleanup(self) -> None: ...
