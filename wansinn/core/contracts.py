from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class WanProfile:
    id: str
    label: str
    enabled: bool = True


@dataclass(frozen=True)
class AddonInfo:
    id: str
    name: str
    vendor: str
    version: str
    description: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class HealthCheck:
    id: str
    label: str
    status: str
    message: str
    details: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if self.status not in {"ok", "warning", "error", "unknown"}:
            raise ValueError(f"Ungültiger Health-Status: {self.status}")


class RouterAddon(ABC):
    info: AddonInfo

    @abstractmethod
    def profiles(self) -> list[WanProfile]:
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def set_device_profile(self, ip: str, profile: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_device_profile(self, ip: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def diagnostics(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> list[HealthCheck]:
        raise NotImplementedError
