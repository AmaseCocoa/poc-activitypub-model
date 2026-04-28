from typing import Any


class TestObject:
    __slots__ = ("_data",)

    def __init__(self, type: str):
        self._data: dict[str, str] = {"@type": type}

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        return cls(**data)

    @property
    def type(self) -> str:
        return self._data["@type"]
