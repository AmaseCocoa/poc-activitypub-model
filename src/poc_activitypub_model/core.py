from collections import ChainMap
from datetime import datetime, timezone
import json
from types import MappingProxyType
from typing import Literal, Optional, cast, Final
from urllib.parse import urlparse

from apsig import LDSignature, ProofSigner
from apsig.draft import Signer
from apsig.rfc9421 import RFC9421Signer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key

from poc_activitypub_model.utils import jsonld

Specs = Literal["draft", "rsa2017", "fep8b32", "rfc9421"]
SPECS_ORDER: dict[Specs, int] = {
    "rsa2017": 1,
    "fep8b32": 3,
    "rfc9421": 2,
    "draft": 4,
}


class DeletedAttribute:
    pass


class ActorKey:
    def __init__(
        self, key_id: str, public_key: str | None = None, private_key: str | None = None
    ):
        self.__key_id = key_id

        if not public_key and not private_key:
            raise ValueError("Either public_key or private_key must be provided")

        if private_key:
            self.__private_key = load_der_private_key(
                private_key.encode("utf-8"), password=None, backend=default_backend()
            )
        self.__public_key = (
            public_key if public_key else self.__private_key.public_key()
        )

    @property
    def key_id(self):
        return self.__key_id

    @property
    def private_key(self):
        return self.__private_key

    @property
    def public_key(self):
        return self.__public_key


class ActivityPubModel:
    def __init__(self, **kwargs):
        self.__raw_data = kwargs
        self.__mapping = jsonld.get_mapping(self.__raw_data)

        self.__overlay = {}

        self.__bytes: bytes | None = None
        self.__data = None

    @classmethod
    def from_dict(cls, data: dict) -> "ActivityPubModel":
        return cls(**data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ActivityPubModel":
        instance = cls(**json.loads(data))
        instance._set_raw_bytes(data)
        return instance

    @property
    def _data(self) -> ChainMap:
        if not self.__data:
            self.__data = ChainMap(self.__overlay, self.__raw_data)
        return self.__data

    @property
    def _mapping(self) -> MappingProxyType:
        return MappingProxyType(self.__mapping)

    def _set_raw_bytes(self, value: bytes) -> None:
        if self.__bytes is None:
            self.__bytes = value
        else:
            raise RuntimeError("Raw bytes already set")

    @property
    def _raw(self) -> MappingProxyType:
        return MappingProxyType(self.__raw_data)

    def sign(
        self,
        headers: dict,
        method: str,
        url: str,
        key: ActorKey,
        as_dict: bool = False,
        specs: Optional[list[Specs]] = None,
    ) -> tuple[dict | bytes, dict]:
        _specs: list[Specs] = (
            specs if specs is not None else cast(list[Specs], ["draft"])
        )
        specs_to_loop = sorted(set(_specs), key=lambda x: SPECS_ORDER.get(x, 99))
        body = self.dump()
        final_headers = headers.copy()

        for spec in specs_to_loop:
            body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

            match (spec, key.private_key):
                case ("draft", RSAPrivateKey() as pk):
                    final_headers = Signer(
                        final_headers, pk, method, url, key.key_id, body_bytes
                    ).sign()

                case ("rfc9421", RSAPrivateKey() as pk) if "draft" not in specs_to_loop:
                    p = urlparse(url)
                    final_headers = RFC9421Signer(pk, key.key_id).sign(
                        method, p.path, p.netloc.lower(), final_headers, body
                    )

                case ("rsa2017", RSAPrivateKey() as pk):
                    body = LDSignature().sign(body, key.key_id, pk)

                case ("fep8b32", Ed25519PrivateKey() as pk):
                    now = (
                        datetime.now(timezone.utc)
                        .isoformat(timespec="seconds")
                        .replace("+00:00", "Z")
                    )
                    body = ProofSigner(pk).sign(
                        body,
                        {
                            "type": "DataIntegrityProof",
                            "cryptosuite": "eddsa-jcs-2022",
                            "verificationMethod": key.key_id,
                            "created": now,
                        },
                    )

                case _:
                    raise ValueError(
                        f"Unknown or incompatible spec/key: {spec} with {type(key.private_key)}"
                    )

        final_body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
        return (body if as_dict else final_body_bytes), final_headers

    def _dump(self) -> dict:
        return {
            k: v for k, v in self.__data.items() if not isinstance(v, DeletedAttribute)
        }

    def dump(self) -> dict:
        return self._dump()
