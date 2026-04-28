import json
from collections import ChainMap
from datetime import datetime, timezone
from typing import Literal, Optional
from urllib.parse import urlparse

from apsig import LDSignature, ProofSigner
from apsig.draft import Signer
from apsig.rfc9421 import RFC9421Signer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key


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
    def __init__(self, key_id: str, public_key: str | None = None, private_key: str | None = None):
        self.__key_id = key_id

        if not public_key and not private_key:
            raise ValueError("Either public_key or private_key must be provided")

        if private_key:
            self.__private_key = load_der_private_key(private_key.encode("utf-8"), password=None, backend=default_backend())
        self.__public_key = public_key if public_key else self.__private_key.public_key()

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
    def _overlay(self) -> dict:
        return self.__overlay

    def _set_raw_bytes(self, value: bytes) -> None:
        if self.__bytes is None:
            self.__bytes = value
        else:
            raise RuntimeError("Raw bytes already set")

    @property
    def _raw(self) -> dict:
        return self.__raw_data

    def sign(self, headers: dict, method: str, url: str, key: ActorKey, as_dict: bool = False, specs: Optional[list[Specs]] = None) -> tuple[dict | bytes, dict]:
        if not specs:
            specs = ["draft"]

        specs = sorted(set(specs or []), key=lambda x: SPECS_ORDER.get(x, 99))

        body = self.dump()
        body_str = json.dumps(body, ensure_ascii=False)
        private_key = key.private_key
        final_headers = headers.copy()
        for spec in specs or []:
            if isinstance(private_key, RSAPrivateKey):
                if spec == "draft":
                    signer = Signer(
                        headers=final_headers,
                        private_key=private_key,
                        method=method,
                        url=url,
                        key_id=key.key_id,
                        body=body_str.encode("utf-8"),
                    )
                    final_headers = signer.sign()
                elif spec == "rfc9421" and "draft" not in specs:
                    parsed_url = urlparse(url)
                    signer = RFC9421Signer(private_key, key.key_id)
                    final_headers = signer.sign(method, parsed_url.path, parsed_url.netloc.lower(), final_headers, body)
                elif spec == "rsa2017":
                    ld_signer = LDSignature()
                    body = ld_signer.sign(
                        doc=body,
                        creator=key.key_id,
                        private_key=private_key
                    )
                    body_str = json.dumps(body, ensure_ascii=False)
                else:
                    raise ValueError(f"Unknown spec: {spec}")
            elif isinstance(private_key, Ed25519PrivateKey):
                if spec == "fep8b32":
                    now = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
                    signer = ProofSigner(private_key)
                    body = signer.sign(body, {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "verificationMethod": key.key_id,
                        "created": now,
                    })
                    body_str = json.dumps(body, ensure_ascii=False)
                else:
                    raise ValueError(f"Unknown spec: {spec}")
            else:
                raise ValueError(f"Unknown spec: {spec}")

        if as_dict:
            return body, final_headers
        return json.dumps(body, ensure_ascii=False).encode("utf-8"), final_headers

    def _dump(self) -> dict:
        return {
            k: v for k, v in self.__data.items()
            if not isinstance(v, DeletedAttribute)
        }

    def dump(self) -> dict:
        return self._dump()