from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from poc_activitypub_model.base import ActivityPubModel


class CryptographicKey(ActivityPubModel):
    @property
    def type(self) -> str:return self._data.get("@type", "CryptographicKey")

    @property
    def id(self) -> str | None: return self._data.get("@id")

    @property
    def owner(self) -> str | None: return self._data.get("https://w3id.org/security/v1#owner")

    @property
    def public_key(self) -> RSAPublicKey | Ed25519PublicKey | None:
        public_key = self._kv.get("https://w3id.org/security/v1#publicKeyPem")
        if public_key:
            return public_key

        data: bytes | str | None = self._data.get("https://w3id.org/security/v1#publicKeyPem")

        if not data:
            return None

        key = load_pem_public_key(data if isinstance(data, bytes) else data.encode("utf-8"))
        match key:
            case RSAPublicKey() | Ed25519PublicKey():
                self._kv["https://w3id.org/security/v1#publicKeyPem"] = key
                return key
            case _:
                return None