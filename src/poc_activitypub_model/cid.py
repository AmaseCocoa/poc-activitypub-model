from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from multiformats import multibase, multicodec

from poc_activitypub_model.base import ActivityPubModel
from poc_activitypub_model.utils import parse_xsd_datetime


class DataIntegrityProof(ActivityPubModel):
    @property
    def cryptosuite(self) -> str | None:
        return self._data.get("https://w3id.org/security#cryptosuite")

    @property
    def proof_value(self) -> str | None:
        return self._data.get("https://w3id.org/security#proofValue")

    @property
    def proof_purpose(self) -> str | None:
        return self._data.get("https://w3id.org/security#proofPurpose")

    @property
    def verification_method(self) -> str | None:
        return self._data.get("https://w3id.org/security#verificationMethod")

    @property
    def created(self) -> datetime | None:
        return parse_xsd_datetime(self._data.get("https://w3id.org/security#created"))


class Multikey(ActivityPubModel):
    @property
    def id(self) -> str | None:
        return self._data.get("@id")

    @property
    def controller(self) -> str | None:
        """
        Owner of this key.
        """
        return self._data.get("https://w3id.org/security#controller")

    @property
    def public_key(
        self,
    ) -> ed25519.Ed25519PublicKey | rsa.RSAPublicKey | None:
        multibase = self._data.get("https://w3id.org/security#publicKeyMultibase")
        if not multibase:
            return None

        k = self.__mb_decode(multibase)
        if isinstance(k, rsa.RSAPublicKey) or isinstance(k, ed25519.Ed25519PublicKey):
            return k

    @property
    def private_key(self) -> ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | None:
        multibase = self._data.get("https://w3id.org/security#secretKeyMultibase")
        if not multibase:
            return None

        k = self.__mb_decode(multibase)
        if isinstance(k, rsa.RSAPrivateKey) or isinstance(k, ed25519.Ed25519PrivateKey):
            return k

    @staticmethod
    def __mb_encode(
        k: ed25519.Ed25519PublicKey
        | rsa.RSAPublicKey
        | ed25519.Ed25519PrivateKey
        | rsa.RSAPrivateKey,
    ) -> str:
        match k:
            case rsa.RSAPublicKey():
                codec, data = (
                    "rsa-pub",
                    k.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
                    ),
                )
            case rsa.RSAPrivateKey():
                codec, data = (
                    "rsa-priv",
                    k.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ),
                )
            case ed25519.Ed25519PrivateKey():
                codec, data = (
                    "ed25519-priv",
                    k.private_bytes(
                        serialization.Encoding.Raw,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    ),
                )
            case _:
                raise ValueError(f"Unsupported key type: {type(k)}")

        wrapped = multicodec.wrap(codec, data)
        return multibase.encode(wrapped, "base58btc")

    @staticmethod
    def __mb_decode(
        v: str,
    ) -> (
        ed25519.Ed25519PublicKey
        | rsa.RSAPublicKey
        | ed25519.Ed25519PrivateKey
        | rsa.RSAPrivateKey
    ):
        decoded = multibase.decode(v)
        codec, data = multicodec.unwrap(decoded)

        match codec.name:
            case "ed25519-pub":
                k = ed25519.Ed25519PublicKey.from_public_bytes(data)
            case "rsa-pub":
                k = serialization.load_der_public_key(data)
            case "ed25519-priv":
                k = ed25519.Ed25519PrivateKey.from_private_bytes(data)
            case "rsa-priv":
                k = serialization.load_der_private_key(data, password=None)
            case _:
                raise ValueError(f"Unsupported Codec: {codec.name}")

        match k:
            case (
                rsa.RSAPrivateKey()
                | ed25519.Ed25519PrivateKey()
                | rsa.RSAPublicKey()
                | ed25519.Ed25519PublicKey()
            ):
                return k
            case _:
                raise ValueError(f"Unsupported Key Type for {codec.name}: {type(k)}")
