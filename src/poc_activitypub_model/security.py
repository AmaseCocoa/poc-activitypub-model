from poc_activitypub_model.base import ActivityPubModel


class CryptographicKey(ActivityPubModel):
    @property
    def type(self) -> str:return self._data.get("@type", "CryptographicKey")

    @property
    def id(self) -> str | None: return self._data.get("@id")

    @property
    def owner(self) -> str | None: return self._data.get("https://w3id.org/security/v1#owner")

    @property # TODO: implement logic convert to publicKey Object
    def public_key(self) -> bytes | str | None: return self._data.get("https://w3id.org/security/v1#publicKeyPem")