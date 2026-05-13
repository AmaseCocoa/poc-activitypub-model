from poc_activitypub_model.base import ActivityPubModel


class DataIntegrityProof(ActivityPubModel):
    @property
    def cryptosuite(self) -> str | None: return self._data.get("https://w3id.org/security#cryptosuite")

    @property
    def proof_value(self) -> str | None: return self._data.get("https://w3id.org/security#proofValue")

    @property
    def proof_purpose(self) -> str | None: return self._data.get("https://w3id.org/security#proofValue")

    @property
    def verification_method(self) -> str | None: return self._data.get("https://w3id.org/security#proofValue")

    @property
    def created(self) -> str | None: return self._data.get("https://w3id.org/security#proofValue")

class Multikey(ActivityPubModel):
    @property
    def id(self) -> str | None: return self._data.get("@id")

    @property
    def controller(self) -> str | None:
        """
        Owner of this key.
        """
        return self._data.get("https://w3id.org/security#controller")

    @property
    def public_key(self) -> str | None: return self._data.get("https://w3id.org/security#publicKeyMultibase")

    @property
    def private_key(self) -> str | None: return self._data.get("https://w3id.org/security#secretKeyMultibase")