from datetime import datetime
from poc_activitypub_model.base import ActivityPubModel
from poc_activitypub_model.utils import parse_xsd_datetime


class DataIntegrityProof(ActivityPubModel):
    @property
    def cryptosuite(self) -> str | None: return self._data.get("https://w3id.org/security#cryptosuite")

    @property
    def proof_value(self) -> str | None: return self._data.get("https://w3id.org/security#proofValue")

    @property
    def proof_purpose(self) -> str | None: return self._data.get("https://w3id.org/security#proofPurpose")

    @property
    def verification_method(self) -> str | None: return self._data.get("https://w3id.org/security#verificationMethod")

    @property
    def created(self) -> datetime | None: return parse_xsd_datetime(self._data.get("https://w3id.org/security#created"))

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