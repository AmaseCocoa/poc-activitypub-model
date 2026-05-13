from poc_activitypub_model.base import ActivityPubModel


class PropertyValue(ActivityPubModel):
    @property
    def name(self) -> str | None:
        return self._data.get("http://schema.org#name")

    @property
    def value(self) -> str | None:
        return self._data.get("http://schema.org#value")