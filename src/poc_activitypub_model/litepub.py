from poc_activitypub_model.base import ActivityPubModel


class EmojiReact(ActivityPubModel):
    @property
    def content(self) -> str | None:
        return self._data.get("https://www.w3.org/ns/activitystreams#content")