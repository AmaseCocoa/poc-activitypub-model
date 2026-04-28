from poc_activitypub_model.utils import JSONLDTools

jld = JSONLDTools()

incoming_json = {
    "@context": {
        "as": "https://www.w3.org/ns/activitystreams#",
        "schema": "http://schema.org/",
        "t": "@type",
        "s": "as:summary",
        "c": "as:content",
        "n": "schema:name",
    },
    "t": "Note",
    "s": "A note",
    "c": "My dog has fleas.",
    "n": "John Doe",
}

iri_to_key = jld.get_mapping(incoming_json)

print(iri_to_key)
