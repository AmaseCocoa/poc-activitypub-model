from pyld import jsonld as _jsonld


# noinspection PyMethodMayBeStatic
class JSONLDTools:
    def __init__(self):
        secure_loader = _jsonld.requests_document_loader(secure=True, timeout=5)
        _jsonld.set_document_loader(secure_loader)

    def get_mapping(self, doc):
        reverse_map = {}
        context = doc.get("@context")

        if not context:
            return reverse_map

        for original_key in doc.keys():
            if original_key == "@context":
                continue

            try:
                test_doc = {"@context": context, original_key: "value"}
                expanded = _jsonld.expand(test_doc)

                if expanded and isinstance(expanded, list) and len(expanded) > 0:
                    for iri in expanded[0].keys():
                        reverse_map[iri] = original_key
            except Exception:
                continue

        return reverse_map

jsonld = JSONLDTools()