from pyld import jsonld

def create_iri_mapping_dict(doc):
    """
    未知のJSON-LDを解析し、{絶対URL: 元のキー} の辞書を返す
    """
    reverse_map = {}
    context = doc.get('@context')

    if not context:
        return reverse_map

    # 1. 元のJSONにある全キー（@context以外）を調査
    for original_key in doc.keys():
        if original_key == "@context":
            continue

        # 2. そのキーが「どの絶対URL」に展開されるかを特定
        try:
            # 最小構成のJSONで展開テストを実施
            test_doc = {"@context": context, original_key: "value"}
            expanded = jsonld.expand(test_doc)

            if expanded and isinstance(expanded, list) and len(expanded) > 0:
                # 展開後のオブジェクトから @ で始まらないキー（＝絶対URL）を抽出
                for iri in expanded[0].keys():
                    if not iri.startswith('@'):
                        # マッピング辞書に保存
                        reverse_map[iri] = original_key
        except Exception:
            continue

    return reverse_map

# --- 実行例 ---
# どんなに未知のキー名やプレフィックスが来ても大丈夫です
incoming_json = {
    "@context": {
        "as": "https://www.w3.org/ns/activitystreams#",
        "schema": "http://schema.org/",
        "s": "as:summary",
        "c": "as:content",
        "n": "schema:name"
    },
    "type": "Note",
    "s": "A note",
    "c": "My dog has fleas.",
    "n": "John Doe"
}

# マッピングを辞書として保持
iri_to_key = create_iri_mapping_dict(incoming_json)

print(iri_to_key)