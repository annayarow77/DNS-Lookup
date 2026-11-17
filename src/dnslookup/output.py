"""Render lookup results for a terminal or script."""

import json
import sys


def render_batch(responses, as_json):
    if as_json:
        print(json.dumps(responses, ensure_ascii=True, allow_nan=False))
    else:
        for response in responses:
            render(response, False)


def render(response, as_json):
    if as_json:
        print(json.dumps(response, ensure_ascii=True, allow_nan=False))
        return

    query = response["query"]
    if response["error"]:
        prefix = f"{query['name']!r} {query['type']}: " if query else ""
        print(prefix + response["error"], file=sys.stderr)
        return

    print(f"{query['name']} {query['type']} via {response['resolver']} "
          f"({response['elapsed_ms']:g} ms)")
    if response["canonical_name"] != query["name"]:
        print(f"Canonical name: {response['canonical_name']}")
    if not response["answers"]:
        print("No records of the requested type.")
    for answer in response["answers"]:
        print(f"{answer['name']}\t{answer['ttl']}\t{answer['type']}\t{answer['value']}")
