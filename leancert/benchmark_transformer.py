from __future__ import annotations

import copy
from typing import Any


def _matches(item: dict[str, Any], match: dict[str, Any]) -> bool:
    return all(item.get(key) == value for key, value in match.items())


def _targets(trace: dict[str, Any], selector: dict[str, Any]) -> list[dict[str, Any]]:
    collection = selector.get("collection")
    values = trace.get(collection, []) if collection else [trace]
    if not isinstance(values, list):
        raise ValueError(f"Selector collection is not a list: {collection}")
    match = selector.get("match", {})
    matches = [item for item in values if isinstance(item, dict) and _matches(item, match)]
    occurrence = selector.get("occurrence", "first")
    if occurrence == "all":
        return matches
    if occurrence == "last":
        return matches[-1:] if matches else []
    return matches[:1]


def apply_mutation(trace: dict[str, Any], mutation: dict[str, Any]) -> dict[str, Any]:
    """Execute declarative data edits without interpreting forensic requirements."""
    output = copy.deepcopy(trace)
    operation = mutation["operation"]
    selector = mutation.get("selector", {})
    targets = _targets(output, selector)
    if not targets:
        raise ValueError(f"Mutation {mutation.get('mutation_id')} selector matched no objects")
    field = mutation.get("field") or selector.get("field")
    if operation == "replace_value":
        for target in targets:
            target[field] = copy.deepcopy(mutation.get("value"))
    elif operation == "remove_field":
        for target in targets:
            target.pop(field, None)
    elif operation == "alter_integer":
        for target in targets:
            target[field] = int(target[field]) + int(mutation.get("delta", 0))
    elif operation == "copy_value":
        source_selector = mutation["source_selector"]
        sources = _targets(output, source_selector)
        if not sources:
            raise ValueError("Source selector matched no objects")
        source_field = mutation.get("source_field", field)
        for target in targets:
            target[field] = copy.deepcopy(sources[0][source_field])
    elif operation == "append_value":
        for target in targets:
            target.setdefault(field, []).append(copy.deepcopy(mutation.get("value")))
    elif operation == "duplicate_object":
        collection = output[selector["collection"]]
        duplicate = copy.deepcopy(targets[0])
        duplicate.update(copy.deepcopy(mutation.get("updates", {})))
        collection.append(duplicate)
    elif operation == "remove_object":
        collection = output[selector["collection"]]
        output[selector["collection"]] = [item for item in collection if item not in targets]
    elif operation == "reorder_collection":
        output[selector["collection"]] = list(reversed(output[selector["collection"]]))
    else:
        raise ValueError(f"Unsupported declarative operation: {operation}")
    return output
