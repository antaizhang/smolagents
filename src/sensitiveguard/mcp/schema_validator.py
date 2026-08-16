"""Dependency-free, strict validation for MCP JSON-schema payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any


class SchemaDefinitionError(ValueError):
    """Raised when a tool advertises an invalid or unsupported schema."""


class SchemaValidationError(ValueError):
    """Raised when an MCP payload does not conform to its schema."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.validation_message = message
        super().__init__(f"{path}: {message}")


class MCPSchemaValidator:
    """Validate the security-relevant subset of JSON Schema used by MCP tools.

    Object schemas are always closed: omitted or permissive
    ``additionalProperties`` declarations are replaced with ``False``.  This
    prevents a model from smuggling sensitive fields through undeclared keys.
    """

    def __init__(self, *, max_depth: int = 64) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be positive")
        self.max_depth = max_depth

    def make_strict(self, schema: Mapping[str, Any] | bool) -> dict[str, Any] | bool:
        if isinstance(schema, bool):
            return schema
        if not isinstance(schema, Mapping):
            raise SchemaDefinitionError("Schema must be an object or boolean")
        strict = deepcopy(dict(schema))
        self._close_object_schemas(strict, depth=0)
        return strict

    def validate(self, instance: Any, schema: Mapping[str, Any] | bool) -> Any:
        strict = self.make_strict(schema)
        self._validate(instance, strict, path="$", root=strict, depth=0)
        return instance

    validate_payload = validate

    def describes_object(self, schema: Mapping[str, Any] | bool) -> bool:
        """Return whether a schema explicitly constrains an object payload."""

        strict = self.make_strict(schema)
        return self._describes_object(strict, root=strict, depth=0)

    def _close_object_schemas(self, schema: Any, *, depth: int) -> None:
        self._check_depth(depth)
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaDefinitionError("Nested schema must be an object or boolean")

        if self._is_object_like(schema):
            schema["additionalProperties"] = False

        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise SchemaDefinitionError("properties must be an object")
        for child in properties.values():
            self._close_object_schemas(child, depth=depth + 1)

        if "items" in schema:
            self._close_object_schemas(schema["items"], depth=depth + 1)
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in schema:
                continue
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                raise SchemaDefinitionError(f"{keyword} must be a non-empty array")
            for branch in branches:
                self._close_object_schemas(branch, depth=depth + 1)
        if "not" in schema:
            self._close_object_schemas(schema["not"], depth=depth + 1)
        for definitions_key in ("$defs", "definitions"):
            definitions = schema.get(definitions_key, {})
            if not isinstance(definitions, Mapping):
                raise SchemaDefinitionError(f"{definitions_key} must be an object")
            for child in definitions.values():
                self._close_object_schemas(child, depth=depth + 1)

    def _validate(
        self,
        instance: Any,
        schema: Mapping[str, Any] | bool,
        *,
        path: str,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> None:
        self._check_depth(depth)
        if schema is True:
            return
        if schema is False:
            raise SchemaValidationError(path, "value is forbidden by schema")
        if not isinstance(schema, Mapping):
            raise SchemaDefinitionError("Nested schema must be an object or boolean")

        if "$ref" in schema:
            target = self._resolve_local_ref(root, schema["$ref"])
            self._validate(instance, target, path=path, root=root, depth=depth + 1)

        self._validate_combinators(instance, schema, path=path, root=root, depth=depth)
        self._validate_type(instance, schema, path=path)

        if "const" in schema and instance != schema["const"]:
            raise SchemaValidationError(path, "value does not match const")
        if "enum" in schema:
            enum_values = schema["enum"]
            if not isinstance(enum_values, list) or not enum_values:
                raise SchemaDefinitionError("enum must be a non-empty array")
            if instance not in enum_values:
                raise SchemaValidationError(path, "value is not in enum")

        if isinstance(instance, Mapping) and self._is_object_like(schema):
            self._validate_object(instance, schema, path=path, root=root, depth=depth)
        elif isinstance(instance, list) and (schema.get("type") == "array" or "items" in schema):
            self._validate_array(instance, schema, path=path, root=root, depth=depth)
        elif isinstance(instance, str):
            self._validate_string(instance, schema, path=path)
        elif self._is_number(instance):
            self._validate_number(instance, schema, path=path)

    def _validate_combinators(
        self,
        instance: Any,
        schema: Mapping[str, Any],
        *,
        path: str,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> None:
        for branch in schema.get("allOf", ()):
            self._validate(instance, branch, path=path, root=root, depth=depth + 1)

        any_of = schema.get("anyOf")
        if any_of is not None and not self._matching_branches(instance, any_of, path, root, depth):
            raise SchemaValidationError(path, "value does not match anyOf")

        one_of = schema.get("oneOf")
        if one_of is not None and self._matching_branches(instance, one_of, path, root, depth) != 1:
            raise SchemaValidationError(path, "value does not match exactly one oneOf branch")

        if "not" in schema:
            try:
                self._validate(instance, schema["not"], path=path, root=root, depth=depth + 1)
            except SchemaValidationError:
                pass
            else:
                raise SchemaValidationError(path, "value matches forbidden schema")

    def _matching_branches(
        self,
        instance: Any,
        branches: Any,
        path: str,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> int:
        if not isinstance(branches, list) or not branches:
            raise SchemaDefinitionError("Schema branches must be a non-empty array")
        matches = 0
        for branch in branches:
            try:
                self._validate(instance, branch, path=path, root=root, depth=depth + 1)
            except SchemaValidationError:
                continue
            matches += 1
        return matches

    def _validate_type(self, instance: Any, schema: Mapping[str, Any], *, path: str) -> None:
        expected = schema.get("type")
        if expected is None:
            return
        expected_types = [expected] if isinstance(expected, str) else expected
        if (
            not isinstance(expected_types, list)
            or not expected_types
            or not all(isinstance(value, str) for value in expected_types)
        ):
            raise SchemaDefinitionError("type must be a string or non-empty string array")
        if not any(self._matches_type(instance, value) for value in expected_types):
            raise SchemaValidationError(path, f"expected type {' or '.join(expected_types)}")

    def _validate_object(
        self,
        instance: Mapping[str, Any],
        schema: Mapping[str, Any],
        *,
        path: str,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> None:
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping):
            raise SchemaDefinitionError("properties must be an object")
        if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
            raise SchemaDefinitionError("required must be a string array")
        missing = [key for key in required if key not in instance]
        if missing:
            raise SchemaValidationError(path, f"missing required properties: {', '.join(sorted(missing))}")

        unknown = [key for key in instance if key not in properties]
        if unknown:
            raise SchemaValidationError(path, "additional properties are forbidden")
        for key, value in instance.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                self._validate(value, child_schema, path=f"{path}.{key}", root=root, depth=depth + 1)

        self._check_size(instance, schema, path=path, minimum="minProperties", maximum="maxProperties")

    def _validate_array(
        self,
        instance: list[Any],
        schema: Mapping[str, Any],
        *,
        path: str,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> None:
        self._check_size(instance, schema, path=path, minimum="minItems", maximum="maxItems")
        if schema.get("uniqueItems") and len({self._stable_repr(item) for item in instance}) != len(instance):
            raise SchemaValidationError(path, "array items must be unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, value in enumerate(instance):
                self._validate(value, item_schema, path=f"{path}[{index}]", root=root, depth=depth + 1)

    @staticmethod
    def _validate_string(instance: str, schema: Mapping[str, Any], *, path: str) -> None:
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and len(instance) < minimum:
            raise SchemaValidationError(path, "string is shorter than minLength")
        if maximum is not None and len(instance) > maximum:
            raise SchemaValidationError(path, "string is longer than maxLength")
        if "pattern" in schema:
            try:
                matches = re.search(schema["pattern"], instance)
            except (re.error, TypeError) as exc:
                raise SchemaDefinitionError("pattern must be a valid regular expression") from exc
            if matches is None:
                raise SchemaValidationError(path, "string does not match pattern")

    @staticmethod
    def _validate_number(instance: int | float, schema: Mapping[str, Any], *, path: str) -> None:
        comparisons = (
            ("minimum", lambda value, bound: value >= bound),
            ("maximum", lambda value, bound: value <= bound),
            ("exclusiveMinimum", lambda value, bound: value > bound),
            ("exclusiveMaximum", lambda value, bound: value < bound),
        )
        for keyword, comparison in comparisons:
            if keyword in schema and not comparison(instance, schema[keyword]):
                raise SchemaValidationError(path, f"number violates {keyword}")

    @staticmethod
    def _check_size(instance: Any, schema: Mapping[str, Any], *, path: str, minimum: str, maximum: str) -> None:
        if minimum in schema and len(instance) < schema[minimum]:
            raise SchemaValidationError(path, f"value has fewer entries than {minimum}")
        if maximum in schema and len(instance) > schema[maximum]:
            raise SchemaValidationError(path, f"value has more entries than {maximum}")

    @staticmethod
    def _matches_type(instance: Any, expected: str) -> bool:
        matchers = {
            "null": lambda value: value is None,
            "boolean": lambda value: isinstance(value, bool),
            "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
            "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
            "string": lambda value: isinstance(value, str),
            "array": lambda value: isinstance(value, list),
            "object": lambda value: isinstance(value, Mapping),
        }
        if expected not in matchers:
            raise SchemaDefinitionError(f"Unsupported JSON Schema type: {expected}")
        return matchers[expected](instance)

    @staticmethod
    def _is_number(instance: Any) -> bool:
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)

    @staticmethod
    def _is_object_like(schema: Mapping[str, Any]) -> bool:
        schema_type = schema.get("type")
        declares_object = schema_type == "object" or (isinstance(schema_type, list) and "object" in schema_type)
        return declares_object or any(
            keyword in schema for keyword in ("properties", "required", "additionalProperties")
        )

    def _describes_object(
        self,
        schema: Mapping[str, Any] | bool,
        *,
        root: Mapping[str, Any] | bool,
        depth: int,
    ) -> bool:
        self._check_depth(depth)
        if not isinstance(schema, Mapping):
            return False
        if self._is_object_like(schema):
            return True
        if "$ref" in schema:
            target = self._resolve_local_ref(root, schema["$ref"])
            return self._describes_object(target, root=root, depth=depth + 1)
        for keyword in ("allOf", "anyOf", "oneOf"):
            branches = schema.get(keyword)
            if branches and all(self._describes_object(branch, root=root, depth=depth + 1) for branch in branches):
                return True
        return False

    @staticmethod
    def _stable_repr(value: Any) -> str:
        if isinstance(value, Mapping):
            return repr(sorted((str(key), MCPSchemaValidator._stable_repr(item)) for key, item in value.items()))
        if isinstance(value, list):
            return repr([MCPSchemaValidator._stable_repr(item) for item in value])
        return repr(value)

    @staticmethod
    def _resolve_local_ref(root: Mapping[str, Any] | bool, reference: Any) -> Mapping[str, Any] | bool:
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise SchemaDefinitionError("Only local JSON Schema references are supported")
        current: Any = root
        for encoded_part in reference[2:].split("/"):
            part = encoded_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, Mapping) or part not in current:
                raise SchemaDefinitionError("JSON Schema reference cannot be resolved")
            current = current[part]
        if not isinstance(current, (Mapping, bool)):
            raise SchemaDefinitionError("JSON Schema reference does not point to a schema")
        return current

    def _check_depth(self, depth: int) -> None:
        if depth > self.max_depth:
            raise SchemaDefinitionError("JSON Schema nesting limit exceeded")


SchemaValidator = MCPSchemaValidator
