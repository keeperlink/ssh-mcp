"""TEST-371 value-free validation rejection helper."""
from __future__ import annotations

import json
import unittest

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from app.mcp_gateway import _validation_rejection


class _Echoing(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    value: str

    @field_validator("value")
    @classmethod
    def unsafe_message(cls, value: str) -> str:
        # A careless validator that interpolates the submitted value.
        raise ValueError(f"rejected {value}")


class _Long(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def long_message(cls, value: str) -> str:
        raise ValueError("x" * 300)


def body(error: ValidationError) -> dict:
    result = _validation_rejection(error)
    assert result.is_error
    return json.loads(result.content[0].text)


class ValidationRejectionTests(unittest.TestCase):
    def test_message_containing_input_is_replaced(self):
        with self.assertRaises(ValidationError) as caught:
            _Echoing.model_validate({"value": "SECRET-371-VALUE"})
        data = body(caught.exception)
        self.assertEqual(data["failed_field"], "value")
        self.assertEqual(data["error"], "Invalid value")
        self.assertNotIn("SECRET-371-VALUE", json.dumps(data))

    def test_overlong_message_is_replaced(self):
        with self.assertRaises(ValidationError) as caught:
            _Long.model_validate({"value": "ok"})
        self.assertEqual(body(caught.exception)["error"], "Invalid value")

    def test_unsafe_unknown_key_and_nested_index_paths(self):
        with self.assertRaises(ValidationError) as caught:
            _Echoing.model_validate({"value": "abc", "x" * 65: 1, "bad key": 2})
        data = body(caught.exception)
        self.assertIn(data["failed_field"], {"value", "?"})
        self.assertEqual(data["error_count"], 3)

        class Nested(BaseModel):
            items: list[int]

        with self.assertRaises(ValidationError) as caught:
            Nested.model_validate({"items": [1, "two"]})
        self.assertEqual(body(caught.exception)["failed_field"], "items.1")

    def test_model_level_error_uses_arguments(self):
        from app.contracts import TransferFileRequest
        with self.assertRaises(ValidationError) as caught:
            TransferFileRequest.model_validate({
                "source_server": "a", "source_path": "/x", "dest_server": "a",
                "dest_path": "/y", "reason": "r",
            })
        data = body(caught.exception)
        self.assertEqual(data["failed_field"], "arguments")
        self.assertIn("different approved hosts", data["error"])


if __name__ == "__main__":
    unittest.main()
