from __future__ import annotations

from typing import Any, Optional, Type

from pydantic import BaseModel


class Swag:
    """Compatibility decorator used in Flask version.

    FastAPI generates OpenAPI from type hints and `response_model`.
    We keep this class as a no-op so existing decorators don't break.
    """

    def __init__(self, tag: str):
        self.tag = tag

    def body(self, model: Optional[Type[BaseModel]] = None, content_type: str = 'application/json'):
        return self

    def response(self, model: Optional[Type[BaseModel]] = None):
        return self

    def __call__(self, fn):
        return fn
