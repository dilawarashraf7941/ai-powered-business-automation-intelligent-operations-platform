"""Strict models for the single allowlisted HighLevel contact-tag mutation."""

import re
import unicodedata
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_GHL_TAG_LENGTH = 50

type GHLContactId = Annotated[str, Field(min_length=10, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")]
type GHLTag = Annotated[
    str,
    Field(min_length=1, max_length=MAX_GHL_TAG_LENGTH, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$"),
]

_CREDENTIAL_PATTERN = re.compile(
    r"(?:\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bsk-[A-Za-z0-9_-]{10,}|private[ _-]?key)",
    re.IGNORECASE,
)


class GHLAddContactTagParameters(BaseModel):
    """Canonical approval-bound target and exactly one tag."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    contact_id: GHLContactId
    tag: GHLTag

    @field_validator("tag")
    @classmethod
    def validate_tag(cls, value: str) -> str:
        if value != value.strip() or any(
            unicodedata.category(character) in {"Cc", "Cf"} for character in value
        ):
            raise ValueError("GHL tag contains unsupported whitespace or control characters")
        if _CREDENTIAL_PATTERN.search(value):
            raise ValueError("GHL tag contains prohibited credential-like content")
        return value


class GHLAddTagsRequest(BaseModel):
    """The complete fixed provider request body; arbitrary keys are impossible."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tags: tuple[GHLTag] = Field(min_length=1, max_length=1)


class GHLAddTagsResponse(BaseModel):
    """Bounded subset of the provider's documented HTTP 201 response."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    tags: tuple[GHLTag, ...] = Field(min_length=1, max_length=100)

    @field_validator("tags", mode="before")
    @classmethod
    def parse_tags(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value
