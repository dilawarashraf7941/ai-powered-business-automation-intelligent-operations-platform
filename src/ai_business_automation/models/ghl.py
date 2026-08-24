"""Strict models for the single allowlisted HighLevel contact-tag mutation."""

import re
import unicodedata
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_GHL_TAGS = 10
MAX_GHL_TAG_LENGTH = 50

type GHLContactId = Annotated[str, Field(min_length=10, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")]
type GHLTag = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_GHL_TAG_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$",
    ),
]

_CREDENTIAL_PATTERN = re.compile(
    r"(?:\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bsk-[A-Za-z0-9_-]{10,}|private[ _-]?key)",
    re.IGNORECASE,
)


class GHLAddContactTagParameters(BaseModel):
    """Canonical approval-bound target and tag collection."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    contact_id: GHLContactId
    tags: tuple[GHLTag, ...] = Field(min_length=1, max_length=MAX_GHL_TAGS)

    @field_validator("tags", mode="before")
    @classmethod
    def canonicalize_tags(cls, value: object) -> object:
        if not isinstance(value, list | tuple):
            return value
        tags: list[str] = []
        identities: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                return value
            if item != item.strip() or any(
                unicodedata.category(character) in {"Cc", "Cf"} for character in item
            ):
                raise ValueError("GHL tag contains unsupported whitespace or control characters")
            if _CREDENTIAL_PATTERN.search(item):
                raise ValueError("GHL tag contains prohibited credential-like content")
            identity = item.casefold()
            if identity in identities:
                raise ValueError("GHL tags must be unique")
            identities.add(identity)
            tags.append(item)
        return tuple(sorted(tags, key=lambda tag: (tag.casefold(), tag)))


class GHLAddTagsRequest(BaseModel):
    """The complete fixed provider request body; arbitrary keys are impossible."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tags: tuple[GHLTag, ...] = Field(min_length=1, max_length=MAX_GHL_TAGS)


class GHLAddTagsResponse(BaseModel):
    """Bounded subset of the documented 201 response."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    tags: tuple[GHLTag, ...] = Field(min_length=1, max_length=100)

    @field_validator("tags", mode="before")
    @classmethod
    def parse_tags(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value
