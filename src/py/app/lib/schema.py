from typing import Any

import msgspec
from advanced_alchemy.utils.text import camelize
from pydantic import BaseModel as _BaseModel
from pydantic import ConfigDict


class BaseStruct(msgspec.Struct):
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for f in self.__struct_fields__:
            val = getattr(self, f)
            if val is not msgspec.UNSET:
                result[f] = val
        return result


class CamelizedBaseStruct(BaseStruct, rename="camel"):
    """Camelized Base Struct"""


class Message(CamelizedBaseStruct):
    message: str


class BaseSchema(_BaseModel):
    """Base Settings."""

    model_config = ConfigDict(
        validate_assignment=True,
        from_attributes=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
    )


class CamelizedBaseSchema(BaseSchema):
    """Camelized Base pydantic schema."""

    model_config = ConfigDict(populate_by_name=True, alias_generator=camelize)
