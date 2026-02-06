"""Fax domain schemas."""

from app.domain.fax.schemas._fax_email_route import FaxEmailRoute, FaxEmailRouteCreate, FaxEmailRouteUpdate
from app.domain.fax.schemas._fax_message import FaxMessage, FaxMessageCreate
from app.domain.fax.schemas._fax_number import FaxNumber, FaxNumberUpdate
from app.lib.schema import Message

__all__ = (
    "FaxEmailRoute",
    "FaxEmailRouteCreate",
    "FaxEmailRouteUpdate",
    "FaxMessage",
    "FaxMessageCreate",
    "FaxNumber",
    "FaxNumberUpdate",
    "Message",
)
