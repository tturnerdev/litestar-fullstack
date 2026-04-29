"""Fax domain schemas."""

from app.domain.fax.schemas._fax_email_route import FaxEmailRoute, FaxEmailRouteCreate, FaxEmailRouteUpdate
from app.domain.fax.schemas._fax_message import FaxMessage, FaxMessageCreate, SendFax
from app.domain.fax.schemas._fax_number import FaxNumber, FaxNumberCreate, FaxNumberUpdate
from app.lib.schema import Message

__all__ = (
    "FaxEmailRoute",
    "FaxEmailRouteCreate",
    "FaxEmailRouteUpdate",
    "FaxMessage",
    "FaxMessageCreate",
    "FaxNumber",
    "FaxNumberCreate",
    "FaxNumberUpdate",
    "SendFax",
    "Message",
)
