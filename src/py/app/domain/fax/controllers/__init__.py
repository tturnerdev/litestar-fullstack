"""Fax domain controllers."""

from app.domain.fax.controllers._fax_email_route import FaxEmailRouteController
from app.domain.fax.controllers._fax_message import FaxMessageController
from app.domain.fax.controllers._fax_number import FaxNumberController

__all__ = (
    "FaxEmailRouteController",
    "FaxMessageController",
    "FaxNumberController",
)
