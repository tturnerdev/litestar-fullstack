"""FreePBX GraphQL gateway provider."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, ClassVar

import httpx
from structlog import get_logger

from app.db import models as m
from app.domain.gateway.providers._base import GatewayProvider, ProviderResult
from app.domain.gateway.providers import register_provider

logger = get_logger()

# ---------------------------------------------------------------------------
# OAuth2 token cache
# ---------------------------------------------------------------------------

TOKEN_EXPIRY_BUFFER_SECONDS = 60
"""Refresh the token this many seconds before its actual expiry."""


@dataclass
class CachedToken:
    """An in-memory cached OAuth2 access token."""

    access_token: str
    expires_at: float


_token_cache: dict[str, CachedToken] = {}


# ---------------------------------------------------------------------------
# GraphQL query constants
# ---------------------------------------------------------------------------

_GQL_ALL_INBOUND_ROUTES = """\
query {
  allInboundRoutes {
    totalCount
    inboundRoutes {
      extension
      cidnum
      description
      destinationConnection
      privacyman
      alertinfo
      grppre
      delay_answer
    }
  }
}
"""

_GQL_ALL_EXTENSIONS = """\
query {
  fetchAllExtensions {
    status
    message
    totalCount
    extension {
      id
      extensionId
      user {
        name
        outboundCid
        voicemail
        ringtimer
        noanswer
        noanswerDestination
        callwaiting
        donotdisturb
      }
      coreDevice {
        deviceId
        dial
        devicetype
        description
        emergencyCid
        tech
      }
    }
  }
}
"""

_GQL_EXTENSION = """\
query {{
  fetchExtension(extensionId: "{ext}") {{
    status
    message
    extensionId
    user {{
      name
      outboundCid
      voicemail
      ringtimer
      noanswer
      noanswerCid
      busyCid
      chanunavailCid
      noanswerDestination
      busyDestination
      chanunavailDestination
      callwaiting
      donotdisturb
      callforward_unconditional
      callforward_busy
      sipname
      mohclass
      recording
      recording_in_external
      recording_out_external
      recording_in_internal
      recording_out_internal
      recording_ondemand
      recording_priority
    }}
    coreDevice {{
      deviceId
      dial
      devicetype
      description
      emergencyCid
      tech
    }}
  }}
}}
"""

_GQL_FOLLOW_ME = """\
query {{
  fetchFollowMe(extensionId: "{ext}") {{
    status
    message
    enabled
    extensionId
    strategy
    ringTime
    followMeList
    initialRingTime
    confirmCalls
    noAnswerDestination
  }}
}}
"""

_GQL_ALL_RING_GROUPS = """\
query {
  fetchAllRingGroups {
    status
    totalCount
    message
    ringgroups {
      groupNumber
      description
      groupList
      strategy
      groupTime
      groupPrefix
    }
  }
}
"""

_GQL_UPDATE_EXTENSION = """\
mutation {{
  updateExtension(input: {{
    extensionId: "{ext}"
    {fields}
  }}) {{
    status
    message
  }}
}}
"""

_GQL_ADD_EXTENSION = """\
mutation {{
  addExtension(input: {{
    extensionId: "{ext}"
    {fields}
  }}) {{
    status
    message
  }}
}}
"""

_GQL_DO_RELOAD = """\
mutation {
  doreload(input: {}) {
    status
    message
    transaction_id
  }
}
"""

_GQL_ALL_CORE_DEVICES = """\
query {
  fetchAllCoreDevices {
    status
    message
    totalCount
    coreDevice {
      deviceId
      tech
      dial
      devicetype
      description
      emergencyCid
      user {
        name
        extension
      }
    }
  }
}
"""

_GQL_VOICEMAIL = """\
query {
  fetchVoiceMail {
    status
    message
    voicemail {
      mailbox
      email
      pager
    }
  }
}
"""

_GQL_ALL_CDRS = """\
query {
  fetchAllCdrs {
    status
    message
    totalCount
    cdr {
      calldate
      clid
      src
      dst
      dcontext
      channel
      dstchannel
      lastapp
      lastdata
      duration
      billsec
      disposition
      amaflags
      uniqueid
    }
  }
}
"""


# ---------------------------------------------------------------------------
# Asterisk dialplan destination parser
# ---------------------------------------------------------------------------


def parse_destination(destination: str) -> dict[str, str]:
    """Parse an Asterisk dialplan destination into a typed label.

    FreePBX stores routing destinations in the format
    ``context,extension,priority`` (e.g. ``ext-group,600,1``).  This
    helper returns a dict with ``type``, ``target``, and ``label`` keys
    that describe the destination in human-readable form.

    Args:
        destination: The raw dialplan destination string.

    Returns:
        A dict with ``type``, ``target``, and ``label``.
    """
    if not destination:
        return {"type": "unknown", "target": "", "label": ""}

    parts = destination.split(",")
    if len(parts) < 2:
        return {"type": "unknown", "target": destination, "label": destination}

    context, exten = parts[0], parts[1]

    # IVR menus use a variable context prefix
    if context.startswith("ivr-"):
        ivr_id = context.removeprefix("ivr-")
        return {"type": "ivr", "target": ivr_id, "label": f"IVR Menu {ivr_id}"}

    # Voicemail variants live under ext-local
    if context.startswith("ext-local") and exten.startswith("vm"):
        # vmb = busy greeting, vmu = unavailable greeting, vm = standard
        if exten.startswith("vmb"):
            ext_num = exten[3:]
            return {"type": "voicemail", "target": ext_num, "label": f"Voicemail (busy) {ext_num}"}
        if exten.startswith("vmu"):
            ext_num = exten[3:]
            return {"type": "voicemail", "target": ext_num, "label": f"Voicemail (unavail) {ext_num}"}
        ext_num = exten[2:]
        return {"type": "voicemail", "target": ext_num, "label": f"Voicemail {ext_num}"}

    # Static context -> type mapping
    mapping: dict[str, tuple[str, str]] = {
        "from-did-direct": ("extension", f"Extension {exten}"),
        "ext-local": ("extension", f"Extension {exten}"),
        "ext-group": ("ring_group", f"Ring Group {exten}"),
        "ext-queues": ("queue", f"Queue {exten}"),
        "timeconditions": ("time_condition", f"Time Condition {exten}"),
        "app-blackhole": ("terminate", f"Terminate ({exten})"),
        "ext-meetme": ("conference", f"Conference {exten}"),
        "app-announcement": ("announcement", f"Announcement {exten}"),
        "app-misclookup": ("misc_destination", f"Misc Destination {exten}"),
    }

    if context in mapping:
        dtype, label = mapping[context]
        return {"type": dtype, "target": exten, "label": label}

    return {"type": "unknown", "target": destination, "label": destination}


# ---------------------------------------------------------------------------
# FreePBX GraphQL provider
# ---------------------------------------------------------------------------


@register_provider
class FreePBXProvider(GatewayProvider):
    """Gateway provider for FreePBX systems using the GraphQL API.

    Handles OAuth2 client-credentials authentication, in-memory token
    caching, and translates queries into FreePBX GraphQL operations.
    """

    provider_name: ClassVar[str] = "freepbx"
    supported_domains: ClassVar[set[str]] = {"numbers", "extensions", "devices"}

    # -- OAuth2 token management -------------------------------------------

    async def _get_token(self, connection: m.Connection) -> str:
        """Obtain a valid OAuth2 access token for *connection*.

        Tokens are cached in a module-level dict keyed by the connection's
        primary key.  A cached token is reused unless it is within
        ``TOKEN_EXPIRY_BUFFER_SECONDS`` of expiry, in which case a fresh
        one is obtained from the FreePBX token endpoint.

        Args:
            connection: The connection whose credentials to use.

        Returns:
            A bearer access token string.

        Raises:
            ValueError: If credentials are missing or incomplete.
            httpx.HTTPStatusError: If the token request fails.
        """
        cache_key = str(connection.id)
        cached = _token_cache.get(cache_key)
        if cached and cached.expires_at > time.time() + TOKEN_EXPIRY_BUFFER_SECONDS:
            return cached.access_token

        creds = connection.credentials or {}
        client_id = creds.get("client_id")
        client_secret = creds.get("client_secret")
        scopes: list[str] = creds.get("scopes", [])

        if not client_id or not client_secret:
            msg = "FreePBX connection is missing client_id or client_secret in credentials"
            raise ValueError(msg)

        base_url = self._base_url(connection)
        token_url = f"{base_url}/admin/api/api/token"

        form_data: dict[str, str] = {"grant_type": "client_credentials"}
        if scopes:
            form_data["scope"] = " ".join(scopes)

        settings = connection.settings or {}
        verify_ssl = settings.get("verify_ssl", True)
        timeout = settings.get("timeout", 10)

        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            resp = await client.post(
                token_url,
                data=form_data,
                auth=(client_id, client_secret),
            )
            resp.raise_for_status()
            data = resp.json()

        access_token: str = data["access_token"]
        expires_in: int = data.get("expires_in", 3600)

        _token_cache[cache_key] = CachedToken(
            access_token=access_token,
            expires_at=time.time() + expires_in,
        )

        await logger.adebug(
            "freepbx_token_acquired",
            connection_id=cache_key,
            expires_in=expires_in,
        )
        return access_token

    # -- GraphQL client ----------------------------------------------------

    async def _execute_graphql(
        self,
        query: str,
        connection: m.Connection,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query against the FreePBX API.

        Args:
            query: The GraphQL query string.
            connection: The connection to query against.
            variables: Optional GraphQL variables.

        Returns:
            The parsed JSON response body.

        Raises:
            httpx.HTTPStatusError: On non-2xx responses.
            httpx.TimeoutException: On request timeout.
        """
        token = await self._get_token(connection)
        base_url = self._base_url(connection)
        url = f"{base_url}/admin/api/api/gql"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        settings = connection.settings or {}
        timeout = settings.get("timeout", 10)
        verify_ssl = settings.get("verify_ssl", True)

        payload: dict[str, Any] = {"query": query}
        if variables is not None:
            payload["variables"] = variables

        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()

    # -- Public query methods ----------------------------------------------

    async def query_number(self, phone_number: str, connection: m.Connection) -> ProviderResult:
        """Look up a phone number in FreePBX.

        Queries inbound routes for matching DIDs and extensions whose
        outbound caller ID matches the phone number.
        """
        try:
            return await self._query_number_inner(phone_number, connection)
        except httpx.TimeoutException as exc:
            await logger.awarning("freepbx_query_number_timeout", phone_number=phone_number, error=str(exc))
            return ProviderResult(status="timeout", error=f"Request timed out: {exc}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                self._invalidate_token(connection)
                await logger.awarning("freepbx_query_number_auth_failed", phone_number=phone_number, status=exc.response.status_code)
                return ProviderResult(status="auth_failed", error=f"Authentication failed (HTTP {exc.response.status_code})")
            await logger.awarning("freepbx_query_number_error", phone_number=phone_number, error=str(exc))
            return ProviderResult(status="error", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            await logger.awarning("freepbx_query_number_error", phone_number=phone_number, error=str(exc))
            return ProviderResult(status="error", error=str(exc))

    async def query_extension(self, extension: str, connection: m.Connection) -> ProviderResult:
        """Look up an extension in FreePBX.

        Fetches extension details, core device, Follow Me configuration,
        and ring group membership.
        """
        try:
            return await self._query_extension_inner(extension, connection)
        except httpx.TimeoutException as exc:
            await logger.awarning("freepbx_query_extension_timeout", extension=extension, error=str(exc))
            return ProviderResult(status="timeout", error=f"Request timed out: {exc}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                self._invalidate_token(connection)
                await logger.awarning("freepbx_query_extension_auth_failed", extension=extension, status=exc.response.status_code)
                return ProviderResult(status="auth_failed", error=f"Authentication failed (HTTP {exc.response.status_code})")
            await logger.awarning("freepbx_query_extension_error", extension=extension, error=str(exc))
            return ProviderResult(status="error", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            await logger.awarning("freepbx_query_extension_error", extension=extension, error=str(exc))
            return ProviderResult(status="error", error=str(exc))

    async def query_device(self, mac_address: str, connection: m.Connection) -> ProviderResult:
        """Look up a device by MAC address in FreePBX.

        FreePBX GraphQL has limited device support.  This performs a
        best-effort search of core devices and cross-references with
        extension data.
        """
        try:
            return await self._query_device_inner(mac_address, connection)
        except httpx.TimeoutException as exc:
            await logger.awarning("freepbx_query_device_timeout", mac_address=mac_address, error=str(exc))
            return ProviderResult(status="timeout", error=f"Request timed out: {exc}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                self._invalidate_token(connection)
                await logger.awarning("freepbx_query_device_auth_failed", mac_address=mac_address, status=exc.response.status_code)
                return ProviderResult(status="auth_failed", error=f"Authentication failed (HTTP {exc.response.status_code})")
            await logger.awarning("freepbx_query_device_error", mac_address=mac_address, error=str(exc))
            return ProviderResult(status="error", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            await logger.awarning("freepbx_query_device_error", mac_address=mac_address, error=str(exc))
            return ProviderResult(status="error", error=str(exc))

    async def health_check(self, connection: m.Connection) -> tuple[bool, str | None]:
        """Verify connectivity by attempting a token exchange."""
        try:
            await self._get_token(connection)
            return True, None
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    # -- Extension mutation helpers ----------------------------------------

    @staticmethod
    def _build_update_fields(
        display_name: str | None = None,
        dnd_enabled: bool | None = None,
        no_answer_dest: str | None = None,
        ring_timer: int | None = None,
    ) -> str:
        parts: list[str] = []
        if display_name is not None:
            escaped = display_name.replace("\\", "\\\\").replace('"', '\\"')
            parts.append(f'name: "{escaped}"')
        if dnd_enabled is not None:
            parts.append(f'donotdisturb: "{"yes" if dnd_enabled else "no"}"')
        if no_answer_dest is not None:
            parts.append(f'noanswerDestination: "{no_answer_dest}"')
        if ring_timer is not None:
            parts.append(f'ringtimer: "{ring_timer}"')
        return "\n    ".join(parts)

    async def _do_reload(self, connection: m.Connection) -> dict[str, Any]:
        result = await self._execute_graphql(_GQL_DO_RELOAD, connection)
        await logger.ainfo("freepbx_do_reload", result=result)
        return result

    async def update_extension_on_pbx(
        self,
        ext_number: str,
        connection: m.Connection,
        *,
        display_name: str | None = None,
        dnd_enabled: bool | None = None,
        no_answer_dest: str | None = None,
        ring_timer: int | None = None,
    ) -> dict[str, Any]:
        fields = self._build_update_fields(display_name, dnd_enabled, no_answer_dest, ring_timer)
        query = _GQL_UPDATE_EXTENSION.format(ext=ext_number, fields=fields)
        result = await self._execute_graphql(query, connection)
        await logger.ainfo("freepbx_update_extension", ext=ext_number, result=result)
        await self._do_reload(connection)
        return result

    async def add_extension_on_pbx(
        self,
        ext_number: str,
        connection: m.Connection,
        *,
        display_name: str | None = None,
        email: str = "",
        dnd_enabled: bool | None = None,
        no_answer_dest: str | None = None,
        ring_timer: int | None = None,
    ) -> dict[str, Any]:
        escaped_name = (display_name or f"Extension {ext_number}").replace("\\", "\\\\").replace('"', '\\"')
        add_fields = f'name: "{escaped_name}"\n    email: "{email}"'
        query = _GQL_ADD_EXTENSION.format(ext=ext_number, fields=add_fields)
        result = await self._execute_graphql(query, connection)
        await logger.ainfo("freepbx_add_extension", ext=ext_number, result=result)

        update_fields = self._build_update_fields(
            dnd_enabled=dnd_enabled,
            no_answer_dest=no_answer_dest,
            ring_timer=ring_timer,
        )
        if update_fields:
            update_query = _GQL_UPDATE_EXTENSION.format(ext=ext_number, fields=update_fields)
            await self._execute_graphql(update_query, connection)

        await self._do_reload(connection)
        return result

    # -- Internal query implementations ------------------------------------

    async def _query_number_inner(self, phone_number: str, connection: m.Connection) -> ProviderResult:
        """Core implementation for number queries."""
        # Normalize the phone number for matching (strip leading +, spaces, dashes)
        normalized = re.sub(r"[^\d]", "", phone_number)

        # 1. Fetch all inbound routes and filter for matching DID
        routes_resp = await self._execute_graphql(_GQL_ALL_INBOUND_ROUTES, connection)
        routes_data = routes_resp.get("data", {}).get("allInboundRoutes", {})
        all_routes: list[dict[str, Any]] = routes_data.get("inboundRoutes", []) or []

        matching_routes: list[dict[str, Any]] = []
        for route in all_routes:
            route_did = re.sub(r"[^\d]", "", route.get("extension", ""))
            if route_did and (route_did == normalized or normalized.endswith(route_did) or route_did.endswith(normalized)):
                destination_raw = route.get("destinationConnection", "") or ""
                parsed = parse_destination(destination_raw)
                matching_routes.append({
                    "description": route.get("description", ""),
                    "did": route.get("extension", ""),
                    "cid_pattern": route.get("cidnum", ""),
                    "destination": destination_raw,
                    "destination_label": parsed["label"],
                    "destination_type": parsed["type"],
                    "destination_target": parsed["target"],
                    "privacy_manager": _to_bool(route.get("privacyman")),
                    "alert_info": route.get("alertinfo") or None,
                    "group_prefix": route.get("grppre") or None,
                    "delay_answer": _to_int(route.get("delay_answer")),
                })

        # 2. Fetch all extensions and find those using this number as outbound CID
        ext_resp = await self._execute_graphql(_GQL_ALL_EXTENSIONS, connection)
        ext_data = ext_resp.get("data", {}).get("fetchAllExtensions", {})
        all_extensions: list[dict[str, Any]] = ext_data.get("extension", []) or []

        extensions_using: list[dict[str, Any]] = []
        for ext in all_extensions:
            user = ext.get("user") or {}
            outbound_cid = user.get("outboundCid", "") or ""
            # Extract digits from the outbound CID string (e.g., '"John" <15551234567>')
            cid_digits = re.sub(r"[^\d]", "", outbound_cid)
            if cid_digits and (cid_digits == normalized or normalized.endswith(cid_digits) or cid_digits.endswith(normalized)):
                extensions_using.append({
                    "extension_id": ext.get("extensionId", ""),
                    "name": user.get("name", ""),
                    "outbound_cid": outbound_cid,
                    "type": "outbound_cid",
                })

        # 3. Fetch recent call detail records for this number
        recent_calls = await self._fetch_cdrs(phone_number, connection)

        return ProviderResult(
            status="ok",
            data={
                "inbound_routes": matching_routes,
                "extensions_using": extensions_using,
                "recent_calls": recent_calls,
            },
        )

    async def _query_extension_inner(self, extension: str, connection: m.Connection) -> ProviderResult:
        """Core implementation for extension queries."""
        # 1. Fetch the extension details
        ext_query = _GQL_EXTENSION.format(ext=extension)
        ext_resp = await self._execute_graphql(ext_query, connection)
        ext_data = ext_resp.get("data", {}).get("fetchExtension", {})

        ext_status = ext_data.get("status", "")
        if ext_status and str(ext_status).lower() not in ("true", "ok", "success", "1"):
            # Extension not found or query error
            ext_msg = ext_data.get("message", "Extension not found")
            if "not found" in str(ext_msg).lower() or "does not exist" in str(ext_msg).lower():
                return ProviderResult(
                    status="ok",
                    data={
                        "extension": None,
                        "device": None,
                        "follow_me": None,
                        "ring_groups": [],
                    },
                )

        user_data = ext_data.get("user") or {}
        device_data = ext_data.get("coreDevice") or {}

        no_answer_dest = user_data.get("noanswerDestination", "") or ""
        busy_dest = user_data.get("busyDestination", "") or ""
        chanunavail_dest = user_data.get("chanunavailDestination", "") or ""

        extension_info: dict[str, Any] = {
            "extension_id": ext_data.get("extensionId", extension),
            "name": user_data.get("name", ""),
            "outbound_cid": user_data.get("outboundCid", ""),
            "sip_name": user_data.get("sipname", ""),
            "voicemail_enabled": _to_bool(user_data.get("voicemail")),
            "ring_timer": _to_int(user_data.get("ringtimer")),
            "call_waiting": _to_bool(user_data.get("callwaiting")),
            "do_not_disturb": _to_bool(user_data.get("donotdisturb")),
            "music_on_hold_class": user_data.get("mohclass", ""),
            "no_answer_cid": user_data.get("noanswerCid", ""),
            "no_answer_destination": no_answer_dest,
            "no_answer_destination_label": parse_destination(no_answer_dest)["label"] if no_answer_dest else None,
            "busy_cid": user_data.get("busyCid", ""),
            "busy_destination": busy_dest,
            "busy_destination_label": parse_destination(busy_dest)["label"] if busy_dest else None,
            "chanunavail_cid": user_data.get("chanunavailCid", ""),
            "chanunavail_destination": chanunavail_dest,
            "chanunavail_destination_label": parse_destination(chanunavail_dest)["label"] if chanunavail_dest else None,
            "call_forward": {
                "unconditional": user_data.get("callforward_unconditional", ""),
                "busy": user_data.get("callforward_busy", ""),
            },
            "recording": {
                "policy": user_data.get("recording", ""),
                "inbound_external": user_data.get("recording_in_external", ""),
                "outbound_external": user_data.get("recording_out_external", ""),
                "inbound_internal": user_data.get("recording_in_internal", ""),
                "outbound_internal": user_data.get("recording_out_internal", ""),
                "on_demand": user_data.get("recording_ondemand", ""),
                "priority": _to_int(user_data.get("recording_priority")),
            },
        }

        device_info: dict[str, Any] | None = None
        if device_data.get("deviceId"):
            device_info = {
                "device_id": device_data.get("deviceId", ""),
                "tech": device_data.get("tech", ""),
                "dial": device_data.get("dial", ""),
                "device_type": device_data.get("devicetype", ""),
                "description": device_data.get("description", ""),
                "emergency_cid": device_data.get("emergencyCid", ""),
            }

        # 2. Fetch Follow Me configuration
        follow_me_info = await self._fetch_follow_me(extension, connection)

        # 3. Fetch ring groups containing this extension
        ring_groups = await self._fetch_ring_groups_for_extension(extension, connection)

        # 4. Fetch voicemail configuration
        voicemail_info = await self._fetch_voicemail(extension, connection)

        # 5. Fetch recent call detail records
        recent_calls = await self._fetch_cdrs(extension, connection)

        return ProviderResult(
            status="ok",
            data={
                "extension": extension_info,
                "device": device_info,
                "follow_me": follow_me_info,
                "ring_groups": ring_groups,
                "voicemail": voicemail_info,
                "recent_calls": recent_calls,
            },
        )

    async def _query_device_inner(self, mac_address: str, connection: m.Connection) -> ProviderResult:
        """Core implementation for device queries.

        FreePBX GraphQL has limited device support -- the
        ``fetchAllCoreDevice`` query returns minimal data.  We also
        cross-reference with all extensions to try to find the associated
        extension by matching device descriptions or IDs against the
        normalized MAC.
        """
        normalized_mac = mac_address.replace(":", "").replace("-", "").replace(".", "").lower()

        # Fetch core devices
        devices_resp = await self._execute_graphql(_GQL_ALL_CORE_DEVICES, connection)
        devices_data = devices_resp.get("data", {}).get("fetchAllCoreDevices", {})

        all_devices: list[dict[str, Any]] = devices_data.get("coreDevice", []) or []

        # Search core devices for a MAC match in description or device ID
        matched_device: dict[str, Any] | None = None
        associated_extension: dict[str, Any] | None = None

        for device in all_devices:
            description = (device.get("description", "") or "").lower()
            device_id = (device.get("deviceId", "") or "").lower()

            description_normalized = re.sub(r"[^a-f0-9]", "", description)
            device_id_normalized = re.sub(r"[^a-f0-9]", "", device_id)

            if normalized_mac and (
                normalized_mac in description_normalized
                or normalized_mac in device_id_normalized
            ):
                user = device.get("user") or {}
                matched_device = {
                    "device_id": device.get("deviceId", ""),
                    "tech": device.get("tech", ""),
                    "dial": device.get("dial", ""),
                    "device_type": device.get("devicetype", ""),
                    "description": device.get("description", ""),
                    "emergency_cid": device.get("emergencyCid", ""),
                }
                associated_extension = {
                    "extension_id": user.get("extension", ""),
                    "name": user.get("name", ""),
                }
                break

        # If not found in core devices, also search extensions
        if not matched_device:
            ext_resp = await self._execute_graphql(_GQL_ALL_EXTENSIONS, connection)
            ext_data = ext_resp.get("data", {}).get("fetchAllExtensions", {})
            all_extensions: list[dict[str, Any]] = ext_data.get("extension", []) or []

            for ext in all_extensions:
                core_device = ext.get("coreDevice") or {}
                description = (core_device.get("description", "") or "").lower()
                device_id = (core_device.get("deviceId", "") or "").lower()

                description_normalized = re.sub(r"[^a-f0-9]", "", description)
                device_id_normalized = re.sub(r"[^a-f0-9]", "", device_id)

                if normalized_mac and (
                    normalized_mac in description_normalized
                    or normalized_mac in device_id_normalized
                ):
                    user = ext.get("user") or {}
                    matched_device = {
                        "device_id": core_device.get("deviceId", ""),
                        "tech": core_device.get("tech", ""),
                        "dial": core_device.get("dial", ""),
                        "device_type": core_device.get("devicetype", ""),
                        "description": core_device.get("description", ""),
                        "emergency_cid": core_device.get("emergencyCid", ""),
                    }
                    associated_extension = {
                        "extension_id": ext.get("extensionId", ""),
                        "name": user.get("name", ""),
                    }
                    break

        return ProviderResult(
            status="ok",
            data={
                "device": matched_device,
                "associated_extension": associated_extension,
                "total_devices": devices_data.get("totalCount", 0),
            },
        )

    # -- Helpers -----------------------------------------------------------

    async def _fetch_follow_me(self, extension: str, connection: m.Connection) -> dict[str, Any] | None:
        """Fetch the Follow Me configuration for an extension.

        Returns ``None`` if Follow Me is not configured or the query
        fails.
        """
        try:
            fm_query = _GQL_FOLLOW_ME.format(ext=extension)
            fm_resp = await self._execute_graphql(fm_query, connection)
            fm_data = fm_resp.get("data", {}).get("fetchFollowMe", {})

            # If the status indicates not found / not configured, return None
            fm_status = fm_data.get("status", "")
            if fm_status and str(fm_status).lower() not in ("true", "ok", "success", "1"):
                return None

            enabled = _to_bool(fm_data.get("enabled"))
            if not enabled and not fm_data.get("followMeList"):
                return None

            follow_me_list_raw = fm_data.get("followMeList", "")
            follow_me_list = _parse_hyphen_list(follow_me_list_raw) if isinstance(follow_me_list_raw, str) else follow_me_list_raw

            no_answer_dest_raw = fm_data.get("noAnswerDestination", "")
            no_answer_parsed = parse_destination(no_answer_dest_raw) if no_answer_dest_raw else None

            return {
                "enabled": enabled,
                "strategy": fm_data.get("strategy", ""),
                "ring_time": _to_int(fm_data.get("ringTime")),
                "follow_me_list": follow_me_list or [],
                "initial_ring_time": _to_int(fm_data.get("initialRingTime")),
                "confirm_calls": _to_bool(fm_data.get("confirmCalls")),
                "no_answer_destination": no_answer_dest_raw,
                "no_answer_destination_label": no_answer_parsed["label"] if no_answer_parsed else None,
            }
        except Exception:  # noqa: BLE001
            await logger.adebug("freepbx_follow_me_query_failed", extension=extension)
            return None

    async def _fetch_ring_groups_for_extension(
        self,
        extension: str,
        connection: m.Connection,
    ) -> list[dict[str, Any]]:
        """Fetch all ring groups and filter for those containing *extension*."""
        try:
            rg_resp = await self._execute_graphql(_GQL_ALL_RING_GROUPS, connection)
            rg_data = rg_resp.get("data", {}).get("fetchAllRingGroups", {})
            all_groups: list[dict[str, Any]] = rg_data.get("ringgroups", []) or []

            matching: list[dict[str, Any]] = []
            for group in all_groups:
                group_list_raw = group.get("groupList", "")
                members = _parse_hyphen_list(group_list_raw) if isinstance(group_list_raw, str) else (group_list_raw or [])

                # Check if the extension is a member (strip any suffix like # for external numbers)
                member_ids = [re.sub(r"[#*]$", "", m_item) for m_item in members]
                if extension in member_ids:
                    matching.append({
                        "group_number": group.get("groupNumber", ""),
                        "description": group.get("description", ""),
                        "strategy": group.get("strategy", ""),
                        "ring_time": _to_int(group.get("groupTime")),
                        "member_extensions": members,
                    })

            return matching
        except Exception:  # noqa: BLE001
            await logger.adebug("freepbx_ring_groups_query_failed", extension=extension)
            return []

    async def _fetch_voicemail(self, extension: str, connection: m.Connection) -> dict[str, Any] | None:
        """Fetch voicemail configuration for an extension.

        Queries all voicemail boxes and returns the one matching
        *extension*, or ``None`` if not found or the query fails.
        """
        try:
            vm_resp = await self._execute_graphql(_GQL_VOICEMAIL, connection)
            vm_data = vm_resp.get("data", {}).get("fetchVoiceMail", {})

            vm_status = vm_data.get("status", "")
            if vm_status and str(vm_status).lower() not in ("true", "ok", "success", "1"):
                return None

            all_boxes: list[dict[str, Any]] = vm_data.get("voicemail", []) or []

            for box in all_boxes:
                if str(box.get("mailbox", "")) == str(extension):
                    return {
                        "enabled": True,
                        "email": box.get("email") or None,
                        "pager": box.get("pager") or None,
                        "mailbox": box.get("mailbox", ""),
                    }

            return None
        except Exception:  # noqa: BLE001
            await logger.adebug("freepbx_voicemail_query_failed", extension=extension)
            return None

    async def _fetch_cdrs(
        self,
        identifier: str,
        connection: m.Connection,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Fetch recent call detail records matching *identifier*.

        Queries all CDRs and filters for records where the source or
        destination matches the given phone number or extension.

        Args:
            identifier: A phone number or extension to filter by.
            connection: The connection to query against.
            limit: Maximum number of records to return.

        Returns:
            A list of CDR dicts, or an empty list on failure.
        """
        try:
            cdr_resp = await self._execute_graphql(_GQL_ALL_CDRS, connection)
            cdr_data = cdr_resp.get("data", {}).get("fetchAllCdrs", {})

            cdr_status = cdr_data.get("status", "")
            if cdr_status and str(cdr_status).lower() not in ("true", "ok", "success", "1"):
                return []

            all_cdrs: list[dict[str, Any]] = cdr_data.get("cdr", []) or []

            normalized = re.sub(r"[^\d]", "", identifier)
            results: list[dict[str, Any]] = []

            for record in all_cdrs:
                src = str(record.get("src", ""))
                dst = str(record.get("dst", ""))
                src_digits = re.sub(r"[^\d]", "", src)
                dst_digits = re.sub(r"[^\d]", "", dst)

                if (
                    src == identifier
                    or dst == identifier
                    or (normalized and (src_digits == normalized or dst_digits == normalized))
                ):
                    results.append({
                        "date": record.get("calldate", ""),
                        "source": src,
                        "destination": dst,
                        "duration": _to_int(record.get("duration")),
                        "disposition": record.get("disposition", ""),
                        "channel": record.get("channel", ""),
                        "uniqueId": record.get("uniqueid", ""),
                    })

                    if len(results) >= limit:
                        break

            return results
        except Exception:  # noqa: BLE001
            await logger.adebug("freepbx_cdr_query_failed", identifier=identifier)
            return []

    @staticmethod
    def _base_url(connection: m.Connection) -> str:
        """Build the base URL from connection host, port, and settings."""
        host = (connection.host or "").rstrip("/")
        settings = connection.settings or {}
        protocol = settings.get("protocol", "https")

        if not host.startswith(("http://", "https://")):
            host = f"{protocol}://{host}"

        port = connection.port
        if port:
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(host)
            default_port = 443 if parsed.scheme == "https" else 80
            if port != default_port:
                netloc_with_port = f"{parsed.hostname}:{port}"
                host = urlunparse(parsed._replace(netloc=netloc_with_port))

        return host

    def _invalidate_token(self, connection: m.Connection) -> None:
        """Remove a cached token so the next request forces re-auth."""
        _token_cache.pop(str(connection.id), None)


# ---------------------------------------------------------------------------
# Module-level utility helpers
# ---------------------------------------------------------------------------


def _parse_hyphen_list(value: str) -> list[str]:
    """Parse a hyphen-separated list into individual items.

    FreePBX ring group member lists and Follow Me lists use hyphens as
    delimiters (e.g. ``"100-101-102"`` or ``"100-5551239999#"``).

    Args:
        value: The raw hyphen-separated string.

    Returns:
        A list of individual member strings.
    """
    if not value or not value.strip():
        return []
    return [item.strip() for item in value.split("-") if item.strip()]


def _to_bool(value: Any) -> bool:
    """Coerce a FreePBX API value to a Python bool.

    FreePBX returns booleans inconsistently -- sometimes as strings
    ``"yes"``/``"no"``, sometimes as ``"1"``/``"0"``, and sometimes as
    actual booleans.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "enabled", "on")
    return False


def _to_int(value: Any, default: int = 0) -> int:
    """Coerce a FreePBX API value to an int.

    Args:
        value: The raw value from the API.
        default: The fallback if coercion fails.

    Returns:
        The integer value.
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
