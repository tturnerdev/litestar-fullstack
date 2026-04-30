# FEATURE-GATEWAY.md — External Data Gateway API

## Overview

The Gateway API provides a unified interface for querying external data sources (FreePBX, Telnyx, etc.) to enrich our internal entities with live, provider-side configuration details. Rather than syncing/caching external data into our database, the gateway proxies requests in real-time to the configured external systems and returns normalized, aggregated responses.

The gateway leverages the existing `Connection` model (`src/py/app/db/models/_connection.py`) which already supports PBX, Carrier, and Helpdesk connection types with configurable auth (OAuth2, API key, token, basic).

---

## API Endpoints

### Numbers Gateway

```
GET /api/gateway/numbers/{phone_number}
```

**Path parameter:** `phone_number` — E.164 digits without `+` (e.g., `15551234567`)

**Response:** Aggregated data from all configured sources for this phone number.

```json
{
  "phone_number": "15551234567",
  "sources": {
    "freepbx": {
      "connection_id": "uuid",
      "connection_name": "Office PBX",
      "status": "ok",
      "data": {
        "inbound_routes": [
          {
            "description": "Main Line",
            "did": "15551234567",
            "cid_pattern": "",
            "destination": "ext-group,600,1",
            "destination_label": "Ring Group: Sales Team (600)",
            "privacy_manager": false,
            "alert_info": null
          }
        ],
        "extensions_using": [
          {
            "extension_id": "100",
            "name": "John Smith",
            "outbound_cid": "\"John Smith\" <15551234567>",
            "type": "outbound_cid"
          }
        ]
      }
    },
    "telnyx": {
      "connection_id": "uuid",
      "connection_name": "Telnyx Account",
      "status": "ok",
      "data": {
        "phone_number": "+15551234567",
        "status": "active",
        "connection_name": "My SIP Connection",
        "e911": {
          "registered": true,
          "address": "123 Main St, Springfield, IL 62701"
        },
        "cnam": {
          "enabled": true,
          "caller_id_name": "ACME CORP"
        },
        "messaging_profile": null,
        "tags": ["main-line", "sales"]
      }
    }
  },
  "internal": {
    "phone_number_id": "uuid-or-null",
    "assigned_to_extension": "100",
    "assigned_to_user": "John Smith"
  }
}
```

### Extensions Gateway

```
GET /api/gateway/extensions/{extension_number}
```

**Path parameter:** `extension_number` — Extension number (e.g., `1001`)

**Response:** Aggregated extension data from all configured sources.

```json
{
  "extension_number": "1001",
  "sources": {
    "freepbx": {
      "connection_id": "uuid",
      "connection_name": "Office PBX",
      "status": "ok",
      "data": {
        "extension": {
          "extension_id": "1001",
          "name": "Jane Doe",
          "outbound_cid": "\"Jane Doe\" <15551234567>",
          "voicemail_enabled": true,
          "ring_timer": 15,
          "no_answer_destination": "app-voicemail,1001,1"
        },
        "device": {
          "device_id": "1001",
          "tech": "pjsip",
          "dial": "PJSIP/1001",
          "device_type": "fixed",
          "description": "Jane's Desk Phone",
          "emergency_cid": "15551234567"
        },
        "follow_me": {
          "enabled": true,
          "strategy": "ringallv2",
          "ring_time": 25,
          "follow_me_list": ["1001", "1002", "5551239999#"],
          "initial_ring_time": 7,
          "confirm_calls": false,
          "no_answer_destination": "app-voicemail,1001,1"
        },
        "ring_groups": [
          {
            "group_number": "600",
            "description": "Sales Team",
            "strategy": "ringall",
            "ring_time": 20,
            "member_extensions": ["1001", "1002", "1003"]
          }
        ],
        "voicemail": {
          "enabled": true,
          "email": "jane@example.com"
        }
      }
    }
  },
  "internal": {
    "extension_id": "uuid-or-null",
    "user_id": "uuid-or-null",
    "user_name": "Jane Doe"
  }
}
```

### Devices Gateway

```
GET /api/gateway/devices/{mac_address}
```

**Path parameter:** `mac_address` — MAC address with colons (e.g., `00:1A:2B:3C:4D:5E`)

**Response:** Aggregated device data from all configured sources.

```json
{
  "mac_address": "00:1A:2B:3C:4D:5E",
  "sources": {
    "freepbx": {
      "connection_id": "uuid",
      "connection_name": "Office PBX",
      "status": "ok",
      "data": {
        "device": {
          "device_id": "1001",
          "tech": "pjsip",
          "dial": "PJSIP/1001",
          "device_type": "fixed",
          "description": "Jane's Desk Phone",
          "caller_id": "\"Jane Doe\" <15551234567>"
        },
        "associated_extension": {
          "extension_id": "1001",
          "name": "Jane Doe"
        }
      }
    }
  },
  "internal": {
    "device_id": "uuid-or-null",
    "device_name": "Jane's Desk Phone",
    "user_id": "uuid-or-null",
    "status": "online"
  }
}
```

---

## Architecture

### Domain Structure

```
src/py/app/domain/gateway/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   ├── _numbers.py          # GET /api/gateway/numbers/{phone_number}
│   ├── _extensions.py       # GET /api/gateway/extensions/{extension_number}
│   └── _devices.py          # GET /api/gateway/devices/{mac_address}
├── services/
│   ├── __init__.py
│   ├── _gateway.py           # GatewayService — orchestrates provider queries
│   ├── _number_gateway.py    # NumberGatewayService — number-specific aggregation
│   ├── _extension_gateway.py # ExtensionGatewayService — extension-specific aggregation
│   └── _device_gateway.py    # DeviceGatewayService — device-specific aggregation
├── schemas/
│   ├── __init__.py
│   ├── _numbers.py           # NumberGatewayResponse, etc.
│   ├── _extensions.py        # ExtensionGatewayResponse, etc.
│   ├── _devices.py           # DeviceGatewayResponse, etc.
│   └── _common.py            # SourceResult, SourceStatus, etc.
├── providers/
│   ├── __init__.py
│   ├── _base.py              # Abstract GatewayProvider base class
│   ├── _freepbx.py           # FreePBXProvider — GraphQL client
│   └── _telnyx.py            # TelnyxProvider — REST client
├── deps.py
└── guards.py
```

### Provider Pattern

Each external data source is implemented as a provider class inheriting from `GatewayProvider`. Providers are stateless — they receive connection credentials at query time and return normalized data.

```python
class GatewayProvider(ABC):
    """Base class for external data source providers."""

    provider_name: ClassVar[str]
    supported_domains: ClassVar[set[str]]  # {"numbers", "extensions", "devices"}

    @abstractmethod
    async def query_number(self, phone_number: str, connection: Connection) -> ProviderNumberResult: ...

    @abstractmethod
    async def query_extension(self, extension: str, connection: Connection) -> ProviderExtensionResult: ...

    @abstractmethod
    async def query_device(self, mac_address: str, connection: Connection) -> ProviderDeviceResult: ...
```

### Provider Registry

Providers are registered by name and matched to connections via `Connection.provider` field:

```python
PROVIDER_REGISTRY: dict[str, type[GatewayProvider]] = {
    "freepbx": FreePBXProvider,
    "telnyx": TelnyxProvider,
}
```

### Gateway Service Flow

1. Controller receives request (e.g., `GET /api/gateway/numbers/15551234567`)
2. GatewayService loads all enabled `Connection` records for the current user's team(s)
3. For each connection, looks up the matching provider from the registry
4. Calls the provider's query method concurrently via `asyncio.gather()`
5. Also queries internal database for matching entity data
6. Returns aggregated response with per-source status

---

## External Provider Details

### FreePBX Provider

**Auth:** OAuth2 Client Credentials flow
- Token endpoint: `https://{host}/admin/api/api/token`
- GraphQL endpoint: `https://{host}/admin/api/api/gql`
- Scopes needed: `gql:core`, `gql:ringgroup`, `gql:findmefollow`, `gql:cdr`
- Token TTL: 3600s — cache tokens per-connection

**Connection.credentials schema:**
```json
{
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["gql:core", "gql:ringgroup", "gql:findmefollow"]
}
```

**Connection.settings schema:**
```json
{
  "verify_ssl": true,
  "timeout": 10
}
```

#### Number Queries (FreePBX)

To resolve where a phone number routes, the provider:

1. **fetchAllInboundRoutes** — find routes where `extension` (DID field) matches the phone number
2. For each matching route, parse the `destination` field (Asterisk dialplan format: `context,exten,priority`) to determine target:
   - `from-did-direct,{ext},1` → Direct to extension
   - `ext-group,{group},1` → Ring Group
   - `ivr-{id},s,1` → IVR Menu
   - `ext-queues,{queue},1` → Call Queue
   - `app-blackhole,{type},1` → Terminated/Blackhole
   - `timeconditions,{id},1` → Time Condition
3. **fetchAllExtensions** — find extensions using this number as `outboundCid`

#### Extension Queries (FreePBX)

1. **fetchExtension(extensionId)** — core extension data + SIP device
2. **fetchFollowMe(extensionId)** — Follow Me/Find Me configuration
3. **fetchAllRingGroups** — filter for groups where `groupList` contains this extension
4. **fetchVoiceMail** — voicemail configuration for the extension

#### Device Queries (FreePBX)

FreePBX's EndPoint Manager GraphQL is limited to global settings (no per-device queries). Device lookup by MAC is not directly available via GraphQL. The provider should:

1. **fetchAllCoreDevice** — search results by matching description or device fields
2. Cross-reference with extension data to find the associated extension

### Telnyx Provider

**Auth:** API Key (Bearer token)
- Base URL: `https://api.telnyx.com/v2`
- Header: `Authorization: Bearer {api_key}`

**Connection.credentials schema:**
```json
{
  "api_key": "KEY_..."
}
```

#### Number Queries (Telnyx)

1. `GET /v2/phone_numbers?filter[phone_number]={e164_number}` — number details, status, connection
2. `GET /v2/phone_numbers/{id}/messaging` — messaging profile info
3. Number resource includes: `status`, `connection_name`, `connection_id`, `tags`, `purchased_at`, `billing_group_id`
4. E911: `GET /v2/phone_numbers/{id}/regulatory_requirements` or embedded in number resource
5. CNAM: Check via number features / CNAM listing status

#### Extension/Device Queries (Telnyx)

Telnyx is a carrier — it does not manage extensions or devices. These methods return empty results for Telnyx connections.

---

## Connection Setup Integration

The existing `Connection` model and `connections` domain handle CRUD for external data sources. The gateway feature adds:

1. **Provider validation** — When creating/updating a Connection, validate that `provider` matches a registered gateway provider name
2. **Connection test enhancement** — `ConnectionService.test_connection()` delegates to the provider's health check (e.g., FreePBX: attempt token exchange; Telnyx: `GET /v2/phone_numbers?page[size]=1`)
3. **Credential encryption** — The `credentials` JSONB column stores sensitive data; consider encrypting at the application level (AES-GCM with a `GATEWAY_ENCRYPTION_KEY` env var)

---

## Caching Strategy

External API calls can be slow and rate-limited. Use Redis for response caching:

- **Cache key format:** `gateway:{provider}:{domain}:{identifier}:{connection_id}`
- **Default TTL:** 300s (5 minutes) — configurable per connection via `settings.cache_ttl`
- **Cache bypass:** `?refresh=true` query parameter forces a fresh fetch
- **Invalidation:** No active invalidation — TTL-based expiry only

---

## Settings

Add to `AppSettings` in `src/py/app/lib/settings.py`:

```python
GATEWAY_DEFAULT_TIMEOUT: int = 10          # seconds per provider request
GATEWAY_DEFAULT_CACHE_TTL: int = 300       # seconds
GATEWAY_ENCRYPTION_KEY: str | None = None  # for credential encryption
```

---

## Error Handling

Each source in the response includes its own status. A failure in one provider does not fail the whole request:

```json
{
  "connection_id": "uuid",
  "connection_name": "Broken PBX",
  "status": "error",
  "error": "Connection timed out after 10s",
  "data": null
}
```

Status values: `"ok"`, `"error"`, `"timeout"`, `"auth_failed"`, `"not_supported"`

---

## Implementation Plan

### Phase 1 — Foundation (Batch 1)

**1a. Gateway domain scaffolding + provider base**
- Create `src/py/app/domain/gateway/` directory structure
- Implement `GatewayProvider` abstract base class
- Implement provider registry
- Create common schemas (`SourceResult`, `SourceStatus`, gateway response wrappers)
- Create `GatewayService` orchestrator that loads connections and dispatches to providers
- Create `deps.py` and `guards.py`

**1b. FreePBX provider — auth + core queries**
- Implement `FreePBXProvider` class with OAuth2 token management
- Implement `_execute_graphql()` helper with error handling
- Implement number queries: `fetchAllInboundRoutes`, destination parsing
- Implement extension queries: `fetchExtension`, `fetchCoreDevice`
- Implement Asterisk destination format parser (`from-did-direct,100,1` → human label)

**1c. Gateway controllers**
- `NumbersGatewayController` — `GET /api/gateway/numbers/{phone_number}`
- `ExtensionsGatewayController` — `GET /api/gateway/extensions/{extension_number}`
- `DevicesGatewayController` — `GET /api/gateway/devices/{mac_address}`
- Response schema serialization
- Internal entity cross-referencing (look up matching records in our DB)

### Phase 2 — Extended Queries (Batch 2)

**2a. FreePBX provider — ring groups, follow me, voicemail**
- `fetchAllRingGroups` — find groups containing an extension
- `fetchFollowMe(extensionId)` — follow me configuration
- `fetchVoiceMail` — voicemail status
- `fetchAllCdrs` — recent call history for a number/extension

**2b. Telnyx provider**
- Implement `TelnyxProvider` with API key auth
- Number lookup: status, connection, E911, CNAM, tags
- Proper E.164 formatting

**2c. Caching layer**
- Redis-based response caching
- Per-connection TTL configuration
- `?refresh=true` cache bypass
- Cache key management

### Phase 3 — Frontend + Polish (Batch 3)

**3a. Frontend gateway data panels**
- "External Data" tab/section on phone number detail pages
- "PBX Configuration" tab on extension detail pages
- "Provisioning" tab on device detail pages
- Loading states, error states per source
- Refresh button per source

**3b. Connection test enhancement**
- Wire `ConnectionService.test_connection()` to actual provider health checks
- Show connection health in admin UI

**3c. Gateway settings in admin**
- Default timeout and cache TTL configuration
- Per-connection cache TTL override in connection edit form

---

## FreePBX GraphQL Reference (Key Queries)

### Authentication

```
POST https://{host}/admin/api/api/token
Authorization: Basic {base64(client_id:client_secret)}
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=gql:core gql:ringgroup gql:findmefollow
```

### Core Queries

```graphql
# All extensions
query { fetchAllExtensions {
  status message totalCount
  extension { id extensionId
    user { name outboundCid voicemail ringtimer noanswer noanswerDestination }
    coreDevice { deviceId dial devicetype description emergencyCid tech }
  }
}}

# Single extension
query { fetchExtension(extensionId: "1001") {
  status message extensionId
  user { name outboundCid voicemail ringtimer noanswer noanswerDestination noanswerCid busyCid }
  coreDevice { deviceId dial devicetype description emergencyCid tech callerId sipdriver }
}}

# Inbound routes
query { fetchAllInboundRoutes {
  status message
  # returns route objects with extension (DID), cidnum, destination, description
}}

# Core devices
query { fetchAllCoreDevice {
  status message
  # returns device objects with id, tech, dial, devicetype, description
}}
```

### Ring Group Queries

```graphql
query { fetchAllRingGroups {
  status totalCount message
  ringgroups { groupNumber description groupTime groupList strategy groupPrefix }
}}

query { fetchRingGroup(groupNumber: "600") {
  status message
  groupNumber description groupList strategy groupTime
}}
```

### Follow Me Queries

```graphql
query { fetchFollowMe(extensionId: "1001") {
  status message enabled extensionId strategy ringTime
  followMeList initialRingTime confirmCalls noAnswerDestination
}}
```

### Destination Format Reference

FreePBX routes use Asterisk dialplan format: `context,extension,priority`

| Destination Pattern | Target Type | Example |
|---|---|---|
| `from-did-direct,{ext},1` | Extension | `from-did-direct,100,1` |
| `ext-group,{group},1` | Ring Group | `ext-group,600,1` |
| `ivr-{id},s,1` | IVR Menu | `ivr-3,s,1` |
| `ext-queues,{queue},1` | Call Queue | `ext-queues,400,1` |
| `app-blackhole,{type},1` | Terminate | `app-blackhole,hangup,1` |
| `timeconditions,{id},1` | Time Condition | `timeconditions,1,1` |
| `ext-meetme,{room},1` | Conference | `ext-meetme,800,1` |
| `app-announcement,{id},1` | Announcement | `app-announcement,1,1` |
| `app-misclookup,{id},1` | Misc Destination | `app-misclookup,1,1` |
| `ext-local,vmb{ext},1` | Voicemail (busy) | `ext-local,vmb100,1` |
| `ext-local,vmu{ext},1` | Voicemail (unavail) | `ext-local,vmu100,1` |

### Important API Notes

1. **Boolean bug in addInboundRoute:** All boolean fields (`privacyman`, `ringing`, `pricid`, `reversal`, `fanswer`) must be included explicitly even when not needed.
2. **After mutations, call `doreload`:** `mutation { doreload(input: {}) { message status } }`
3. **Token lifetime:** 3600 seconds. Cache and refresh proactively.
4. **EndPoint Manager GraphQL** is limited to global settings — no per-device CRUD.
5. **Schema introspection** is available: `query { __schema { types { name } } }`
