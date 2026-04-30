"""Gateway domain guards.

Gateway endpoints are read-only and require only an authenticated user.
No additional guards are needed at this time — authentication is handled
by the application-wide JWT guard.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
