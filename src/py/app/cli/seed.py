"""Database seed command for development data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import anyio
import click
from advanced_alchemy.utils.text import slugify
from rich import get_console
from rich.table import Table
from sqlalchemy import delete, select

from app.config import alchemy
from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.lib.deps import provide_services


@click.command(name="seed", help="Seed the database with realistic development data.")
@click.option("--reset", is_flag=True, default=False, help="Delete existing seed data before seeding.")
def seed_database(reset: bool) -> None:
    """Seed the database with sample development data."""
    console = get_console()
    console.rule("[bold blue]Database Seed[/bold blue]")

    async def _seed() -> None:
        async with alchemy.get_session() as session:
            seeder = DatabaseSeeder(session, console)
            if reset:
                await seeder.reset()
            await seeder.run()

    anyio.run(_seed)


class DatabaseSeeder:
    """Seeds the database with realistic development data.

    Creates data in FK-safe order and is idempotent (skips existing records).
    """

    def __init__(self, session: Any, console: Any) -> None:
        self.session = session
        self.console = console
        # Collected IDs for cross-references
        self.org_id: UUID | None = None
        self.team_id: UUID | None = None
        self.user_ids: dict[str, UUID] = {}
        self.location_ids: dict[str, UUID] = {}
        self.extension_ids: dict[str, UUID] = {}
        self.phone_number_ids: dict[str, UUID] = {}
        self.tag_ids: dict[str, UUID] = {}

    # ------------------------------------------------------------------
    # Top-level orchestration
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run all seed steps in FK-safe order."""
        await self._seed_roles()
        await self._seed_organization()
        await self._seed_team()
        await self._seed_users()
        await self._seed_team_members()
        await self._seed_tags()
        await self._seed_locations()
        await self._seed_phone_numbers()
        await self._seed_extensions()
        await self._seed_devices()
        await self._seed_fax_numbers()
        await self._seed_tickets()
        await self._seed_connections()
        await self._seed_notifications()
        await self._seed_e911_registrations()

        await self.session.commit()
        self._print_summary()

    async def reset(self) -> None:
        """Remove previously seeded data (in reverse FK order)."""
        self.console.print("[yellow]Resetting seed data...[/yellow]")
        # Delete in reverse dependency order — cascades handle children
        for model in [
            m.Notification,
            m.E911Registration,
            m.Connection,
            m.TicketMessage,
            m.Ticket,
            m.FaxEmailRoute,
            m.FaxNumber,
            m.DeviceLineAssignment,
            m.Device,
            m.VoicemailBox,
            m.Extension,
            m.PhoneNumber,
            m.Location,
            m.TeamMember,
            m.Tag,
            m.Organization,
        ]:
            await self.session.execute(delete(model))
        # Only delete seed users (by known emails), not all users
        for email in _USERS:
            await self.session.execute(delete(m.User).where(m.User.email == email))
        await self.session.commit()
        self.console.print("[green]  Reset complete.[/green]")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _status(self, label: str, action: str) -> None:
        icon = "[green]+[/green]" if action == "created" else "[dim]-[/dim]"
        self.console.print(f"  {icon} {label} {action}")

    async def _get_or_create(
        self,
        model: type,
        lookup: dict[str, Any],
        defaults: dict[str, Any] | None = None,
    ) -> tuple[Any, bool]:
        """Return (instance, created) — idempotent insert."""
        stmt = select(model)
        for k, v in lookup.items():
            stmt = stmt.where(getattr(model, k) == v)
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing, False
        obj = model(**{**lookup, **(defaults or {})})
        self.session.add(obj)
        await self.session.flush()
        return obj, True

    # ------------------------------------------------------------------
    # Seed steps
    # ------------------------------------------------------------------

    async def _seed_roles(self) -> None:
        """Ensure default roles exist (mirrors load_database_fixtures)."""
        self.console.print("[bold]Roles[/bold]")
        for role_data in _ROLES:
            role, created = await self._get_or_create(
                m.Role,
                lookup={"slug": role_data["slug"]},
                defaults={"name": role_data["name"], "description": role_data["description"]},
            )
            self._status(role_data["name"], "created" if created else "exists")

    async def _seed_organization(self) -> None:
        self.console.print("[bold]Organization[/bold]")
        org, created = await self._get_or_create(
            m.Organization,
            lookup={"slug": "acme-corp"},
            defaults={
                "name": "Acme Corp",
                "description": "A leading provider of innovative communication solutions.",
                "website": "https://acmecorp.example.com",
                "email": "info@acmecorp.example.com",
                "phone": "+15551000000",
                "address_line_1": "100 Innovation Drive",
                "address_line_2": "Suite 400",
                "city": "San Francisco",
                "state": "CA",
                "postal_code": "94105",
                "country": "US",
                "timezone": "America/Los_Angeles",
            },
        )
        self.org_id = org.id
        self._status("Acme Corp", "created" if created else "exists")

    async def _seed_team(self) -> None:
        self.console.print("[bold]Team[/bold]")
        team, created = await self._get_or_create(
            m.Team,
            lookup={"slug": "it-department"},
            defaults={
                "name": "IT Department",
                "description": "Internal IT and telecom administration team.",
                "is_active": True,
            },
        )
        self.team_id = team.id
        self._status("IT Department", "created" if created else "exists")

    async def _seed_users(self) -> None:
        """Create users via UserService so passwords are hashed properly."""
        self.console.print("[bold]Users[/bold]")

        async with provide_services(provide_users_service, session=self.session) as (users_service,):
            for email, data in _USERS.items():
                existing = await users_service.get_one_or_none(email=email)
                if existing is not None:
                    self.user_ids[email] = existing.id
                    self._status(f"{data['name']} <{email}>", "exists")
                    continue

                user = await users_service.create(
                    data={
                        "email": email,
                        "name": data["name"],
                        "password": data["password"],
                        "is_superuser": data.get("is_superuser", False),
                        "is_active": True,
                        "is_verified": True,
                    },
                )
                self.user_ids[email] = user.id
                self._status(f"{data['name']} <{email}>", "created")
            await self.session.flush()

    async def _seed_team_members(self) -> None:
        self.console.print("[bold]Team Members[/bold]")
        assert self.team_id is not None  # noqa: S101

        for email, data in _USERS.items():
            user_id = self.user_ids.get(email)
            if user_id is None:
                continue
            role = m.TeamRoles.ADMIN if data.get("is_superuser") else m.TeamRoles.MEMBER
            is_owner = data.get("is_superuser", False)
            member, created = await self._get_or_create(
                m.TeamMember,
                lookup={"user_id": user_id, "team_id": self.team_id},
                defaults={"role": role, "is_owner": is_owner},
            )
            self._status(f"{data['name']} -> IT Department ({role})", "created" if created else "exists")

    async def _seed_tags(self) -> None:
        self.console.print("[bold]Tags[/bold]")
        for tag_data in _TAGS:
            tag, created = await self._get_or_create(
                m.Tag,
                lookup={"slug": slugify(tag_data["name"])},
                defaults={"name": tag_data["name"], "description": tag_data.get("description")},
            )
            self.tag_ids[tag_data["name"]] = tag.id
            self._status(tag_data["name"], "created" if created else "exists")

    async def _seed_locations(self) -> None:
        self.console.print("[bold]Locations[/bold]")
        assert self.team_id is not None  # noqa: S101

        for loc in _LOCATIONS:
            location, created = await self._get_or_create(
                m.Location,
                lookup={"name": loc["name"], "team_id": self.team_id},
                defaults={
                    "description": loc.get("description"),
                    "location_type": loc.get("location_type", m.LocationType.ADDRESSED),
                    "address_line_1": loc.get("address_line_1"),
                    "address_line_2": loc.get("address_line_2"),
                    "city": loc.get("city"),
                    "state": loc.get("state"),
                    "postal_code": loc.get("postal_code"),
                    "country": loc.get("country", "US"),
                },
            )
            self.location_ids[loc["name"]] = location.id
            self._status(loc["name"], "created" if created else "exists")

    async def _seed_phone_numbers(self) -> None:
        self.console.print("[bold]Phone Numbers[/bold]")

        for pn in _PHONE_NUMBERS:
            phone, created = await self._get_or_create(
                m.PhoneNumber,
                lookup={"number": pn["number"]},
                defaults={
                    "friendly_name": pn.get("friendly_name"),
                    "number_type": pn.get("number_type", "local"),
                    "capability": pn.get("capability", "voice"),
                    "status": "active",
                    "city": pn.get("city"),
                    "state": pn.get("state"),
                    "country": pn.get("country", "US"),
                    "provider": pn.get("provider", "telnyx"),
                    "team_id": self.team_id,
                },
            )
            self.phone_number_ids[pn["number"]] = phone.id
            self._status(f"{pn['number']} ({pn.get('friendly_name', '')})", "created" if created else "exists")

    async def _seed_extensions(self) -> None:
        self.console.print("[bold]Extensions[/bold]")
        admin_id = self.user_ids.get("admin@example.com")

        for ext in _EXTENSIONS:
            owner_email = ext.get("user_email", "admin@example.com")
            user_id = self.user_ids.get(owner_email, admin_id)
            phone_number_id = self.phone_number_ids.get(ext.get("phone_number"))

            extension, created = await self._get_or_create(
                m.Extension,
                lookup={"extension_number": ext["extension_number"]},
                defaults={
                    "user_id": user_id,
                    "display_name": ext["display_name"],
                    "phone_number_id": phone_number_id,
                    "is_active": True,
                },
            )
            self.extension_ids[ext["extension_number"]] = extension.id
            self._status(
                f"x{ext['extension_number']} - {ext['display_name']}",
                "created" if created else "exists",
            )

            # Create voicemail box if specified
            if ext.get("voicemail") and created:
                vm = ext["voicemail"]
                await self._get_or_create(
                    m.VoicemailBox,
                    lookup={"extension_id": extension.id},
                    defaults={
                        "is_enabled": vm.get("is_enabled", True),
                        "pin": vm.get("pin", "1234"),
                        "greeting_type": vm.get("greeting_type", m.GreetingType.DEFAULT),
                        "email_notification": vm.get("email_notification", True),
                        "email_address": vm.get("email_address", owner_email),
                        "max_message_length_seconds": vm.get("max_message_length_seconds", 120),
                        "transcription_enabled": vm.get("transcription_enabled", False),
                    },
                )

    async def _seed_devices(self) -> None:
        self.console.print("[bold]Devices[/bold]")
        admin_id = self.user_ids.get("admin@example.com")

        for dev in _DEVICES:
            owner_email = dev.get("user_email", "admin@example.com")
            user_id = self.user_ids.get(owner_email, admin_id)

            device, created = await self._get_or_create(
                m.Device,
                lookup={"mac_address": dev["mac_address"]},
                defaults={
                    "user_id": user_id,
                    "team_id": self.team_id,
                    "name": dev["name"],
                    "device_type": dev["device_type"],
                    "device_model": dev.get("device_model"),
                    "manufacturer": dev.get("manufacturer"),
                    "firmware_version": dev.get("firmware_version"),
                    "ip_address": dev.get("ip_address"),
                    "sip_username": dev["sip_username"],
                    "sip_server": dev.get("sip_server", "sip.acmecorp.example.com"),
                    "status": dev.get("status", m.DeviceStatus.ONLINE),
                    "is_active": True,
                    "last_seen_at": datetime.now(UTC),
                    "provisioned_at": datetime.now(UTC),
                },
            )
            self._status(f"{dev['name']} ({dev['mac_address']})", "created" if created else "exists")

            # Create line assignments
            if created and dev.get("lines"):
                for line in dev["lines"]:
                    ext_id = self.extension_ids.get(line.get("extension_number"))
                    await self._get_or_create(
                        m.DeviceLineAssignment,
                        lookup={"device_id": device.id, "line_number": line["line_number"]},
                        defaults={
                            "label": line["label"],
                            "line_type": line.get("line_type", m.DeviceLineType.PRIVATE),
                            "is_active": True,
                        },
                    )

    async def _seed_fax_numbers(self) -> None:
        self.console.print("[bold]Fax Numbers[/bold]")
        admin_id = self.user_ids.get("admin@example.com")

        for fax in _FAX_NUMBERS:
            owner_email = fax.get("user_email", "admin@example.com")
            user_id = self.user_ids.get(owner_email, admin_id)

            fax_number, created = await self._get_or_create(
                m.FaxNumber,
                lookup={"number": fax["number"]},
                defaults={
                    "user_id": user_id,
                    "team_id": self.team_id,
                    "label": fax.get("label"),
                    "is_active": True,
                },
            )
            self._status(f"{fax['number']} ({fax.get('label', '')})", "created" if created else "exists")

            # Create email routes
            if created and fax.get("email_routes"):
                for route in fax["email_routes"]:
                    await self._get_or_create(
                        m.FaxEmailRoute,
                        lookup={"fax_number_id": fax_number.id, "email_address": route["email_address"]},
                        defaults={
                            "is_active": True,
                            "notify_on_failure": route.get("notify_on_failure", True),
                        },
                    )

    async def _seed_tickets(self) -> None:
        self.console.print("[bold]Support Tickets[/bold]")
        admin_id = self.user_ids.get("admin@example.com")

        for idx, ticket_data in enumerate(_TICKETS, start=1):
            reporter_email = ticket_data.get("user_email", "admin@example.com")
            reporter_id = self.user_ids.get(reporter_email, admin_id)
            assignee_email = ticket_data.get("assigned_to_email")
            assignee_id = self.user_ids.get(assignee_email) if assignee_email else None

            ticket_number = ticket_data["ticket_number"]
            ticket, created = await self._get_or_create(
                m.Ticket,
                lookup={"ticket_number": ticket_number},
                defaults={
                    "user_id": reporter_id,
                    "assigned_to_id": assignee_id,
                    "team_id": self.team_id,
                    "subject": ticket_data["subject"],
                    "status": ticket_data.get("status", m.TicketStatus.OPEN),
                    "priority": ticket_data.get("priority", m.TicketPriority.MEDIUM),
                    "category": ticket_data.get("category"),
                    "closed_at": ticket_data.get("closed_at"),
                    "resolved_at": ticket_data.get("resolved_at"),
                },
            )
            self._status(f"{ticket_number}: {ticket_data['subject']}", "created" if created else "exists")

            # Create messages
            if created and ticket_data.get("messages"):
                for msg in ticket_data["messages"]:
                    author_email = msg.get("author_email", reporter_email)
                    author_id = self.user_ids.get(author_email, reporter_id)
                    await self._get_or_create(
                        m.TicketMessage,
                        lookup={"ticket_id": ticket.id, "body_markdown": msg["body"]},
                        defaults={
                            "author_id": author_id,
                            "body_html": f"<p>{msg['body']}</p>",
                            "is_internal_note": msg.get("is_internal_note", False),
                            "is_system_message": False,
                        },
                    )

    async def _seed_connections(self) -> None:
        self.console.print("[bold]Connections[/bold]")
        assert self.team_id is not None  # noqa: S101

        for conn in _CONNECTIONS:
            connection, created = await self._get_or_create(
                m.Connection,
                lookup={"name": conn["name"], "team_id": self.team_id},
                defaults={
                    "description": conn.get("description"),
                    "connection_type": conn["connection_type"],
                    "provider": conn["provider"],
                    "host": conn.get("host"),
                    "port": conn.get("port"),
                    "auth_type": conn.get("auth_type", m.ConnectionAuthType.API_KEY),
                    "credentials": conn.get("credentials"),
                    "settings": conn.get("settings"),
                    "status": conn.get("status", m.ConnectionStatus.CONNECTED),
                    "is_enabled": True,
                },
            )
            self._status(f"{conn['name']} ({conn['provider']})", "created" if created else "exists")

    async def _seed_notifications(self) -> None:
        self.console.print("[bold]Notifications[/bold]")
        admin_id = self.user_ids.get("admin@example.com")
        if admin_id is None:
            return

        for notif in _NOTIFICATIONS:
            notification, created = await self._get_or_create(
                m.Notification,
                lookup={"user_id": admin_id, "title": notif["title"]},
                defaults={
                    "message": notif["message"],
                    "category": notif["category"],
                    "is_read": notif.get("is_read", False),
                    "action_url": notif.get("action_url"),
                },
            )
            self._status(notif["title"], "created" if created else "exists")

    async def _seed_e911_registrations(self) -> None:
        self.console.print("[bold]E911 Registrations[/bold]")
        assert self.team_id is not None  # noqa: S101

        for reg in _E911_REGISTRATIONS:
            phone_number_id = self.phone_number_ids.get(reg["phone_number"])
            location_id = self.location_ids.get(reg.get("location_name", ""))

            e911, created = await self._get_or_create(
                m.E911Registration,
                lookup={"phone_number_id": phone_number_id},
                defaults={
                    "team_id": self.team_id,
                    "location_id": location_id,
                    "address_line_1": reg["address_line_1"],
                    "city": reg["city"],
                    "state": reg["state"],
                    "postal_code": reg["postal_code"],
                    "country": reg.get("country", "US"),
                    "validated": reg.get("validated", True),
                    "validated_at": datetime.now(UTC) if reg.get("validated", True) else None,
                },
            )
            self._status(
                f"{reg['phone_number']} -> {reg['address_line_1']}, {reg['city']}",
                "created" if created else "exists",
            )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _print_summary(self) -> None:
        self.console.print()
        self.console.rule("[bold green]Seed Complete[/bold green]")

        table = Table(title="Seeded Data Summary", show_lines=False)
        table.add_column("Entity", style="cyan")
        table.add_column("Count", justify="right", style="green")

        table.add_row("Organization", "1")
        table.add_row("Team", "1")
        table.add_row("Users", str(len(_USERS)))
        table.add_row("Locations", str(len(_LOCATIONS)))
        table.add_row("Phone Numbers", str(len(_PHONE_NUMBERS)))
        table.add_row("Extensions", str(len(_EXTENSIONS)))
        table.add_row("Devices", str(len(_DEVICES)))
        table.add_row("Fax Numbers", str(len(_FAX_NUMBERS)))
        table.add_row("Tickets", str(len(_TICKETS)))
        table.add_row("Tags", str(len(_TAGS)))
        table.add_row("Connections", str(len(_CONNECTIONS)))
        table.add_row("E911 Registrations", str(len(_E911_REGISTRATIONS)))
        table.add_row("Notifications", str(len(_NOTIFICATIONS)))

        self.console.print(table)
        self.console.print()
        self.console.print("[bold]Login credentials:[/bold]")
        self.console.print("  Email:    [cyan]admin@example.com[/cyan]")
        self.console.print(f"  Password: [cyan]{_SEED_PASSWORD}[/cyan]")
        self.console.print()


# =============================================================================
# Seed Data Definitions
# =============================================================================

_ROLES = [
    {"slug": "application-access", "name": "Application Access", "description": "Default role required for access."},
    {"slug": "superuser", "name": "Superuser", "description": "Allows superuser access to the application."},
]

_SEED_PASSWORD = "Test1234!@#$"
"""Default password for all seeded users. Meets strength requirements (12+ chars, upper, lower, digit, special)."""

_USERS: dict[str, dict[str, Any]] = {
    "admin@example.com": {
        "name": "Alice Admin",
        "password": _SEED_PASSWORD,
        "is_superuser": True,
    },
    "bob.manager@example.com": {
        "name": "Bob Manager",
        "password": _SEED_PASSWORD,
        "is_superuser": False,
    },
    "carol.tech@example.com": {
        "name": "Carol Technician",
        "password": _SEED_PASSWORD,
        "is_superuser": False,
    },
    "dave.support@example.com": {
        "name": "Dave Support",
        "password": _SEED_PASSWORD,
        "is_superuser": False,
    },
    "erin.user@example.com": {
        "name": "Erin User",
        "password": _SEED_PASSWORD,
        "is_superuser": False,
    },
}

_TAGS = [
    {"name": "VIP", "description": "High-priority VIP resources"},
    {"name": "Remote", "description": "Remote / off-site equipment"},
    {"name": "Conference Room", "description": "Conference room equipment"},
    {"name": "Lobby", "description": "Lobby and reception area devices"},
    {"name": "IT Closet", "description": "Server room and wiring closet equipment"},
    {"name": "Executive", "description": "Executive suite resources"},
]

_LOCATIONS = [
    {
        "name": "Main Office",
        "description": "Corporate headquarters at 100 Innovation Drive.",
        "location_type": m.LocationType.ADDRESSED,
        "address_line_1": "100 Innovation Drive",
        "address_line_2": "Suite 400",
        "city": "San Francisco",
        "state": "CA",
        "postal_code": "94105",
        "country": "US",
    },
    {
        "name": "Branch Office",
        "description": "East Bay satellite office for remote team members.",
        "location_type": m.LocationType.ADDRESSED,
        "address_line_1": "2500 Broadway",
        "city": "Oakland",
        "state": "CA",
        "postal_code": "94612",
        "country": "US",
    },
]

_PHONE_NUMBERS = [
    {
        "number": "+14155550100",
        "friendly_name": "Main Office Line",
        "number_type": "local",
        "capability": "voice",
        "city": "San Francisco",
        "state": "CA",
        "provider": "telnyx",
    },
    {
        "number": "+14155550101",
        "friendly_name": "Support Hotline",
        "number_type": "local",
        "capability": "voice",
        "city": "San Francisco",
        "state": "CA",
        "provider": "telnyx",
    },
    {
        "number": "+18005550200",
        "friendly_name": "Toll-Free Sales",
        "number_type": "toll_free",
        "capability": "voice",
        "city": None,
        "state": None,
        "provider": "telnyx",
    },
    {
        "number": "+15105550300",
        "friendly_name": "Branch Office Line",
        "number_type": "local",
        "capability": "voice",
        "city": "Oakland",
        "state": "CA",
        "provider": "telnyx",
    },
    {
        "number": "+14155550102",
        "friendly_name": "Conference Bridge",
        "number_type": "local",
        "capability": "voice",
        "city": "San Francisco",
        "state": "CA",
        "provider": "telnyx",
    },
]

_EXTENSIONS = [
    {
        "extension_number": "100",
        "display_name": "Alice Admin",
        "user_email": "admin@example.com",
        "phone_number": "+14155550100",
        "voicemail": {"pin": "1234", "email_address": "admin@example.com", "transcription_enabled": True},
    },
    {
        "extension_number": "101",
        "display_name": "Bob Manager",
        "user_email": "bob.manager@example.com",
        "phone_number": "+14155550101",
        "voicemail": {"pin": "5678", "email_address": "bob.manager@example.com"},
    },
    {
        "extension_number": "102",
        "display_name": "Carol Technician",
        "user_email": "carol.tech@example.com",
        "voicemail": {"pin": "9012", "email_address": "carol.tech@example.com"},
    },
    {
        "extension_number": "103",
        "display_name": "Dave Support",
        "user_email": "dave.support@example.com",
        "voicemail": {"pin": "3456", "email_address": "dave.support@example.com"},
    },
    {
        "extension_number": "104",
        "display_name": "Erin User",
        "user_email": "erin.user@example.com",
        "voicemail": {"pin": "7890", "email_address": "erin.user@example.com"},
    },
    {
        "extension_number": "200",
        "display_name": "Conference Room A",
        "user_email": "admin@example.com",
        "phone_number": "+14155550102",
        "voicemail": None,
    },
    {
        "extension_number": "201",
        "display_name": "Lobby Phone",
        "user_email": "admin@example.com",
        "voicemail": None,
    },
    {
        "extension_number": "300",
        "display_name": "Branch Reception",
        "user_email": "bob.manager@example.com",
        "phone_number": "+15105550300",
        "voicemail": {"pin": "0000", "email_address": "bob.manager@example.com"},
    },
]

_DEVICES = [
    {
        "name": "Alice Desk Phone",
        "device_type": m.DeviceType.DESK_PHONE,
        "mac_address": "AA:BB:CC:01:01:01",
        "device_model": "T54W",
        "manufacturer": "Yealink",
        "firmware_version": "96.86.0.100",
        "ip_address": "10.10.1.101",
        "sip_username": "alice.admin",
        "user_email": "admin@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Alice Admin", "extension_number": "100", "line_type": m.DeviceLineType.PRIVATE},
            {"line_number": 2, "label": "Main Office", "line_type": m.DeviceLineType.SHARED},
        ],
    },
    {
        "name": "Alice Softphone",
        "device_type": m.DeviceType.SOFTPHONE,
        "mac_address": "AA:BB:CC:01:01:02",
        "device_model": "Obi Softphone",
        "manufacturer": "Obi",
        "ip_address": "10.10.1.102",
        "sip_username": "alice.soft",
        "user_email": "admin@example.com",
        "status": m.DeviceStatus.OFFLINE,
        "lines": [
            {"line_number": 1, "label": "Alice Admin", "extension_number": "100", "line_type": m.DeviceLineType.PRIVATE},
        ],
    },
    {
        "name": "Bob Desk Phone",
        "device_type": m.DeviceType.DESK_PHONE,
        "mac_address": "AA:BB:CC:02:02:01",
        "device_model": "T46U",
        "manufacturer": "Yealink",
        "firmware_version": "108.86.0.95",
        "ip_address": "10.10.1.103",
        "sip_username": "bob.manager",
        "user_email": "bob.manager@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Bob Manager", "extension_number": "101", "line_type": m.DeviceLineType.PRIVATE},
        ],
    },
    {
        "name": "Carol Desk Phone",
        "device_type": m.DeviceType.DESK_PHONE,
        "mac_address": "AA:BB:CC:03:03:01",
        "device_model": "VVX 450",
        "manufacturer": "Poly",
        "firmware_version": "6.4.3.1015",
        "ip_address": "10.10.1.104",
        "sip_username": "carol.tech",
        "user_email": "carol.tech@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Carol Tech", "extension_number": "102", "line_type": m.DeviceLineType.PRIVATE},
            {"line_number": 2, "label": "Support Hotline", "line_type": m.DeviceLineType.SHARED},
        ],
    },
    {
        "name": "Conference Room A",
        "device_type": m.DeviceType.CONFERENCE,
        "mac_address": "AA:BB:CC:04:04:01",
        "device_model": "CP960",
        "manufacturer": "Yealink",
        "firmware_version": "73.86.0.90",
        "ip_address": "10.10.1.120",
        "sip_username": "conf.room.a",
        "user_email": "admin@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Conf Room A", "extension_number": "200", "line_type": m.DeviceLineType.SHARED},
        ],
    },
    {
        "name": "Lobby ATA",
        "device_type": m.DeviceType.ATA,
        "mac_address": "AA:BB:CC:05:05:01",
        "device_model": "HT801",
        "manufacturer": "Grandstream",
        "firmware_version": "1.0.13.6",
        "ip_address": "10.10.1.130",
        "sip_username": "lobby.ata",
        "user_email": "admin@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Lobby Phone", "extension_number": "201", "line_type": m.DeviceLineType.PRIVATE},
        ],
    },
    {
        "name": "Dave Softphone",
        "device_type": m.DeviceType.SOFTPHONE,
        "mac_address": "AA:BB:CC:06:06:01",
        "device_model": "Obi Softphone",
        "manufacturer": "Obi",
        "ip_address": "10.10.2.50",
        "sip_username": "dave.support",
        "user_email": "dave.support@example.com",
        "status": m.DeviceStatus.OFFLINE,
        "lines": [
            {"line_number": 1, "label": "Dave Support", "extension_number": "103", "line_type": m.DeviceLineType.PRIVATE},
        ],
    },
    {
        "name": "Branch Reception Phone",
        "device_type": m.DeviceType.DESK_PHONE,
        "mac_address": "AA:BB:CC:07:07:01",
        "device_model": "T53W",
        "manufacturer": "Yealink",
        "firmware_version": "96.86.0.100",
        "ip_address": "10.20.1.101",
        "sip_username": "branch.reception",
        "user_email": "bob.manager@example.com",
        "status": m.DeviceStatus.ONLINE,
        "lines": [
            {"line_number": 1, "label": "Branch Rcpt", "extension_number": "300", "line_type": m.DeviceLineType.PRIVATE},
        ],
    },
]

_FAX_NUMBERS = [
    {
        "number": "+14155559001",
        "label": "Main Office Fax",
        "user_email": "admin@example.com",
        "email_routes": [
            {"email_address": "admin@example.com", "notify_on_failure": True},
            {"email_address": "fax-archive@acmecorp.example.com", "notify_on_failure": False},
        ],
    },
    {
        "number": "+14155559002",
        "label": "Accounting Fax",
        "user_email": "bob.manager@example.com",
        "email_routes": [
            {"email_address": "bob.manager@example.com", "notify_on_failure": True},
        ],
    },
    {
        "number": "+15105559003",
        "label": "Branch Office Fax",
        "user_email": "bob.manager@example.com",
        "email_routes": [
            {"email_address": "bob.manager@example.com", "notify_on_failure": True},
        ],
    },
]

_TICKETS: list[dict[str, Any]] = [
    {
        "ticket_number": "TKT-0001",
        "subject": "Desk phone not registering after firmware update",
        "status": m.TicketStatus.OPEN,
        "priority": m.TicketPriority.HIGH,
        "category": m.TicketCategory.DEVICE,
        "user_email": "erin.user@example.com",
        "assigned_to_email": "carol.tech@example.com",
        "messages": [
            {
                "body": "My desk phone (ext 104) stopped working after the firmware update last night. It shows a 'Registration Failed' error on screen.",
                "author_email": "erin.user@example.com",
            },
            {
                "body": "I can see the device is offline in the dashboard. I will check the SIP credentials and reprovision. Can you confirm the phone's IP address?",
                "author_email": "carol.tech@example.com",
            },
        ],
    },
    {
        "ticket_number": "TKT-0002",
        "subject": "Request new DID for marketing campaign",
        "status": m.TicketStatus.IN_PROGRESS,
        "priority": m.TicketPriority.MEDIUM,
        "category": m.TicketCategory.VOICE,
        "user_email": "bob.manager@example.com",
        "assigned_to_email": "admin@example.com",
        "messages": [
            {
                "body": "We need a new local DID number for our upcoming Q3 marketing campaign. Prefer a 415 area code.",
                "author_email": "bob.manager@example.com",
            },
            {
                "body": "Looking into available numbers with Telnyx. Will provision one by end of week.",
                "author_email": "admin@example.com",
            },
        ],
    },
    {
        "ticket_number": "TKT-0003",
        "subject": "Voicemail to email not delivering",
        "status": m.TicketStatus.RESOLVED,
        "priority": m.TicketPriority.MEDIUM,
        "category": m.TicketCategory.VOICE,
        "user_email": "dave.support@example.com",
        "assigned_to_email": "carol.tech@example.com",
        "resolved_at": datetime(2026, 4, 28, 14, 30, 0, tzinfo=UTC),
        "messages": [
            {
                "body": "I haven't been receiving voicemail-to-email notifications for the past two days.",
                "author_email": "dave.support@example.com",
            },
            {
                "body": "The email address on your voicemail box had a typo. Corrected it and sent a test message — please confirm you received it.",
                "author_email": "carol.tech@example.com",
            },
            {
                "body": "Got it, works perfectly now. Thanks Carol!",
                "author_email": "dave.support@example.com",
            },
        ],
    },
    {
        "ticket_number": "TKT-0004",
        "subject": "Fax machine at branch office intermittently failing",
        "status": m.TicketStatus.WAITING_ON_CUSTOMER,
        "priority": m.TicketPriority.LOW,
        "category": m.TicketCategory.FAX,
        "user_email": "bob.manager@example.com",
        "assigned_to_email": "dave.support@example.com",
        "messages": [
            {
                "body": "The branch office fax line (+15105559003) is failing about 30% of incoming faxes. They come through garbled or incomplete.",
                "author_email": "bob.manager@example.com",
            },
            {
                "body": "This could be a T.38 negotiation issue with the carrier. Can you send a test fax so I can capture the SIP trace?",
                "author_email": "dave.support@example.com",
            },
        ],
    },
    {
        "ticket_number": "TKT-0005",
        "subject": "Set up new employee - Erin User",
        "status": m.TicketStatus.CLOSED,
        "priority": m.TicketPriority.MEDIUM,
        "category": m.TicketCategory.ACCOUNT,
        "user_email": "bob.manager@example.com",
        "assigned_to_email": "admin@example.com",
        "closed_at": datetime(2026, 4, 15, 10, 0, 0, tzinfo=UTC),
        "resolved_at": datetime(2026, 4, 15, 9, 45, 0, tzinfo=UTC),
        "messages": [
            {
                "body": "Please provision a new extension, desk phone, and voicemail for Erin User who starts Monday.",
                "author_email": "bob.manager@example.com",
            },
            {
                "body": "All set. Extension 104, Yealink T54W provisioned and ready at her desk. Voicemail PIN is 7890.",
                "author_email": "admin@example.com",
            },
            {
                "body": "Confirmed, closing ticket.",
                "author_email": "bob.manager@example.com",
            },
        ],
    },
]

_CONNECTIONS = [
    {
        "name": "FreePBX Production",
        "description": "Primary FreePBX PBX server for main office telephony.",
        "connection_type": m.ConnectionType.PBX,
        "provider": "FreePBX",
        "host": "pbx.acmecorp.example.com",
        "port": 443,
        "auth_type": m.ConnectionAuthType.API_KEY,
        "credentials": {"api_key": "PLACEHOLDER_API_KEY_REPLACE_ME"},
        "settings": {"sync_interval_minutes": 15, "auto_provision": True},
        "status": m.ConnectionStatus.CONNECTED,
    },
    {
        "name": "Unifi Network",
        "description": "Ubiquiti Unifi network controller for switch and AP management.",
        "connection_type": m.ConnectionType.NETWORK,
        "provider": "Unifi",
        "host": "unifi.acmecorp.example.com",
        "port": 8443,
        "auth_type": m.ConnectionAuthType.BASIC,
        "credentials": {"username": "admin", "password": "PLACEHOLDER_PASSWORD"},
        "settings": {"site": "default", "verify_ssl": False},
        "status": m.ConnectionStatus.CONNECTED,
    },
]

_NOTIFICATIONS = [
    {
        "title": "New support ticket assigned",
        "message": "Ticket TKT-0002 'Request new DID for marketing campaign' has been assigned to you.",
        "category": "ticket",
        "is_read": False,
        "action_url": "/support/tickets",
    },
    {
        "title": "Device offline alert",
        "message": "Device 'Dave Softphone' (AA:BB:CC:06:06:01) has been offline for over 24 hours.",
        "category": "device",
        "is_read": False,
        "action_url": "/devices",
    },
    {
        "title": "Firmware update available",
        "message": "A new firmware version (96.86.0.110) is available for 3 Yealink devices.",
        "category": "system",
        "is_read": False,
    },
    {
        "title": "E911 registration confirmed",
        "message": "E911 address for +14155550100 has been validated by the carrier.",
        "category": "voice",
        "is_read": True,
    },
]

_E911_REGISTRATIONS = [
    {
        "phone_number": "+14155550100",
        "location_name": "Main Office",
        "address_line_1": "100 Innovation Drive, Suite 400",
        "city": "San Francisco",
        "state": "CA",
        "postal_code": "94105",
        "validated": True,
    },
    {
        "phone_number": "+14155550101",
        "location_name": "Main Office",
        "address_line_1": "100 Innovation Drive, Suite 400",
        "city": "San Francisco",
        "state": "CA",
        "postal_code": "94105",
        "validated": True,
    },
    {
        "phone_number": "+15105550300",
        "location_name": "Branch Office",
        "address_line_1": "2500 Broadway",
        "city": "Oakland",
        "state": "CA",
        "postal_code": "94612",
        "validated": True,
    },
]
