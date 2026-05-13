"""User Profile Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

import structlog
from litestar import Controller, delete, get, patch, put
from litestar.datastructures import (
    UploadFile,  # noqa: TC002  (resolved at runtime by Litestar for the request signature)
)
from litestar.di import Provide
from litestar.enums import RequestEncodingType
from litestar.params import Body

from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.domain.accounts.schemas import PasswordUpdate, ProfileUpdate, User
from app.domain.admin.deps import provide_audit_log_service
from app.domain.attachments.services import AttachmentService
from app.lib.deps import create_service_provider
from app.lib.schema import Message

if TYPE_CHECKING:
    from app.domain.accounts.services import UserService
    from app.domain.admin.services import AuditLogService

logger = structlog.get_logger()


class ProfileController(Controller):
    """Handles the current user profile operations."""

    tags = ["Access"]
    dependencies = {
        "users_service": Provide(provide_users_service),
        "attachments_service": create_service_provider(AttachmentService),
        "audit_service": provide_audit_log_service,
    }

    @get(
        operation_id="AccountProfile",
        path="/api/me",
        summary="User Profile",
        description="User profile information.",
    )
    async def get_profile(self, users_service: UserService, current_user: m.User) -> User:
        """User profile.

        Returns:
            User: The current user's profile.
        """
        return users_service.to_schema(current_user, schema_type=User)

    @patch(operation_id="AccountProfileUpdate", path="/api/me")
    async def update_profile(
        self,
        current_user: m.User,
        data: ProfileUpdate,
        users_service: UserService,
    ) -> User:
        """User Profile.

        Args:
            current_user: The current user.
            data: The profile update data.
            users_service: The users service.

        Returns:
            The response object.
        """
        db_obj = await users_service.update(data, item_id=current_user.id)
        return users_service.to_schema(db_obj, schema_type=User)

    @patch(operation_id="AccountPasswordUpdate", path="/api/me/password")
    async def update_password(
        self,
        current_user: m.User,
        data: PasswordUpdate,
        users_service: UserService,
    ) -> Message:
        """Update user password.

        Args:
            current_user: The current user.
            data: The password update data.
            users_service: The users service.

        Returns:
            The response object.
        """
        await users_service.update_password(data.to_dict(), db_obj=current_user)
        return Message(message="Your password was successfully modified.")

    @put(operation_id="AccountAvatarSet", path="/api/me/avatar")
    async def set_avatar(
        self,
        current_user: m.User,
        users_service: UserService,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        data: Annotated[UploadFile, Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> User:
        """Upload and set the current user's avatar.

        Args:
            current_user: The current user.
            users_service: The users service.
            attachments_service: The attachments service.
            audit_service: The audit log service.
            data: The uploaded image.

        Returns:
            The updated user profile.
        """
        previous_avatar_id = current_user.avatar_id
        # exclude the previous avatar's bytes from the (per-team) quota
        # calculation so a same-size replacement at the cap does not 413.
        attachment = await attachments_service.create_from_upload(
            data,
            uploaded_by_id=current_user.id,
            purpose=m.AttachmentPurpose.AVATAR,
            excluding_attachment_id=previous_avatar_id,
        )
        db_obj = await users_service.update(
            {"avatar_id": attachment.id, "avatar_url": f"/api/uploads/{attachment.id}/content"},
            item_id=current_user.id,
        )
        if previous_avatar_id and previous_avatar_id != attachment.id:
            previous = await attachments_service.get_one_or_none(id=previous_avatar_id)
            if previous is not None:
                await attachments_service.delete_with_object(previous)
        await audit_service.log_action(
            "user.avatar.set",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="user",
            target_id=str(current_user.id),
            target_label=current_user.email,
            details={"attachment_id": str(attachment.id), "size_bytes": attachment.size_bytes},
        )
        return users_service.to_schema(db_obj, schema_type=User)

    @delete(operation_id="AccountAvatarClear", path="/api/me/avatar", status_code=200)
    async def clear_avatar(
        self,
        current_user: m.User,
        users_service: UserService,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
    ) -> User:
        """Remove the current user's avatar.

        Args:
            current_user: The current user.
            users_service: The users service.
            attachments_service: The attachments service.
            audit_service: The audit log service.

        Returns:
            The updated user profile.
        """
        previous_avatar_id = current_user.avatar_id
        db_obj = await users_service.update({"avatar_id": None, "avatar_url": None}, item_id=current_user.id)
        if previous_avatar_id:
            previous = await attachments_service.get_one_or_none(id=previous_avatar_id)
            if previous is not None:
                await attachments_service.delete_with_object(previous)
        await audit_service.log_action(
            "user.avatar.cleared",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="user",
            target_id=str(current_user.id),
            target_label=current_user.email,
        )
        return users_service.to_schema(db_obj, schema_type=User)

    @delete(operation_id="AccountDelete", path="/api/me")
    async def remove_account(
        self,
        current_user: m.User,
        users_service: UserService,
    ) -> None:
        """Remove your account.

        Args:
            current_user: The current user.
            users_service: The users service.

        """
        _ = await users_service.delete(current_user.id)
