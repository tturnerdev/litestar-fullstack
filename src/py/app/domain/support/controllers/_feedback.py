"""Feedback Controller - handles portal feedback/issue reports via email."""

from __future__ import annotations

import html
import logging
import mimetypes
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, Request, post
from litestar.datastructures import UploadFile
from litestar.enums import RequestEncodingType
from litestar.exceptions import HTTPException
from litestar.params import Body
from litestar.security.jwt import Token

from app.db import models as m
from app.lib.schema import Message

if TYPE_CHECKING:
    from app.lib.email import AppEmailService

logger = logging.getLogger(__name__)

FEEDBACK_RECIPIENT = "support@atrelix.com"


def _build_feedback_html(
    *,
    title: str,
    category: str,
    description: str,
    user_name: str,
    user_email: str,
    submitted_at: str,
) -> str:
    """Build a clean HTML email body for a feedback submission.

    Args:
        title: The feedback title/subject.
        category: The category label.
        description: The full description text.
        user_name: Display name of the submitting user.
        user_email: Email address of the submitting user.
        submitted_at: Formatted timestamp string.

    Returns:
        Rendered HTML string.
    """
    title_safe = html.escape(title)
    category_safe = html.escape(category)
    description_safe = html.escape(description).replace("\n", "<br>")
    user_name_safe = html.escape(user_name)
    user_email_safe = html.escape(user_email)
    submitted_at_safe = html.escape(submitted_at)

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">

          <!-- Header -->
          <tr>
            <td style="background-color:#18181b;padding:24px 32px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <span style="display:inline-block;background-color:#3b82f6;color:#ffffff;font-size:12px;font-weight:600;padding:4px 12px;border-radius:12px;text-transform:uppercase;letter-spacing:0.5px;">{category_safe}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:12px;">
                    <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:600;line-height:1.4;">{title_safe}</h1>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Submitted by -->
          <tr>
            <td style="padding:20px 32px 0;">
              <p style="margin:0;font-size:14px;color:#71717a;">
                <strong style="color:#3f3f46;">Submitted by:</strong> {user_name_safe} &lt;{user_email_safe}&gt;
              </p>
            </td>
          </tr>

          <!-- Timestamp -->
          <tr>
            <td style="padding:8px 32px 0;">
              <p style="margin:0;font-size:14px;color:#71717a;">
                <strong style="color:#3f3f46;">Date:</strong> {submitted_at_safe}
              </p>
            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding:20px 32px 0;">
              <hr style="border:none;border-top:1px solid #e4e4e7;margin:0;">
            </td>
          </tr>

          <!-- Description -->
          <tr>
            <td style="padding:20px 32px;">
              <h2 style="margin:0 0 12px;font-size:14px;font-weight:600;color:#3f3f46;text-transform:uppercase;letter-spacing:0.5px;">Description</h2>
              <div style="font-size:15px;line-height:1.6;color:#27272a;">{description_safe}</div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:16px 32px 24px;">
              <hr style="border:none;border-top:1px solid #e4e4e7;margin:0 0 16px;">
              <p style="margin:0;font-size:12px;color:#a1a1aa;font-style:italic;">
                This report was submitted via the Admin Portal Help dialog.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


class FeedbackController(Controller):
    """Portal feedback / issue reports."""

    tags = ["Support"]

    @post(
        operation_id="SubmitFeedback",
        path="/api/support/feedback",
    )
    async def submit_feedback(
        self,
        current_user: m.User,
        app_mailer: AppEmailService,
        request: Request[m.User, Token, Any],
        data: Annotated[
            dict[str, Any],
            Body(media_type=RequestEncodingType.MULTI_PART),
        ],
    ) -> Message:
        """Submit portal feedback and send it as an HTML email.

        Accepts multipart form data with fields: title, category,
        description, screenshot (optional file), files (optional files).

        Args:
            current_user: The authenticated user submitting feedback.
            app_mailer: The email service for sending the feedback email.
            request: The HTTP request.
            data: Parsed multipart form data dict.

        Returns:
            A success message.
        """
        title = str(data.get("title", "")).strip()
        category = str(data.get("category", "")).strip()
        description = str(data.get("description", "")).strip()

        if not title:
            raise HTTPException(status_code=400, detail="Title is required.")
        if not category:
            raise HTTPException(status_code=400, detail="Category is required.")
        if not description:
            raise HTTPException(status_code=400, detail="Description is required.")

        user_name = current_user.name or current_user.email
        user_email = current_user.email
        submitted_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        html_content = _build_feedback_html(
            title=title,
            category=category,
            description=description,
            user_name=user_name,
            user_email=user_email,
            submitted_at=submitted_at,
        )

        # Collect file attachments from multipart form data
        attachments: list[tuple[str, bytes, str]] = []

        screenshot = data.get("screenshot")
        if isinstance(screenshot, UploadFile) and screenshot.filename:
            screenshot_bytes = await screenshot.read()
            if screenshot_bytes:
                attachments.append(("screenshot.png", screenshot_bytes, "image/png"))

        files_raw = data.get("files")
        if files_raw is not None:
            # Normalize to list — single file comes as UploadFile, multiple as list
            file_list = files_raw if isinstance(files_raw, list) else [files_raw]
            for file_item in file_list:
                if isinstance(file_item, UploadFile) and file_item.filename:
                    file_bytes = await file_item.read()
                    if file_bytes:
                        mimetype = (
                            file_item.content_type
                            or mimetypes.guess_type(file_item.filename)[0]
                            or "application/octet-stream"
                        )
                        attachments.append((file_item.filename, file_bytes, mimetype))

        subject = f"[Portal Feedback] {category}: {title}"

        await app_mailer.send_email(
            to_email=FEEDBACK_RECIPIENT,
            subject=subject,
            html_content=html_content,
            reply_to=user_email,
            attachments=attachments if attachments else None,
        )

        logger.info(
            "Feedback submitted by %s (%s): %s",
            user_name,
            user_email,
            title,
        )

        return Message(message="Feedback submitted successfully.")
