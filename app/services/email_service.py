"""Generic email delivery service."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import resend

from app.core.config import settings

import logging

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    html: str
    text: str | None = None


class EmailService(ABC):
    """Provider-independent email service contract."""

    @abstractmethod
    async def send(self, message: EmailMessage) -> None:
        payload = {
        "from": f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>",
        "to": [message.to],
        "subject": message.subject,
        "html": message.html,
        }

        if message.text:
            payload["text"] = message.text

        resend.Emails.send(payload)

class ResendEmailService(EmailService):
    """Email service implementation using Resend."""

    def __init__(self) -> None:
        if not settings.RESEND_API_KEY:
            raise RuntimeError("RESEND_API_KEY is not configured")

        resend.api_key = settings.RESEND_API_KEY

    async def send(self, message: EmailMessage) -> None:
        payload: dict[str, str] = {
            "from": f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>",
            "to": [message.to],
            "subject": message.subject,
            "html": message.html,
        }

        if message.text:
            payload["text"] = message.text

        # Resend's SDK call is synchronous, so this should eventually
        # be moved to a background worker for high-volume sending.
        resend.Emails.send(payload)

class ConsoleEmailService(EmailService):
    """Fallback email provider that prints emails to console/logs for testing."""
    async def send(self, message: EmailMessage) -> None:
        logger.info(f"[CONSOLE EMAIL] To: {message.to} | Subject: {message.subject}")
        print(f"\n--- EMAIL SENT TO {message.to} ---")
        print(f"Subject: {message.subject}")
        print(f"Body:\n{message.text or message.html}")
        print("-----------------------------------\n")


def get_email_service() -> EmailService:
    """Return the configured email provider."""
    provider = settings.EMAIL_PROVIDER.lower()

    if provider == "resend":
        return ResendEmailService()
    elif provider in ("console", "test", "mock"):
        return ConsoleEmailService()

    raise RuntimeError(f"Unsupported email provider: {settings.EMAIL_PROVIDER}")