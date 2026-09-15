"""Invitation email templates."""

from html import escape


def build_invitation_email(
    *,
    organization_name: str,
    role_name: str,
    invitation_url: str,
    expires_at: str,
) -> tuple[str, str]:
    """Build HTML and plain-text invitation email content."""

    safe_organization_name = escape(organization_name)
    safe_role_name = escape(role_name)
    safe_invitation_url = escape(invitation_url)
    safe_expires_at = escape(expires_at)

    subject = f"Invitation to join {organization_name}"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{subject}</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #222;">
    <h2>You're invited to join {safe_organization_name}</h2>

    <p>
        You have been invited to join
        <strong>{safe_organization_name}</strong>
        as a <strong>{safe_role_name}</strong>.
    </p>

    <p>
        Click the button below to review and accept your invitation:
    </p>

    <p>
        <a
            href="{safe_invitation_url}"
            style="
                display: inline-block;
                padding: 12px 20px;
                background: #2563eb;
                color: #ffffff;
                text-decoration: none;
                border-radius: 6px;
            "
        >
            Review invitation
        </a>
    </p>

    <p>
        This invitation expires on
        <strong>{safe_expires_at}</strong>.
    </p>

    <p>
        If you were not expecting this invitation, you can safely ignore
        this email.
    </p>
</body>
</html>
"""

    text = f"""
You're invited to join {organization_name}

You have been invited to join {organization_name} as a {role_name}.

Review and accept your invitation here:

{invitation_url}

This invitation expires on {expires_at}.

If you were not expecting this invitation, you can safely ignore this email.
""".strip()

    return subject, html, text