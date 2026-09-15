from datetime import datetime


def build_password_reset_email(
    *,
    reset_url: str,
    expires_at: datetime,
) -> tuple[str, str, str]:
    subject = "Reset your password"

    html = f"""
    <html>
      <body>
        <h2>Password reset request</h2>
        <p>
          We received a request to reset your password.
        </p>
        <p>
          <a href="{reset_url}">Reset your password</a>
        </p>
        <p>
          This link expires at {expires_at.isoformat()}.
        </p>
        <p>
          If you did not request this, you can safely ignore this email.
        </p>
      </body>
    </html>
    """

    text = (
        "We received a request to reset your password.\n\n"
        f"Reset your password using this link:\n{reset_url}\n\n"
        f"This link expires at {expires_at.isoformat()}.\n\n"
        "If you did not request this, you can safely ignore this email."
    )

    return subject, html, text