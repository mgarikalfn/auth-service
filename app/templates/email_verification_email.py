from datetime import datetime


def build_email_verification_email(
    *,
    verification_url: str,
    expires_at: datetime,
) -> tuple[str, str, str]:
    subject = "Verify your email address"

    html = f"""
    <html>
      <body>
        <h2>Verify your email address</h2>

        <p>
          Thanks for creating your account.
          Please verify your email address to activate
          your account.
        </p>

        <p>
          <a href="{verification_url}">
            Verify your email address
          </a>
        </p>

        <p>
          This verification link expires at
          {expires_at.isoformat()}.
        </p>

        <p>
          If you did not create this account,
          you can safely ignore this email.
        </p>
      </body>
    </html>
    """

    text = (
        "Thanks for creating your account.\n\n"
        "Please verify your email address using this link:\n"
        f"{verification_url}\n\n"
        f"This verification link expires at "
        f"{expires_at.isoformat()}.\n\n"
        "If you did not create this account, "
        "you can safely ignore this email."
    )

    return subject, html, text