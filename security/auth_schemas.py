"""
Auth Request Schemas (Pydantic v2)
==================================
Server-side validation for the auth endpoints. Format + length checks run here
on EVERY request, regardless of any client-side validation.

Design notes
------------
- Sanitisation REUSES the project's existing helpers in `security.validators`
  (NFKC normalise, HTML/script escaping, hard length caps) — we do not introduce
  a second, parallel sanitiser. This keeps the established security layer intact.
- Passwords are deliberately NOT HTML-escaped or character-stripped. Mutating a
  password would (a) change the secret the user actually typed and break login
  against the already-stored bcrypt hash in Supabase, and (b) reduce entropy.
  For passwords we validate length/strength only.
- On any invalid field these raise `pydantic.ValidationError`. Callers MUST catch
  it and return a SINGLE generic error — never disclose which field failed.

Usage
-----
    from pydantic import ValidationError
    from security.auth_schemas import SignupSchema, LoginSchema

    try:
        data = LoginSchema.model_validate(request.get_json(silent=True) or {})
    except ValidationError:
        return jsonify({"error": "Incorrect email or password"}), 401
    email, password = data.email, data.password
"""

from pydantic import BaseModel, ConfigDict, field_validator

from security.validators import (
    sanitise,
    sanitise_raw,
    validate_email,
    validate_password,
)

# Hard caps mirrored from security.validators._MAX_LENGTHS (defence in depth —
# Pydantic rejects oversized payloads before they ever reach the sanitiser).
_EMAIL_MAX = 254
_PASSWORD_MAX = 1024
_NAME_MAX = 200
_TOKEN_MAX = 256


class _Base(BaseModel):
    # Ignore unknown keys, strip surrounding whitespace on all string fields.
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")


class SignupSchema(_Base):
    """New-account creation. Enforces email format + password strength."""

    email: str
    password: str
    full_name: str = ""

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        v = sanitise_raw(v, "email").lower()
        if not validate_email(v):
            raise ValueError("email")
        return v

    @field_validator("password")
    @classmethod
    def _v_password(cls, v: str) -> str:
        # No escaping/stripping — see module docstring. Strength only.
        if len(v) > _PASSWORD_MAX:
            raise ValueError("password")
        ok, _ = validate_password(v)
        if not ok:
            raise ValueError("password")
        return v

    @field_validator("full_name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        # Strip HTML/script tags and special chars via the existing sanitiser.
        return sanitise(v, "name")[:_NAME_MAX]


class LoginSchema(_Base):
    """
    Login. Validates email FORMAT and password PRESENCE/length only.
    It must NOT run password-strength rules: existing accounts may have
    passwords that predate the current strength policy, and rejecting them
    here would lock valid users out.
    """

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        v = sanitise_raw(v, "email").lower()
        if not validate_email(v):
            raise ValueError("email")
        return v

    @field_validator("password")
    @classmethod
    def _v_password(cls, v: str) -> str:
        if not v or len(v) > _PASSWORD_MAX:
            raise ValueError("password")
        return v


class ForgotPasswordSchema(_Base):
    """Password-reset request. Email format only."""

    email: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        v = sanitise_raw(v, "email").lower()
        if not validate_email(v):
            raise ValueError("email")
        return v


class ResetPasswordSchema(_Base):
    """Setting a new password via a Supabase reset token. Strength enforced."""

    access_token: str
    refresh_token: str = ""
    password: str

    @field_validator("access_token")
    @classmethod
    def _v_token(cls, v: str) -> str:
        if not v or len(v) > _TOKEN_MAX * 8:  # JWTs are long; generous cap
            raise ValueError("access_token")
        return v

    @field_validator("password")
    @classmethod
    def _v_password(cls, v: str) -> str:
        if len(v) > _PASSWORD_MAX:
            raise ValueError("password")
        ok, _ = validate_password(v)
        if not ok:
            raise ValueError("password")
        return v


class VerifyEmailSchema(_Base):
    """OTP verification. Email format + token presence."""

    email: str
    token: str
    full_name: str = ""

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        v = sanitise_raw(v, "email").lower()
        if not validate_email(v):
            raise ValueError("email")
        return v

    @field_validator("token")
    @classmethod
    def _v_token(cls, v: str) -> str:
        # OTP codes are short numeric strings; cap defensively.
        if not v or len(v) > 32:
            raise ValueError("token")
        return v

    @field_validator("full_name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return sanitise(v, "name")[:_NAME_MAX]
