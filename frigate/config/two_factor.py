from pydantic import Field

from .base import FrigateBaseModel

__all__ = ["TwoFactorConfig"]


class TwoFactorConfig(FrigateBaseModel):
    enabled: bool = Field(
        default=False, title="Enable two-factor authentication functionality"
    )
    code_validity: int = Field(
        default=30, title="Validity period for TOTP codes in seconds", ge=30, le=120
    )
    recovery_codes_count: int = Field(
        default=10, title="Number of recovery codes to generate", ge=5, le=20
    )
    device_token_expiry_days: int = Field(
        default=30, title="Number of days before device tokens expire", ge=1, le=365
    )
