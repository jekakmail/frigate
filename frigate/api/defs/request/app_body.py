from typing import Optional

from pydantic import BaseModel


class AppConfigSetBody(BaseModel):
    requires_restart: int = 1


class AppPutPasswordBody(BaseModel):
    password: str


class AppPostUsersBody(BaseModel):
    username: str
    password: str
    role: Optional[str] = "viewer"


class AppPostLoginBody(BaseModel):
    user: str
    password: str


class AppPostVerifyTotpBody(BaseModel):
    user: str
    totp_code: str
    remember_device: Optional[bool] = False


class AppPutRoleBody(BaseModel):
    role: str


class AppPostEnableTwoFactorBody(BaseModel):
    password: str
    totp_code: str
    secret: str


class AppPostDisableTwoFactorBody(BaseModel):
    password: str
    totp_code: Optional[str] = None
    recovery_code: Optional[str] = None


class AppPostVerifyRecoveryCodeBody(BaseModel):
    user: str
    recovery_code: str
    remember_device: Optional[bool] = False


class AppPostGenerateRecoveryCodesBody(BaseModel):
    password: str
