"""Auth apis."""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import string
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from joserfc import jwt
from peewee import DoesNotExist
from slowapi import Limiter

from frigate.api.defs.request.app_body import (
    AppPostLoginBody,
    AppPostUsersBody,
    AppPutPasswordBody,
    AppPutRoleBody,
    AppPostVerifyTotpBody,
    AppPostEnableTwoFactorBody,
    AppPostDisableTwoFactorBody,
    AppPostVerifyRecoveryCodeBody,
    AppPostGenerateRecoveryCodesBody,
)
from frigate.api.defs.tags import Tags
from frigate.config import AuthConfig, ProxyConfig
from frigate.const import CONFIG_DIR, JWT_SECRET_ENV_VAR, PASSWORD_HASH_ALGORITHM
from frigate.models import User

logger = logging.getLogger(__name__)

router = APIRouter(tags=[Tags.auth])


class RateLimiter:
    _limit = ""

    def set_limit(self, limit: str):
        self._limit = limit

    def get_limit(self) -> str:
        return self._limit


rateLimiter = RateLimiter()


def get_remote_addr(request: Request):
    route = list(reversed(request.headers.get("x-forwarded-for").split(",")))
    logger.debug(f"IP Route: {[r for r in route]}")
    trusted_proxies = []
    for proxy in request.app.frigate_config.auth.trusted_proxies:
        try:
            network = ipaddress.ip_network(proxy)
        except ValueError:
            logger.warning(f"Unable to parse trusted network: {proxy}")
        trusted_proxies.append(network)

    # return the first remote address that is not trusted
    for addr in route:
        ip = ipaddress.ip_address(addr.strip())
        logger.debug(f"Checking {ip} (v{ip.version})")
        trusted = False
        for trusted_proxy in trusted_proxies:
            logger.debug(
                f"Checking against trusted proxy: {trusted_proxy} (v{trusted_proxy.version})"
            )
            if trusted_proxy.version == 4:
                ipv4 = ip.ipv4_mapped if ip.version == 6 else ip
                if ipv4 in trusted_proxy:
                    trusted = True
                    logger.debug(f"Trusted: {str(ip)} by {str(trusted_proxy)}")
                    break
            elif trusted_proxy.version == 6 and ip.version == 6:
                if ip in trusted_proxy:
                    trusted = True
                    logger.debug(f"Trusted: {str(ip)} by {str(trusted_proxy)}")
                    break
        if trusted:
            logger.debug(f"{ip} is trusted")
            continue
        else:
            logger.debug(f"First untrusted IP: {str(ip)}")
            return str(ip)

    # if there wasn't anything in the route, just return the default
    remote_addr = None

    if hasattr(request, "remote_addr"):
        remote_addr = request.remote_addr

    return remote_addr or "127.0.0.1"


def get_jwt_secret() -> str:
    jwt_secret = None
    # check env var
    if JWT_SECRET_ENV_VAR in os.environ:
        logger.debug(
            f"Using jwt secret from {JWT_SECRET_ENV_VAR} environment variable."
        )
        jwt_secret = os.environ.get(JWT_SECRET_ENV_VAR)
    # check docker secrets
    elif os.path.isfile(os.path.join("/run/secrets", JWT_SECRET_ENV_VAR)):
        logger.debug(f"Using jwt secret from {JWT_SECRET_ENV_VAR} docker secret file.")
        jwt_secret = (
            Path(os.path.join("/run/secrets", JWT_SECRET_ENV_VAR)).read_text().strip()
        )
    # check for the add-on options file
    elif os.path.isfile("/data/options.json"):
        with open("/data/options.json") as f:
            raw_options = f.read()
        logger.debug("Using jwt secret from Home Assistant Add-on options file.")
        options = json.loads(raw_options)
        jwt_secret = options.get("jwt_secret")

    if jwt_secret is None:
        jwt_secret_file = os.path.join(CONFIG_DIR, ".jwt_secret")
        # check .jwt_secrets file
        if not os.path.isfile(jwt_secret_file):
            logger.debug(
                "No jwt secret found. Generating one and storing in .jwt_secret file in config directory."
            )
            jwt_secret = secrets.token_hex(64)
            try:
                with open(jwt_secret_file, "w") as f:
                    f.write(str(jwt_secret))
            except Exception:
                logger.warning(
                    "Unable to write jwt token file to config directory. A new jwt token will be created at each startup."
                )
        else:
            logger.debug("Using jwt secret from .jwt_secret file in config directory.")
            with open(jwt_secret_file) as f:
                try:
                    jwt_secret = f.readline().strip()
                except Exception:
                    logger.warning(
                        "Unable to read jwt token from .jwt_secret file in config directory. A new jwt token will be created at each startup."
                    )
                    jwt_secret = secrets.token_hex(64)

    if len(jwt_secret) < 64:
        logger.warning("JWT Secret is recommended to be 64 characters or more")

    return jwt_secret


def hash_password(password: str, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(PASSWORD_HASH_ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == PASSWORD_HASH_ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


def create_encoded_jwt(user, role, expiration, secret):
    return jwt.encode(
        {"alg": "HS256"}, {"sub": user, "role": role, "exp": expiration}, secret
    )


def set_jwt_cookie(response: Response, cookie_name, encoded_jwt, expiration, secure):
    # TODO: ideally this would set secure as well, but that requires TLS
    response.set_cookie(
        key=cookie_name,
        value=encoded_jwt,
        httponly=True,
        expires=expiration,
        secure=secure,
        samesite="lax",  # Allow cookies to be sent with navigation from external sites
    )


def set_device_token_cookie(response: Response, cookie_name, token, expiration, secure):
    """Set a device token cookie with the same attributes as the JWT cookie."""
    response.set_cookie(
        key=cookie_name,
        value=token,
        httponly=True,
        expires=expiration,
        secure=secure,
        samesite="lax",  # Allow cookies to be sent with navigation from external sites
    )


def generate_totp_secret() -> str:
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str, validity_period: int, issuer: str = "Frigate") -> str:
    """Generate a TOTP URI for QR code generation."""

    # Create a TOTP object
    totp = pyotp.totp.TOTP(secret, interval=validity_period)

    # Log the TOTP parameters for debugging (without revealing any part of the secret)
    logger.info(f"Generating TOTP URI for user: {username}")
    logger.info(f"TOTP parameters: interval={totp.interval}, digits={totp.digits}")

    # Generate the URI
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    logger.info(f"Generated TOTP URI for user: {username}")

    return uri


def verify_totp(secret: str, code: str, validity_period: int, username: str = None) -> bool:
    """
    Verify a TOTP code against a secret and check for replay attacks.

    Args:
        secret: The TOTP secret key
        code: The TOTP code to verify
        validity_period: The validity period for TOTP codes in seconds
        username: The username of the user, required to check and store used codes

    Returns:
        bool: True if the code is valid and hasn't been used recently, False otherwise
    """
    if not secret or not code:
        logger.warning(f"TOTP verification failed: No secret or code provided")
        return False

    # Normalize the code using the utility function
    normalized_code = normalize_totp_code(code)

    # Create the TOTP object with the default interval (30 seconds)
    totp = pyotp.TOTP(secret, interval=validity_period)

    # Calculate the appropriate time window based on validity_period
    # pyotp uses a window parameter that represents the number of 30-second intervals
    # to check before and after the current time
    # Use a reasonable window of at least 1 interval, but respect the validity_period
    # Cap the window to a maximum of 3 for security reasons
    window = min(3, max(1, validity_period // 30))

    logger.info(f"Verifying TOTP code with window={window} (±{window} intervals)")

    # Get the current timestamp
    current_time = int(time.time())

    # If a username is provided, check if this code has been used recently
    if username:
        try:
            # Get the user from the database
            user = User.get_by_id(username)

            # Check if the user has used_totp_codes
            if user.used_totp_codes:
                # Check if the normalized code is in the used codes
                for used_code_entry in user.used_totp_codes:
                    if used_code_entry.get('code') == normalized_code:
                        # Check if the code was used within the validity period
                        used_time = used_code_entry.get('timestamp', 0)
                        if current_time - used_time < validity_period * 2:  # Double the validity period for safety
                            logger.warning(f"TOTP code has been used recently (replay attack attempt)")
                            return False

        except DoesNotExist:
            logger.warning(f"User {username} not found when checking used TOTP codes")
            return False
        except Exception as e:
            logger.error(f"Error checking used TOTP codes: {e}")
            # Continue with verification even if there's an error checking used codes

    try:
        # Use the standard pyotp verification with the specified window
        if totp.verify(normalized_code, valid_window=window):
            logger.info(f"TOTP code verified successfully")

            # If a username is provided, store the used code
            if username:
                try:
                    # Get the user from the database
                    user = User.get_by_id(username)

                    # Initialize used_totp_codes if it doesn't exist
                    used_codes = user.used_totp_codes or []

                    # Add the new code with a timestamp
                    used_codes.append({
                        'code': normalized_code,
                        'timestamp': current_time
                    })

                    # Clean up old codes (older than 2 * validity_period)
                    cleanup_time = current_time - (validity_period * 2)
                    used_codes = [code_entry for code_entry in used_codes 
                                 if code_entry.get('timestamp', 0) > cleanup_time]

                    # Update the user in the database
                    User.set_by_id(username, {User.used_totp_codes: used_codes})
                    logger.info(f"Stored used TOTP code, now tracking {len(used_codes)} recent codes")

                except Exception as e:
                    logger.error(f"Error storing used TOTP code: {e}")
                    # Continue even if there's an error storing the used code

            return True
        else:
            logger.info(f"TOTP code verification failed")
            return False
    except Exception as e:
        logger.error(f"Error during TOTP verification: {e}")
        return False


def normalize_totp_code(code: str) -> str:
    """
    Normalize a TOTP code by removing whitespace and non-digit characters.
    """
    # First remove whitespace, then remove non-digit characters
    normalized = re.sub(r'\s+', '', code)
    normalized = re.sub(r'[^0-9]', '', normalized)
    return normalized


def normalize_recovery_code(code: str) -> str:
    """
    Normalize a recovery code by removing hyphens, spaces, and converting to uppercase.
    """
    return re.sub(r'[\s-]+', '', code).upper()


def hash_recovery_code(code: str, salt=None, iterations=600000):
    """
    Hash a recovery code using the same approach as password hashing.
    Returns a formatted string: "{algorithm}${iterations}${salt}${base64_hash}"
    """
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(code, str)

    # Normalize the code
    normalized_code = normalize_recovery_code(code)

    code_hash = hashlib.pbkdf2_hmac(
        "sha256", normalized_code.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(code_hash).decode("ascii").strip()
    return "{}${}${}${}".format(PASSWORD_HASH_ALGORITHM, iterations, salt, b64_hash)


def generate_device_token() -> str:
    """
    Generate a unique device token.
    Returns a string token that can be used to identify a trusted device.
    """
    # Generate a random UUID and convert to a string
    return str(uuid.uuid4())


def store_device_token(username: str, token: str, device_name: str = "Unknown Device", expiry_days: int = 30) -> bool:
    """
    Store a device token for a user.

    Args:
        username: The username of the user
        token: The device token to store
        device_name: A name for the device (can be auto-detected or user-provided)
        expiry_days: Number of days until the token expires

    Returns:
        bool: True if the token was stored successfully, False otherwise
    """
    try:
        # Get the user from the database
        user = User.get_by_id(username)

        # Get existing device tokens or initialize an empty list
        device_tokens = user.device_tokens or []

        # Calculate expiration timestamp
        expiry_time = int((datetime.now() + timedelta(days=expiry_days)).timestamp())

        # Create a new device token entry
        new_token = {
            'token': token,
            'device_name': device_name,
            'created_at': int(datetime.now().timestamp()),
            'expires_at': expiry_time,
            'last_used': int(datetime.now().timestamp())
        }

        # Add the new token to the list
        device_tokens.append(new_token)

        # Update the user in the database
        User.set_by_id(username, {User.device_tokens: device_tokens})
        logger.info(f"Stored device token for user {username}")

        return True
    except Exception as e:
        logger.error(f"Error storing device token: {e}")
        return False


def validate_device_token(username: str, token: str) -> bool:
    """
    Validate a device token for a user.

    Args:
        username: The username of the user
        token: The device token to validate

    Returns:
        bool: True if the token is valid, False otherwise
    """
    try:
        # Get the user from the database
        user = User.get_by_id(username)

        # If the user doesn't have device tokens or 2FA is not enabled, return False
        if not user.device_tokens or not user.two_factor_enabled:
            return False

        current_time = int(datetime.now().timestamp())
        valid_token = False
        updated_tokens = []

        # Check each token
        for device_token in user.device_tokens:
            # Skip if the token is expired
            if device_token.get('expires_at', 0) < current_time:
                continue

            # Add valid tokens to the updated list
            if device_token.get('token') == token:
                # Update last_used timestamp
                device_token['last_used'] = current_time
                valid_token = True

            updated_tokens.append(device_token)

        # Update the user's device tokens, removing expired ones
        if len(updated_tokens) != len(user.device_tokens):
            User.set_by_id(username, {User.device_tokens: updated_tokens})
            logger.info(f"Cleaned up expired device tokens for user {username}")

        # If the token was found and is valid, update its last_used timestamp
        if valid_token:
            User.set_by_id(username, {User.device_tokens: updated_tokens})
            logger.info(f"Valid device token used for user {username}")

        return valid_token
    except Exception as e:
        logger.error(f"Error validating device token: {e}")
        return False


def generate_recovery_codes(count: int = 10) -> Tuple[List[str], List[str]]:
    """
    Generate a list of recovery codes and their hashed versions.
    Returns a tuple of (plain_text_codes, hashed_codes).
    """
    plain_codes = []
    hashed_codes = []
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(count):
        # Generate a random 10-character alphanumeric code using secrets for better security
        code = ''.join(secrets.choice(alphabet) for _ in range(10))
        # Format as XXXX-XXXX-XX
        formatted_code = f"{code[:4]}-{code[4:8]}-{code[8:]}"
        plain_codes.append(formatted_code)
        # Hash the code for storage
        hashed_codes.append(hash_recovery_code(formatted_code))
    return plain_codes, hashed_codes


def verify_recovery_code(stored_hashed_codes: List[str], provided_code: str) -> Tuple[bool, List[str]]:
    """
    Verify a recovery code against stored hashed codes.
    Returns a tuple of (is_valid, updated_codes).
    If the code is valid, it is removed from the list of codes.
    """
    if not stored_hashed_codes or not provided_code:
        logger.debug(f"Recovery code verification failed: No stored codes or no provided code")
        return False, stored_hashed_codes

    # Normalize the provided code
    normalized_code = normalize_recovery_code(provided_code)
    logger.info(f"Verifying recovery code against {len(stored_hashed_codes)} stored codes")

    # Check each stored hashed code
    for i, hashed_code in enumerate(stored_hashed_codes):
        # Parse the hash components
        if (hashed_code or "").count("$") != 3:
            logger.warning(f"Invalid hash format for code {i+1}, skipping")
            continue

        algorithm, iterations, salt, stored_b64_hash = hashed_code.split("$", 3)
        iterations = int(iterations)

        # Hash the provided code with the same salt and iterations
        try:
            # Create the hash directly without using hash_recovery_code to avoid format string comparison
            code_hash = hashlib.pbkdf2_hmac(
                "sha256", normalized_code.encode("utf-8"), salt.encode("utf-8"), iterations
            )
            provided_b64_hash = base64.b64encode(code_hash).decode("ascii").strip()

            # Compare only the hash parts using constant-time comparison
            if secrets.compare_digest(stored_b64_hash, provided_b64_hash):
                logger.info(f"Recovery code matched with stored code {i+1}")
                # Remove the used code
                updated_codes = stored_hashed_codes.copy()
                updated_codes.pop(i)
                return True, updated_codes
        except Exception as e:
            logger.error(f"Error verifying recovery code: {e}")
            continue

    logger.info(f"Recovery code verification failed: No matching code found")
    return False, stored_hashed_codes


async def get_current_user(request: Request):
    username = request.headers.get("remote-user")
    role = request.headers.get("remote-role")

    if not username or not role:
        return JSONResponse(
            content={"message": "No authorization headers."}, status_code=401
        )

    return {"username": username, "role": role}


def require_role(required_roles: List[str]):
    async def role_checker(request: Request):
        # Get role from header (could be comma-separated)
        role_header = request.headers.get("remote-role")
        roles = [r.strip() for r in role_header.split(",")] if role_header else []

        # Check if we have any roles
        if not roles:
            raise HTTPException(status_code=403, detail="Role not provided")

        # Check if any role matches required_roles
        if not any(role in required_roles for role in roles):
            raise HTTPException(
                status_code=403,
                detail=f"Role {', '.join(roles)} not authorized. Required: {', '.join(required_roles)}",
            )

        # Return the first matching role
        return next((role for role in roles if role in required_roles), roles[0])

    return role_checker


# Endpoints
@router.get("/auth")
def auth(request: Request):
    auth_config: AuthConfig = request.app.frigate_config.auth
    proxy_config: ProxyConfig = request.app.frigate_config.proxy

    success_response = Response("", status_code=202)

    # dont require auth if the request is on the internal port
    # this header is set by Frigate's nginx proxy, so it cant be spoofed
    if int(request.headers.get("x-server-port", default=0)) == 5000:
        success_response.headers["remote-user"] = "anonymous"
        success_response.headers["remote-role"] = "admin"
        return success_response

    fail_response = Response("", status_code=401)

    # ensure the proxy secret matches if configured
    if (
        proxy_config.auth_secret is not None
        and request.headers.get("x-proxy-secret", "") != proxy_config.auth_secret
    ):
        logger.debug("X-Proxy-Secret header does not match configured secret value")
        return fail_response

    # if auth is disabled, just apply the proxy header map and return success
    if not auth_config.enabled:
        # pass the user header value from the upstream proxy if a mapping is specified
        # or use anonymous if none are specified
        user_header = proxy_config.header_map.user
        success_response.headers["remote-user"] = (
            request.headers.get(user_header, default="anonymous")
            if user_header
            else "anonymous"
        )

        role_header = proxy_config.header_map.role
        role = (
            request.headers.get(role_header, default=proxy_config.default_role)
            if role_header
            else proxy_config.default_role
        )

        # if comma-separated with "admin", use "admin", else use default role
        success_response.headers["remote-role"] = (
            "admin"
            if role and "admin" in [r.strip() for r in role.split(",")]
            else proxy_config.default_role
        )

        return success_response

    # now apply authentication
    fail_response.headers["location"] = "/login"

    JWT_COOKIE_NAME = request.app.frigate_config.auth.cookie_name
    JWT_COOKIE_SECURE = request.app.frigate_config.auth.cookie_secure
    JWT_REFRESH = request.app.frigate_config.auth.refresh_time
    JWT_SESSION_LENGTH = request.app.frigate_config.auth.session_length

    jwt_source = None
    encoded_token = None
    if "authorization" in request.headers and request.headers[
        "authorization"
    ].startswith("Bearer "):
        jwt_source = "authorization"
        logger.debug("Found authorization header")
        encoded_token = request.headers["authorization"].replace("Bearer ", "")
    elif JWT_COOKIE_NAME in request.cookies:
        jwt_source = "cookie"
        logger.debug("Found jwt cookie")
        encoded_token = request.cookies[JWT_COOKIE_NAME]

    if encoded_token is None:
        logger.debug("No jwt token found")
        return fail_response

    try:
        token = jwt.decode(encoded_token, request.app.jwt_token)
        if "sub" not in token.claims:
            logger.debug("user not set in jwt token")
            return fail_response
        if "role" not in token.claims:
            logger.debug("role not set in jwt token")
            return fail_response
        if "exp" not in token.claims:
            logger.debug("exp not set in jwt token")
            return fail_response

        user = token.claims.get("sub")
        role = token.claims.get("role")
        current_time = int(time.time())

        # if the jwt is expired
        expiration = int(token.claims.get("exp"))
        logger.debug(
            f"current time:   {datetime.fromtimestamp(current_time).strftime('%c')}"
        )
        logger.debug(
            f"jwt expires at: {datetime.fromtimestamp(expiration).strftime('%c')}"
        )
        logger.debug(
            f"jwt refresh at: {datetime.fromtimestamp(expiration - JWT_REFRESH).strftime('%c')}"
        )
        if expiration <= current_time:
            logger.debug("jwt token expired")
            return fail_response

        # if the jwt cookie is expiring soon
        elif jwt_source == "cookie" and expiration - JWT_REFRESH <= current_time:
            logger.debug("jwt token expiring soon, refreshing cookie")
            # ensure the user hasn't been deleted
            try:
                User.get_by_id(user)
            except DoesNotExist:
                return fail_response
            new_expiration = current_time + JWT_SESSION_LENGTH
            new_encoded_jwt = create_encoded_jwt(
                user, role, new_expiration, request.app.jwt_token
            )
            set_jwt_cookie(
                success_response,
                JWT_COOKIE_NAME,
                new_encoded_jwt,
                new_expiration,
                JWT_COOKIE_SECURE,
            )

        success_response.headers["remote-user"] = user
        success_response.headers["remote-role"] = role
        return success_response
    except Exception as e:
        logger.error(f"Error parsing jwt: {e}")
        return fail_response


@router.get("/profile")
def profile(request: Request):
    username = request.headers.get("remote-user", "anonymous")
    role = request.headers.get("remote-role", "viewer")

    # Default response
    response_data = {"username": username, "role": role}

    # If the user is authenticated (not anonymous), check if 2FA is enabled
    if username != "anonymous":
        try:
            db_user = User.get_by_id(username)
            response_data["two_factor_enabled"] = db_user.two_factor_enabled
        except DoesNotExist:
            # If a user doesn't exist in DB, don't add the two_factor_enabled field
            logger.debug(f"User not found in database: {username}")

    return JSONResponse(content=response_data)


@router.get("/logout")
def logout(request: Request):
    auth_config: AuthConfig = request.app.frigate_config.auth
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth_config.cookie_name)
    return response


limiter = Limiter(key_func=get_remote_addr)
from fastapi import Request

@router.post("/login")
@limiter.limit(limit_value=rateLimiter.get_limit)
def login(request: Request, body: AppPostLoginBody):
    JWT_COOKIE_NAME = request.app.frigate_config.auth.cookie_name
    JWT_COOKIE_SECURE = request.app.frigate_config.auth.cookie_secure
    JWT_SESSION_LENGTH = request.app.frigate_config.auth.session_length
    DEVICE_TOKEN_COOKIE_NAME = f"{JWT_COOKIE_NAME}_device"
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled
    user = body.user
    password = body.password

    # Generic error response for all authentication failures
    auth_failed_response = JSONResponse(content={"message": "Invalid credentials"}, status_code=401)

    try:
        db_user: User = User.get_by_id(user)
    except DoesNotExist:
        # Use a constant-time comparison to mitigate timing attacks
        # This simulates the password verification process even when the user doesn't exist
        verify_password("dummy_password", "$sha256$600000$dummy_salt$dummy_hash")
        return auth_failed_response

    password_hash = db_user.password_hash
    if verify_password(password, password_hash):
        # Check if 2FA is enabled globally and for this user
        if TWO_FACTOR_ENABLED and db_user.two_factor_enabled:
            # Check if there's a valid device token in the cookies
            device_token = request.cookies.get(DEVICE_TOKEN_COOKIE_NAME)
            if device_token and validate_device_token(user, device_token):
                logger.info(f"Valid device token found for user {user}, bypassing 2FA")
                # If a valid device token is found, bypass 2FA
                role = getattr(db_user, "role", "viewer")
                if role not in ["admin", "viewer"]:
                    role = "viewer"  # Enforce valid roles
                expiration = int(time.time()) + JWT_SESSION_LENGTH
                encoded_jwt = create_encoded_jwt(user, role, expiration, request.app.jwt_token)
                response = Response("", 200)
                set_jwt_cookie(
                    response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE
                )
                return response
            else:
                # Return a response indicating 2FA is required
                return JSONResponse(
                    content={
                        "message": "Two-factor authentication required",
                        "requires_2fa": True,
                        "user": user,
                    },
                    status_code=200,
                )

        # If 2FA is not enabled (either globally or for this user), proceed with normal login
        role = getattr(db_user, "role", "viewer")
        if role not in ["admin", "viewer"]:
            role = "viewer"  # Enforce valid roles
        expiration = int(time.time()) + JWT_SESSION_LENGTH
        encoded_jwt = create_encoded_jwt(user, role, expiration, request.app.jwt_token)
        response = Response("", 200)
        set_jwt_cookie(
            response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE
        )
        return response
    return auth_failed_response


@router.get("/users", dependencies=[Depends(require_role(["admin"]))])
def get_users():
    exports = (
        User.select(User.username, User.role, User.two_factor_enabled).order_by(User.username).dicts().iterator()
    )
    return JSONResponse([e for e in exports])


@router.post("/users", dependencies=[Depends(require_role(["admin"]))])
def create_user(
    request: Request,
    body: AppPostUsersBody,
):
    HASH_ITERATIONS = request.app.frigate_config.auth.hash_iterations

    if not re.match("^[A-Za-z0-9._]+$", body.username):
        return JSONResponse(content={"message": "Invalid username"}, status_code=400)

    role = body.role if body.role in ["admin", "viewer"] else "viewer"
    password_hash = hash_password(body.password, iterations=HASH_ITERATIONS)
    User.insert(
        {
            User.username: body.username,
            User.password_hash: password_hash,
            User.role: role,
            User.notification_tokens: [],
        }
    ).execute()
    return JSONResponse(content={"username": body.username})


@router.delete("/users/{username}")
def delete_user(username: str):
    User.delete_by_id(username)
    return JSONResponse(content={"success": True})


@router.put("/users/{username}/password")
async def update_password(
    request: Request,
    username: str,
    body: AppPutPasswordBody,
):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        return current_user

    current_username = current_user.get("username")
    current_role = current_user.get("role")

    # viewers can only change their own password
    if current_role == "viewer" and current_username != username:
        raise HTTPException(
            status_code=403, detail="Viewers can only update their own password"
        )

    HASH_ITERATIONS = request.app.frigate_config.auth.hash_iterations

    password_hash = hash_password(body.password, iterations=HASH_ITERATIONS)
    User.set_by_id(username, {User.password_hash: password_hash})

    return JSONResponse(content={"success": True})


@router.put(
    "/users/{username}/role",
    dependencies=[Depends(require_role(["admin"]))],
)
async def update_role(
    request: Request,
    username: str,
    body: AppPutRoleBody,
):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        return current_user

    current_role = current_user.get("role")
    # viewers can't change anyone's role
    if current_role == "viewer":
        raise HTTPException(
            status_code=403, detail="Admin role is required to change user roles"
        )
    if username == "admin":
        return JSONResponse(
            content={"message": "Cannot modify admin user's role"}, status_code=403
        )
    if body.role not in ["admin", "viewer"]:
        return JSONResponse(
            content={"message": "Role must be 'admin' or 'viewer'"}, status_code=400
        )

    User.set_by_id(username, {User.role: body.role})
    return JSONResponse(content={"success": True})


@router.post("/verify-totp")
@limiter.limit(limit_value=rateLimiter.get_limit)
def verify_totp_code(request: Request, body: AppPostVerifyTotpBody):
    JWT_COOKIE_NAME = request.app.frigate_config.auth.cookie_name
    JWT_COOKIE_SECURE = request.app.frigate_config.auth.cookie_secure
    JWT_SESSION_LENGTH = request.app.frigate_config.auth.session_length
    TWO_FACTOR_CODE_VALIDITY = request.app.frigate_config.auth.two_factor.code_validity
    DEVICE_TOKEN_COOKIE_NAME = f"{JWT_COOKIE_NAME}_device"
    DEVICE_TOKEN_EXPIRY_DAYS = request.app.frigate_config.auth.two_factor.device_token_expiry_days
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled

    user = body.user
    totp_code = body.totp_code
    remember_device = body.remember_device

    # Generic error responses
    verification_failed = JSONResponse(content={"message": "Verification failed"}, status_code=401)
    config_error = JSONResponse(content={"message": "Authentication configuration error"}, status_code=400)

    # Check if 2FA is globally enabled
    if not TWO_FACTOR_ENABLED:
        logger.warning(f"Two-factor authentication is disabled globally")
        return JSONResponse(
            content={"message": "Two-factor authentication is disabled globally"},
            status_code=400
        )

    try:
        db_user: User = User.get_by_id(user)
        logger.info(f"Processing TOTP verification request")
    except DoesNotExist:
        logger.warning(f"Authentication error during TOTP verification")
        return verification_failed

    # Check if 2FA is enabled for the user
    if not db_user.two_factor_enabled:
        logger.warning(f"Two-factor authentication configuration error")
        return config_error

    # Check if the user has a TOTP secret
    if not db_user.two_factor_secret:
        logger.warning(f"Two-factor authentication configuration error")
        return config_error

    # Verify the TOTP code
    logger.info(f"Verifying TOTP code")
    if verify_totp(db_user.two_factor_secret, totp_code, TWO_FACTOR_CODE_VALIDITY, user):
        role = getattr(db_user, "role", "viewer")
        if role not in ["admin", "viewer"]:
            role = "viewer"  # Enforce valid roles
        expiration = int(time.time()) + JWT_SESSION_LENGTH
        encoded_jwt = create_encoded_jwt(user, role, expiration, request.app.jwt_token)
        response = Response("", 200)
        set_jwt_cookie(
            response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE
        )

        # Handle the "Remember this device" option
        if remember_device:
            logger.info(f"Remembering device for user {user}")

            # Generate a new device token
            device_token = generate_device_token()

            # Try to get a device name from the user agent
            user_agent = request.headers.get("user-agent", "Unknown Device")
            device_name = user_agent[:100] if user_agent else "Unknown Device"

            # Store the device token in the database
            if store_device_token(user, device_token, device_name, DEVICE_TOKEN_EXPIRY_DAYS):
                # Set a cookie with the device token
                device_token_expiry = int((datetime.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)).timestamp())
                set_device_token_cookie(
                    response,
                    DEVICE_TOKEN_COOKIE_NAME,
                    device_token,
                    device_token_expiry,
                    JWT_COOKIE_SECURE
                )
                logger.info(f"Device token cookie set for user {user}")
            else:
                logger.error(f"Failed to store device token for user {user}")

        logger.info(f"TOTP verification successful")
        return response

    logger.warning(f"Invalid TOTP verification code")
    return verification_failed


@router.post("/verify-recovery-code")
@limiter.limit(limit_value=rateLimiter.get_limit)
def verify_recovery_code_endpoint(request: Request, body: AppPostVerifyRecoveryCodeBody):
    JWT_COOKIE_NAME = request.app.frigate_config.auth.cookie_name
    JWT_COOKIE_SECURE = request.app.frigate_config.auth.cookie_secure
    JWT_SESSION_LENGTH = request.app.frigate_config.auth.session_length
    DEVICE_TOKEN_COOKIE_NAME = f"{JWT_COOKIE_NAME}_device"
    DEVICE_TOKEN_EXPIRY_DAYS = request.app.frigate_config.auth.two_factor.device_token_expiry_days
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled

    user = body.user
    recovery_code = body.recovery_code
    remember_device = body.remember_device

    # Generic error responses
    verification_failed = JSONResponse(content={"message": "Verification failed"}, status_code=401)
    config_error = JSONResponse(content={"message": "Authentication configuration error"}, status_code=400)

    # Check if 2FA is globally enabled
    if not TWO_FACTOR_ENABLED:
        logger.warning(f"Two-factor authentication is disabled globally")
        return JSONResponse(
            content={"message": "Two-factor authentication is disabled globally"},
            status_code=400
        )

    try:
        db_user: User = User.get_by_id(user)
        logger.info(f"Processing recovery code verification request")
    except DoesNotExist:
        logger.warning(f"Authentication error during recovery code verification")
        return verification_failed

    # Check if 2FA is enabled for the user
    if not db_user.two_factor_enabled:
        logger.warning(f"Two-factor authentication configuration error")
        return config_error

    # Check if the user has recovery codes
    if not db_user.recovery_codes:
        logger.warning(f"Recovery codes configuration error")
        return config_error

    # Verify the recovery code
    logger.info(f"Verifying recovery code")
    is_valid, updated_codes = verify_recovery_code(db_user.recovery_codes, recovery_code)

    if is_valid:
        # Update the recovery codes (removing the used one)
        User.set_by_id(user, {User.recovery_codes: updated_codes})
        logger.info(f"Updated recovery codes, {len(updated_codes)} codes remaining")

        role = getattr(db_user, "role", "viewer")
        if role not in ["admin", "viewer"]:
            role = "viewer"  # Enforce valid roles
        expiration = int(time.time()) + JWT_SESSION_LENGTH
        encoded_jwt = create_encoded_jwt(user, role, expiration, request.app.jwt_token)
        response = Response("", 200)
        set_jwt_cookie(
            response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE
        )

        # Handle the "Remember this device" option
        if remember_device:
            logger.info(f"Remembering device for user {user}")

            # Generate a new device token
            device_token = generate_device_token()

            # Try to get a device name from the user agent
            user_agent = request.headers.get("user-agent", "Unknown Device")
            device_name = user_agent[:100] if user_agent else "Unknown Device"

            # Store the device token in the database
            if store_device_token(user, device_token, device_name, DEVICE_TOKEN_EXPIRY_DAYS):
                # Set a cookie with the device token
                device_token_expiry = int((datetime.now() + timedelta(days=DEVICE_TOKEN_EXPIRY_DAYS)).timestamp())
                set_device_token_cookie(
                    response,
                    DEVICE_TOKEN_COOKIE_NAME,
                    device_token,
                    device_token_expiry,
                    JWT_COOKIE_SECURE
                )
                logger.info(f"Device token cookie set for user {user}")
            else:
                logger.error(f"Failed to store device token for user {user}")

        logger.info(f"Recovery code verification successful")
        return response

    logger.warning(f"Invalid recovery code verification")
    return verification_failed


@router.post("/two-factor/setup")
async def setup_two_factor(request: Request):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        return current_user

    # Check if 2FA is globally enabled
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled
    if not TWO_FACTOR_ENABLED:
        return JSONResponse(
            content={"message": "Two-factor authentication is disabled globally"},
            status_code=400
        )

    username = current_user.get("username")

    # Generate a new TOTP secret
    secret = generate_totp_secret()

    TWO_FACTOR_CODE_VALIDITY = request.app.frigate_config.auth.two_factor.code_validity
    # Generate the TOTP URI for QR code generation
    totp_uri = get_totp_uri(username, secret, TWO_FACTOR_CODE_VALIDITY)

    # Return the secret and URI (frontend will display QR code)
    return JSONResponse(content={
        "secret": secret,
        "uri": totp_uri
    })


@router.post("/two-factor/enable")
async def enable_two_factor(request: Request, body: AppPostEnableTwoFactorBody):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        logger.debug("Failed to get current user in two-factor/enable endpoint")
        return current_user

    # Check if 2FA is globally enabled
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled
    if not TWO_FACTOR_ENABLED:
        logger.debug("2FA is disabled globally")
        return JSONResponse(
            content={"message": "Two-factor authentication is disabled globally"},
            status_code=400
        )

    username = current_user.get("username")
    password = body.password
    totp_code = body.totp_code
    secret = body.secret

    logger.debug(f"Processing 2FA enable request")

    # Generic error responses
    auth_error = JSONResponse(content={"message": "Authentication error"}, status_code=401)
    config_error = JSONResponse(content={"message": "Configuration error"}, status_code=400)

    try:
        db_user: User = User.get_by_id(username)
        logger.debug(f"Processing user authentication")
    except DoesNotExist:
        logger.debug(f"Authentication error in 2FA enable request")
        return JSONResponse(content={"message": "Authentication error"}, status_code=401)

    # Check if 2FA is already enabled
    if db_user.two_factor_enabled:
        logger.debug(f"2FA already enabled")
        return config_error

    # Verify the password
    logger.debug(f"Verifying password")
    if not verify_password(password, db_user.password_hash):
        logger.debug(f"Invalid password")
        return auth_error

    # Verify the TOTP code
    TWO_FACTOR_CODE_VALIDITY = request.app.frigate_config.auth.two_factor.code_validity
    logger.debug(f"Verifying TOTP code")
    if not verify_totp(secret, totp_code, TWO_FACTOR_CODE_VALIDITY, username):
        logger.debug(f"Invalid TOTP code")
        return JSONResponse(content={"message": "Verification failed"}, status_code=401)

    logger.debug(f"TOTP code verification successful")

    # Generate recovery codes
    RECOVERY_CODES_COUNT = request.app.frigate_config.auth.two_factor.recovery_codes_count
    plain_codes, hashed_codes = generate_recovery_codes(RECOVERY_CODES_COUNT)
    logger.debug(f"Generated {len(plain_codes)} recovery codes")

    # Enable 2FA for the user
    logger.debug(f"Enabling 2FA")
    User.set_by_id(username, {
        User.two_factor_enabled: True,
        User.two_factor_secret: secret,
        User.recovery_codes: hashed_codes
    })
    logger.debug(f"2FA enabled successfully")

    return JSONResponse(content={
        "success": True,
        "recovery_codes": plain_codes
    })


@router.post("/two-factor/disable")
async def disable_two_factor(request: Request, body: AppPostDisableTwoFactorBody):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        logger.debug("Failed to get current user in two-factor/disable endpoint")
        return current_user

    username = current_user.get("username")
    password = body.password
    totp_code = body.totp_code
    recovery_code = body.recovery_code

    logger.debug(f"Processing 2FA disable request")

    # Generic error responses
    auth_error = JSONResponse(content={"message": "Authentication error"}, status_code=401)
    config_error = JSONResponse(content={"message": "Configuration error"}, status_code=400)
    verification_error = JSONResponse(content={"message": "Verification failed"}, status_code=401)

    try:
        db_user: User = User.get_by_id(username)
        logger.debug(f"Processing user authentication")
    except DoesNotExist:
        logger.debug(f"Authentication error in 2FA disable request")
        return auth_error

    # Check if 2FA is enabled
    if not db_user.two_factor_enabled:
        logger.debug(f"2FA not enabled")
        return config_error

    # Verify the password
    logger.debug(f"Verifying password")
    if not verify_password(password, db_user.password_hash):
        logger.debug(f"Invalid password")
        return auth_error

    # Verify either the TOTP code or recovery code
    is_valid = False
    TWO_FACTOR_CODE_VALIDITY = request.app.frigate_config.auth.two_factor.code_validity

    if totp_code:
        logger.debug(f"Verifying TOTP code")
        is_valid = verify_totp(db_user.two_factor_secret, totp_code, TWO_FACTOR_CODE_VALIDITY, username)
        if is_valid:
            logger.debug(f"TOTP code verification successful")
        else:
            logger.debug(f"Invalid TOTP code")
    elif recovery_code and db_user.recovery_codes:
        logger.debug(f"Verifying recovery code")
        is_valid, _ = verify_recovery_code(db_user.recovery_codes, recovery_code)
        if is_valid:
            logger.debug(f"Recovery code verification successful")
        else:
            logger.debug(f"Invalid recovery code")
    else:
        logger.debug(f"No verification code provided")

    if not is_valid:
        return verification_error

    # Disable 2FA for the user
    logger.debug(f"Disabling 2FA")
    User.set_by_id(username, {
        User.two_factor_enabled: False,
        User.two_factor_secret: None,
        User.recovery_codes: None
    })
    logger.debug(f"2FA disabled successfully")

    return JSONResponse(content={"success": True})


@router.put(
    "/users/{username}/two-factor/disable",
    dependencies=[Depends(require_role(["admin"]))],
)
async def admin_disable_two_factor(
    request: Request,
    username: str,
):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        return current_user

    current_role = current_user.get("role")
    # viewers can't disable 2FA for anyone
    if current_role == "viewer":
        raise HTTPException(
            status_code=403, detail="Admin role is required to disable two-factor authentication"
        )

    try:
        db_user: User = User.get_by_id(username)
    except DoesNotExist:
        return JSONResponse(
            content={"message": f"User {username} not found"}, status_code=404
        )

    # Check if 2FA is enabled for the user
    if not db_user.two_factor_enabled:
        return JSONResponse(
            content={"message": "Two-factor authentication is not enabled for this user"},
            status_code=400
        )

    # Disable 2FA for the user
    logger.debug(f"Admin disabling 2FA for user {username}")
    User.set_by_id(username, {
        User.two_factor_enabled: False,
        User.two_factor_secret: None,
        User.recovery_codes: None
    })
    logger.debug(f"2FA disabled successfully for user {username}")

    return JSONResponse(content={"success": True})


@router.post("/two-factor/recovery-codes")
async def generate_recovery_codes_endpoint(request: Request, body: AppPostGenerateRecoveryCodesBody):
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        # auth failed
        logger.debug("Failed to get current user in two-factor/recovery-codes endpoint")
        return current_user

    # Check if 2FA is globally enabled
    TWO_FACTOR_ENABLED = request.app.frigate_config.auth.two_factor.enabled
    if not TWO_FACTOR_ENABLED:
        logger.warning(f"Two-factor authentication is disabled globally")
        return JSONResponse(
            content={"message": "Two-factor authentication is disabled globally"},
            status_code=400
        )

    username = current_user.get("username")
    password = body.password

    logger.debug(f"Processing recovery codes generation request")

    # Generic error responses
    auth_error = JSONResponse(content={"message": "Authentication error"}, status_code=401)
    config_error = JSONResponse(content={"message": "Configuration error"}, status_code=400)

    try:
        db_user: User = User.get_by_id(username)
        logger.debug(f"Processing user authentication")
    except DoesNotExist:
        logger.debug(f"Authentication error in recovery codes generation request")
        return auth_error

    # Verify the password
    logger.debug(f"Verifying password")
    if not verify_password(password, db_user.password_hash):
        logger.debug(f"Invalid password")
        return auth_error

    # Check if 2FA is enabled
    if not db_user.two_factor_enabled:
        logger.debug(f"2FA not enabled")
        return config_error

    # Generate new recovery codes
    RECOVERY_CODES_COUNT = request.app.frigate_config.auth.two_factor.recovery_codes_count
    plain_codes, hashed_codes = generate_recovery_codes(RECOVERY_CODES_COUNT)
    logger.debug(f"Generated {len(plain_codes)} new recovery codes")

    # Update the user's recovery codes
    logger.debug(f"Updating recovery codes")
    User.set_by_id(username, {User.recovery_codes: hashed_codes})
    logger.debug(f"Recovery codes updated successfully")

    return JSONResponse(content={
        "success": True,
        "recovery_codes": plain_codes
    })
