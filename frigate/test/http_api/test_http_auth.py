import json
import unittest

import pyotp
from fastapi.testclient import TestClient

from frigate.api.auth import (
    generate_totp_secret,
    hash_password,
    hash_recovery_code,
    generate_device_token
)
from frigate.models import User
from frigate.test.http_api.base_http_test import BaseTestHttp


class TestHttpAuth(BaseTestHttp):
    def setUp(self):
        super().setUp([User])

        # The 2FA fields are now added in the BaseTestHttp.setUp() method if needed

        self.app = super().create_app()
        self.client = TestClient(self.app)

        # Create a test user with a known password
        self.test_username = "testuser"
        self.test_password = "testpassword"
        self.test_password_hash = hash_password(self.test_password)

        # Insert the test user into the database
        User.insert(
            username=self.test_username,
            password_hash=self.test_password_hash,
            role="admin",
            notification_tokens=[],
            two_factor_enabled=False,
            two_factor_secret=None,
            recovery_codes=None
        ).execute()

        # Login to get a session cookie
        response = self.client.post(
            "/api/login",
            json={"username": self.test_username, "password": self.test_password}
        )
        self.assertEqual(response.status_code, 200)
        self.cookies = response.cookies

    def test_setup_two_factor(self):
        """Test the setup_two_factor endpoint."""
        response = self.client.get(
            "/api/setup-two-factor",
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check that the response contains the expected fields
        self.assertIn("secret", data)
        self.assertIn("qr_code", data)

        # Verify that the secret is a valid base32 string
        self.assertTrue(all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in data["secret"]))

        # Verify that the QR code is a data URL for an image
        self.assertTrue(data["qr_code"].startswith("data:image/png;base64,"))

    def test_enable_two_factor(self):
        """Test the enable_two_factor endpoint."""
        # First, get a secret from the setup endpoint
        setup_response = self.client.get(
            "/api/setup-two-factor",
            cookies=self.cookies
        )
        setup_data = setup_response.json()
        secret = setup_data["secret"]

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Enable 2FA with the valid code
        response = self.client.post(
            "/api/enable-two-factor",
            json={"totp_code": valid_code},
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check that the response contains recovery codes
        self.assertIn("recovery_codes", data)
        self.assertEqual(len(data["recovery_codes"]), 10)  # Default is 10 recovery codes

        # Verify that 2FA is now enabled for the user
        user = User.get(User.username == self.test_username)
        self.assertTrue(user.two_factor_enabled)
        self.assertEqual(user.two_factor_secret, secret)
        self.assertEqual(len(json.loads(user.recovery_codes)), 10)

    def test_enable_two_factor_invalid_code(self):
        """Test the enable_two_factor endpoint with an invalid TOTP code."""
        # First, get a secret from the setup endpoint
        setup_response = self.client.get(
            "/api/setup-two-factor",
            cookies=self.cookies
        )

        # Try to enable 2FA with an invalid code
        response = self.client.post(
            "/api/enable-two-factor",
            json={"totp_code": "000000"},  # Invalid code
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 401)

        # Verify that 2FA is still disabled for the user
        user = User.get(User.username == self.test_username)
        self.assertFalse(user.two_factor_enabled)

    def test_verify_totp_code(self):
        """Test the verify_totp_code endpoint."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify the TOTP code
        response = self.client.post(
            "/api/verify-totp",
            json={"user": self.test_username, "totp_code": valid_code}
        )

        self.assertEqual(response.status_code, 200)

    def test_verify_totp_code_invalid(self):
        """Test the verify_totp_code endpoint with an invalid code."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Try to verify with an invalid code
        response = self.client.post(
            "/api/verify-totp",
            json={"user": self.test_username, "totp_code": "000000"}  # Invalid code
        )

        self.assertEqual(response.status_code, 401)

    def test_verify_recovery_code(self):
        """Test the verify_recovery_code endpoint."""
        # First, enable 2FA for the user with known recovery codes
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2", "CODE3"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Verify a valid recovery code
        response = self.client.post(
            "/api/verify-recovery-code",
            json={"user": self.test_username, "recovery_code": "CODE1"}
        )

        self.assertEqual(response.status_code, 200)

        # Check that the recovery code was removed
        user = User.get(User.username == self.test_username)
        updated_codes = json.loads(user.recovery_codes)
        self.assertEqual(len(updated_codes), 2)
        # Since we're now storing hashed codes, we can't directly check for the plain code.
        # Instead, we check that the number of codes decreased by 1
        self.assertEqual(len(updated_codes), len(hashed_codes) - 1)

    def test_verify_recovery_code_invalid(self):
        """Test the verify_recovery_code endpoint with an invalid code."""
        # First, enable 2FA for the user with known recovery codes
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2", "CODE3"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Try to verify with an invalid recovery code
        response = self.client.post(
            "/api/verify-recovery-code",
            json={"user": self.test_username, "recovery_code": "INVALID"}
        )

        self.assertEqual(response.status_code, 401)

        # Check that the recovery codes are unchanged
        user = User.get(User.username == self.test_username)
        updated_codes = json.loads(user.recovery_codes)
        self.assertEqual(len(updated_codes), 3)
        # Since we're now storing hashed codes, we can't directly compare the sets
        # Instead, we check that the number of codes is the same
        self.assertEqual(len(updated_codes), len(hashed_codes))

    def test_disable_two_factor(self):
        """Test the disable_two_factor endpoint."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Disable 2FA with the valid code
        response = self.client.post(
            "/api/disable-two-factor",
            json={"totp_code": valid_code},
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)

        # Verify that 2FA is now disabled for the user
        user = User.get(User.username == self.test_username)
        self.assertFalse(user.two_factor_enabled)
        self.assertIsNone(user.two_factor_secret)
        self.assertIsNone(user.recovery_codes)

    def test_disable_two_factor_with_recovery_code(self):
        """Test the disable_two_factor endpoint using a recovery code."""
        # First, enable 2FA for the user with known recovery codes
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2", "CODE3"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Disable 2FA with a recovery code
        response = self.client.post(
            "/api/disable-two-factor",
            json={"recovery_code": "CODE1"},
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)

        # Verify that 2FA is now disabled for the user
        user = User.get(User.username == self.test_username)
        self.assertFalse(user.two_factor_enabled)
        self.assertIsNone(user.two_factor_secret)
        self.assertIsNone(user.recovery_codes)

    def test_generate_recovery_codes(self):
        """Test the generate_recovery_codes endpoint."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        initial_plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        initial_hashed_codes = [hash_recovery_code(code) for code in initial_plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(initial_hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Generate new recovery codes
        response = self.client.post(
            "/api/generate-recovery-codes",
            json={"totp_code": valid_code},
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check that the response contains new recovery codes
        self.assertIn("recovery_codes", data)
        self.assertEqual(len(data["recovery_codes"]), 10)  # Default is 10 recovery codes

        # Verify that the recovery codes were updated in the database
        user = User.get(User.username == self.test_username)
        updated_codes = json.loads(user.recovery_codes)
        self.assertEqual(len(updated_codes), 10)

        # Since we're now storing hashed codes, we can't directly check for the plain codes.
        # Instead, we check that the number of codes is correct, and they're all in the expected format
        for code in updated_codes:
            # Check that each code is a hashed code (contains 3 $ characters)
            self.assertEqual(code.count('$'), 3)

    def test_generate_recovery_codes_with_recovery_code(self):
        """Test the generate_recovery_codes endpoint using a recovery code."""
        # First, enable 2FA for the user with known recovery codes
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2", "CODE3"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes)
        ).where(User.username == self.test_username).execute()

        # Generate new recovery codes with a recovery code
        response = self.client.post(
            "/api/generate-recovery-codes",
            json={"recovery_code": "CODE1"},
            cookies=self.cookies
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Check that the response contains new recovery codes
        self.assertIn("recovery_codes", data)
        self.assertEqual(len(data["recovery_codes"]), 10)  # Default is 10 recovery codes

        # Verify that the recovery codes were updated in the database
        user = User.get(User.username == self.test_username)
        updated_codes = json.loads(user.recovery_codes)
        self.assertEqual(len(updated_codes), 10)

        # Since we're now storing hashed codes, we can't directly check for the plain codes.
        # Instead, we check that the number of codes is correct, and they're all in the expected format
        for code in updated_codes:
            # Check that each code is a hashed code (contains 3 $ characters)
            self.assertEqual(code.count('$'), 3)

    def test_verify_totp_with_remember_device(self):
        """Test the verify_totp endpoint with the remember_device option."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes),
            device_tokens=json.dumps([])  # Initialize with empty device tokens
        ).where(User.username == self.test_username).execute()

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify the TOTP code with remember_device=True
        response = self.client.post(
            "/api/verify-totp",
            json={
                "user": self.test_username, 
                "totp_code": valid_code,
                "remember_device": True
            }
        )

        self.assertEqual(response.status_code, 200)

        # Check that a device token cookie was set
        self.assertIn("frigate_jwt_device", response.cookies)

        # Verify that a device token was stored in the database
        user = User.get(User.username == self.test_username)
        device_tokens = json.loads(user.device_tokens)
        self.assertEqual(len(device_tokens), 1)
        self.assertIn("token", device_tokens[0])
        self.assertIn("device_name", device_tokens[0])
        self.assertIn("created_at", device_tokens[0])
        self.assertIn("expires_at", device_tokens[0])
        self.assertIn("last_used", device_tokens[0])

    def test_verify_recovery_code_with_remember_device(self):
        """Test the verify_recovery_code endpoint with the remember_device option."""
        # First, enable 2FA for the user with known recovery codes
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2", "CODE3"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]
        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes),
            device_tokens=json.dumps([])  # Initialize with empty device tokens
        ).where(User.username == self.test_username).execute()

        # Verify a valid recovery code with remember_device=True
        response = self.client.post(
            "/api/verify-recovery-code",
            json={
                "user": self.test_username, 
                "recovery_code": "CODE1",
                "remember_device": True
            }
        )

        self.assertEqual(response.status_code, 200)

        # Check that a device token cookie was set
        self.assertIn("frigate_jwt_device", response.cookies)

        # Verify that a device token was stored in the database
        user = User.get(User.username == self.test_username)
        device_tokens = json.loads(user.device_tokens)
        self.assertEqual(len(device_tokens), 1)
        self.assertIn("token", device_tokens[0])
        self.assertIn("device_name", device_tokens[0])
        self.assertIn("created_at", device_tokens[0])
        self.assertIn("expires_at", device_tokens[0])
        self.assertIn("last_used", device_tokens[0])

        # Check that the recovery code was removed
        updated_codes = json.loads(user.recovery_codes)
        self.assertEqual(len(updated_codes), 2)

    def test_login_with_device_token(self):
        """Test logging in with a valid device token (bypassing 2FA)."""
        # First, enable 2FA for the user
        secret = generate_totp_secret()
        plain_codes = ["CODE1", "CODE2"]
        # Hash the recovery codes before storing them
        hashed_codes = [hash_recovery_code(code) for code in plain_codes]

        # Generate and store a device token
        device_token = generate_device_token()
        import time
        from datetime import datetime, timedelta
        current_time = int(time.time())
        # Use the device_token_expiry_days from the app's configuration (default is 30)
        device_token_expiry_days = self.app.frigate_config.auth.two_factor.device_token_expiry_days
        expiry_time = int((datetime.now() + timedelta(days=device_token_expiry_days)).timestamp())

        device_tokens = [{
            'token': device_token,
            'device_name': 'Test Device',
            'created_at': current_time,
            'expires_at': expiry_time,
            'last_used': current_time
        }]

        User.update(
            two_factor_enabled=True,
            two_factor_secret=secret,
            recovery_codes=json.dumps(hashed_codes),
            device_tokens=json.dumps(device_tokens)
        ).where(User.username == self.test_username).execute()

        # Create a client with the device token cookie
        client = TestClient(self.app)
        client.cookies.set("frigate_jwt_device", device_token)

        # Try to log in (should bypass 2FA)
        response = client.post(
            "/api/login",
            json={"user": self.test_username, "password": self.test_password}
        )

        self.assertEqual(response.status_code, 200)

        # Verify that the response doesn't indicate 2FA is required
        self.assertNotIn("requires_2fa", response.json())

        # Check that a JWT cookie was set (successful login)
        self.assertIn("frigate_jwt", response.cookies)

        # Verify that the device token's last_used timestamp was updated
        user = User.get(User.username == self.test_username)
        updated_device_tokens = json.loads(user.device_tokens)
        self.assertEqual(len(updated_device_tokens), 1)
        self.assertGreater(updated_device_tokens[0]['last_used'], current_time)


if __name__ == "__main__":
    unittest.main()
