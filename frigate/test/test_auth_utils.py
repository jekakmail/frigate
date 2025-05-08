import unittest
import re
import pyotp
import time
from unittest.mock import patch, MagicMock

from frigate.api.auth import (
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    generate_recovery_codes,
    verify_recovery_code,
    generate_device_token,
    store_device_token,
    validate_device_token,
)


class TestAuthUtils(unittest.TestCase):
    def test_generate_totp_secret(self):
        """Test that generate_totp_secret returns a valid base32 string."""
        secret = generate_totp_secret()
        # Check that the secret is a string
        self.assertIsInstance(secret, str)
        # Check that the secret is a valid base32 string (only A-Z and 2-7)
        self.assertTrue(re.match(r'^[A-Z2-7]+$', secret))
        # Check that the secret is 32 characters long (common for TOTP secrets)
        self.assertEqual(len(secret), 32)

    def test_get_totp_uri(self):
        """Test that get_totp_uri returns a valid TOTP URI."""
        username = "testuser"
        secret = generate_totp_secret()
        validity_period = 30
        issuer = "Frigate"

        uri = get_totp_uri(username, secret, validity_period, issuer=issuer)

        # Check that the URI starts with the correct scheme
        self.assertTrue(uri.startswith("otpauth://totp/"))
        # Check that the URI contains the username
        self.assertIn(username, uri)
        # Check that the URI contains the issuer
        self.assertIn(issuer, uri)
        # Check that the URI contains the secret
        self.assertIn(f"secret={secret}", uri)

        # Verify that the URI is valid by parsing it with pyotp
        totp = pyotp.parse_uri(uri)
        self.assertEqual(totp.secret, secret)
        # The name format depends on the pyotp version, so we just check that it contains the username
        self.assertIn(username, totp.name)

    def test_verify_totp_valid_code(self):
        """Test that verify_totp returns True for a valid TOTP code."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        username = "testuser"

        result = verify_totp(secret, valid_code, validity_period=30, username=username)

        self.assertTrue(result)

    def test_verify_totp_invalid_code(self):
        """Test that verify_totp returns False for an invalid TOTP code."""
        secret = generate_totp_secret()
        invalid_code = "000000"  # Assuming this is not the current valid code
        username = "testuser"

        result = verify_totp(secret, invalid_code, validity_period=30, username=username)

        self.assertFalse(result)

    def test_verify_totp_with_custom_validity_period(self):
        """Test that verify_totp respects the custom validity period."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        base_time = int(time.time())

        # Test code from the current time
        current_code = totp.at(base_time)
        result_current = verify_totp(secret, current_code, validity_period=30)
        self.assertTrue(result_current)

        # Test code from the 60s in the future (should be valid with 120s validity)
        future_code = totp.at(base_time + 60)
        result_future = verify_totp(secret, future_code, validity_period=120)
        self.assertTrue(result_future)

        # Test code from 150s in the future (should be invalid even with 120s validity)
        far_future_code = totp.at(base_time + 150)
        result_far_future = verify_totp(secret, far_future_code, validity_period=120)
        self.assertFalse(result_far_future)

        # Test code from the past (should be invalid)
        past_code = totp.at(base_time - 60)
        result_past = verify_totp(secret, past_code, validity_period=30)
        self.assertFalse(result_past)

    def test_generate_recovery_codes(self):
        """Test that generate_recovery_codes returns the correct number of codes with the expected format."""
        count = 10
        plain_codes, hashed_codes = generate_recovery_codes(count)

        # Check that the correct number of codes is generated
        self.assertEqual(len(plain_codes), count)
        self.assertEqual(len(hashed_codes), count)

        # Check that each code has the expected format (XXXX-XXXX-XX)
        for code in plain_codes:
            self.assertTrue(re.match(r'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{2}$', code))

        # Check that all codes are unique
        self.assertEqual(len(set(plain_codes)), count)

    def test_verify_recovery_code_valid(self):
        """Test that verify_recovery_code returns True for a valid recovery code and removes it from the list."""
        plain_codes, hashed_codes = generate_recovery_codes(10)
        code_to_verify = plain_codes[0]

        result, updated_codes = verify_recovery_code(hashed_codes, code_to_verify)

        self.assertTrue(result)
        self.assertEqual(len(updated_codes), 9)  # One code should be removed
        # We can't directly check if code_to_verify is not in updated_codes because updated_codes contains hashed values

    def test_verify_recovery_code_invalid(self):
        """Test that verify_recovery_code returns False for an invalid recovery code and doesn't modify the list."""
        plain_codes, hashed_codes = generate_recovery_codes(10)
        invalid_code = "INVALID123"  # A code that's not in the list

        result, updated_codes = verify_recovery_code(hashed_codes, invalid_code)

        self.assertFalse(result)
        self.assertEqual(len(updated_codes), 10)  # No codes should be removed
        self.assertEqual(updated_codes, hashed_codes)  # The list should be unchanged

    def test_verify_recovery_code_case_insensitive(self):
        """Test that verify_recovery_code is case-insensitive."""
        plain_codes, hashed_codes = generate_recovery_codes(10)
        code_to_verify = plain_codes[0].lower()  # Convert to lowercase

        result, updated_codes = verify_recovery_code(hashed_codes, code_to_verify)

        self.assertTrue(result)
        self.assertEqual(len(updated_codes), 9)  # One code should be removed

    def test_verify_recovery_code_whitespace_insensitive(self):
        """Test that verify_recovery_code ignores whitespace."""
        plain_codes, hashed_codes = generate_recovery_codes(10)
        code_to_verify = " " + plain_codes[0] + " "  # Add whitespace

        result, updated_codes = verify_recovery_code(hashed_codes, code_to_verify)

        self.assertTrue(result)
        self.assertEqual(len(updated_codes), 9)  # One code should be removed

    def test_generate_device_token(self):
        """Test that generate_device_token returns a valid UUID string."""
        token = generate_device_token()

        # Check that the token is a string
        self.assertIsInstance(token, str)

        # Check that the token is a valid UUID (format: 8-4-4-4-12 hexadecimal digits)
        self.assertTrue(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', token))

    @patch('frigate.api.auth.User')
    def test_store_device_token(self, mock_user):
        """Test that store_device_token correctly stores a token for a user."""
        # Setup mock
        mock_user_instance = MagicMock()
        mock_user_instance.device_tokens = []
        mock_user.get_by_id.return_value = mock_user_instance

        # Test parameters
        username = "testuser"
        token = generate_device_token()
        device_name = "Test Device"
        expiry_days = 30

        # Call the function
        result = store_device_token(username, token, device_name, expiry_days)

        # Verify the result
        self.assertTrue(result)

        # Verify that User.get_by_id was called with the correct username
        mock_user.get_by_id.assert_called_once_with(username)

        # Verify that User.set_by_id was called to update the user's device tokens
        mock_user.set_by_id.assert_called_once()

        # Verify the call arguments
        args, kwargs = mock_user.set_by_id.call_args
        self.assertEqual(args[0], username)

        # Check that the device token was added to the list
        device_tokens = list(kwargs.values())[0]
        self.assertEqual(len(device_tokens), 1)
        self.assertEqual(device_tokens[0]['token'], token)
        self.assertEqual(device_tokens[0]['device_name'], device_name)

    @patch('frigate.api.auth.User')
    def test_validate_device_token_valid(self, mock_user):
        """Test that validate_device_token returns True for a valid token."""
        # Setup mock
        mock_user_instance = MagicMock()
        token = generate_device_token()
        current_time = int(time.time())
        expiry_time = current_time + (30 * 24 * 60 * 60)  # 30 days in the future

        mock_user_instance.device_tokens = [{
            'token': token,
            'device_name': 'Test Device',
            'created_at': current_time,
            'expires_at': expiry_time,
            'last_used': current_time
        }]
        mock_user_instance.two_factor_enabled = True
        mock_user.get_by_id.return_value = mock_user_instance

        # Test parameters
        username = "testuser"

        # Call the function
        result = validate_device_token(username, token)

        # Verify the result
        self.assertTrue(result)

        # Verify that User.get_by_id was called with the correct username
        mock_user.get_by_id.assert_called_with(username)

        # Verify that User.set_by_id was called to update the last_used timestamp
        mock_user.set_by_id.assert_called_once()

    @patch('frigate.api.auth.User')
    def test_validate_device_token_invalid(self, mock_user):
        """Test that validate_device_token returns False for an invalid token."""
        # Setup mock
        mock_user_instance = MagicMock()
        valid_token = generate_device_token()
        invalid_token = generate_device_token()  # Different token
        current_time = int(time.time())
        expiry_time = current_time + (30 * 24 * 60 * 60)  # 30 days in the future

        mock_user_instance.device_tokens = [{
            'token': valid_token,
            'device_name': 'Test Device',
            'created_at': current_time,
            'expires_at': expiry_time,
            'last_used': current_time
        }]
        mock_user_instance.two_factor_enabled = True
        mock_user.get_by_id.return_value = mock_user_instance

        # Test parameters
        username = "testuser"

        # Call the function with an invalid token
        result = validate_device_token(username, invalid_token)

        # Verify the result
        self.assertFalse(result)

        # Verify that User.get_by_id was called with the correct username
        mock_user.get_by_id.assert_called_with(username)

    @patch('frigate.api.auth.User')
    def test_validate_device_token_expired(self, mock_user):
        """Test that validate_device_token returns False for an expired token."""
        # Setup mock
        mock_user_instance = MagicMock()
        token = generate_device_token()
        current_time = int(time.time())
        expiry_time = current_time - 3600  # 1 hour in the past (expired)

        mock_user_instance.device_tokens = [{
            'token': token,
            'device_name': 'Test Device',
            'created_at': current_time - (31 * 24 * 60 * 60),  # 31 days ago
            'expires_at': expiry_time,
            'last_used': current_time - (15 * 24 * 60 * 60)  # 15 days ago
        }]
        mock_user_instance.two_factor_enabled = True
        mock_user.get_by_id.return_value = mock_user_instance

        # Test parameters
        username = "testuser"

        # Call the function
        result = validate_device_token(username, token)

        # Verify the result
        self.assertFalse(result)

        # Verify that User.get_by_id was called with the correct username
        mock_user.get_by_id.assert_called_with(username)

        # Verify that User.set_by_id was called to remove the expired token
        mock_user.set_by_id.assert_called_once()

        # Verify the call arguments - should be updating with an empty list
        args, kwargs = mock_user.set_by_id.call_args
        self.assertEqual(args[0], username)
        device_tokens = list(kwargs.values())[0]
        self.assertEqual(len(device_tokens), 0)


if __name__ == "__main__":
    unittest.main()
