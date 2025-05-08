# Two-Factor Authentication

Two-factor authentication (2FA) adds an extra layer of security to your Frigate installation by requiring a second form of verification in addition to your password. Frigate supports Time-based One-Time Password (TOTP) authentication, which is compatible with authenticator apps like Google Authenticator, Authy, and Microsoft Authenticator.

## Requirements

To use two-factor authentication, you need:

1. A TOTP-compatible authenticator app installed on your mobile device, such as:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
   - FreeOTP
   - AndOTP

## Configuration

Two-factor authentication can be configured in the Frigate configuration file:

```yaml
auth:
  # Two-factor authentication settings
  two_factor:
    # Enable or disable two-factor authentication functionality
    enabled: true

    # Validity period for TOTP codes in seconds (30-120)
    code_validity: 30

    # Number of recovery codes to generate (5-20)
    recovery_codes_count: 10

    # Number of days before device tokens expire (1-365)
    device_token_expiry_days: 30
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `auth.two_factor.enabled` | `true` | If set to `false`, two-factor authentication functionality will be disabled for all users. |
| `auth.two_factor.code_validity` | `30` | The validity period for TOTP codes in seconds. Valid values are between 30 and 120 seconds. |
| `auth.two_factor.recovery_codes_count` | `10` | The number of recovery codes to generate for each user. Valid values are between 5 and 20. |
| `auth.two_factor.device_token_expiry_days` | `30` | The number of days before "Remember this device" tokens expire. Valid values are between 1 and 365 days. |

## Setting Up Two-Factor Authentication

1. Log in to your Frigate account.
2. Go to your account settings.
3. Click on "Security".
4. Click "Set up two-factor authentication".
5. Scan the QR code with your authenticator app.
6. Enter the verification code from your authenticator app.
7. Save your recovery codes in a safe place. These codes can be used to log in if you lose access to your authenticator app.

## Logging In with Two-Factor Authentication

1. Enter your username and password as usual.
2. If 2FA is enabled for your account, you'll be prompted to enter a verification code.
3. Open your authenticator app and enter the code it displays for Frigate.
4. If the code is correct, you'll be logged in.

## Remember This Device Feature

Frigate includes a "Remember this device" option during the two-factor authentication process. This feature allows you to bypass 2FA on trusted devices for a period of time.

### How It Works

1. When logging in with 2FA, you'll see a "Remember this device" checkbox.
2. If you check this box before entering your verification code, Frigate will:
   - Generate a secure device token
   - Store this token in your browser as a cookie
   - Associate the token with your account
3. On subsequent logins from the same device and browser, Frigate will:
   - Check for the presence of the device token
   - Validate the token against your account
   - If valid, bypass the 2FA step entirely

### Benefits

- Improved user experience on personal or trusted devices
- Reduced friction for frequent logins
- Still maintains the security benefits of 2FA for new or untrusted devices

### Security Considerations

- Device tokens are valid for 30 days by default (configurable via `auth.two_factor.device_token_expiry_days`)
- Each device gets its own unique token
- Tokens are stored securely with HTTP-only cookies
- Tokens are automatically invalidated after their expiration period
- If your account is compromised, an attacker would still need access to your physical device to bypass 2FA

### Configuration

The "Remember this device" feature uses the following default settings:

| Setting | Default Value | Description |
|---------|---------------|-------------|
| Token validity | 30 days | How long a device remains trusted before requiring 2FA again (configurable via `auth.two_factor.device_token_expiry_days`) |
| Cookie security | HTTP-only, SameSite=Lax | Security settings for the device token cookie |

## Using Recovery Codes

If you lose access to your authenticator app, you can use one of your recovery codes to log in:

1. Enter your username and password.
2. When prompted for a verification code, click "Use recovery code".
3. Enter one of your recovery codes.
4. If the code is correct, you'll be logged in.

Note that each recovery code can only be used once. After using a recovery code, it's recommended to disable and re-enable 2FA to generate new recovery codes.

## Disabling Two-Factor Authentication

1. Log in to your Frigate account.
2. Go to your account settings.
3. Click on "Security".
4. Click "Disable two-factor authentication".
5. Confirm by entering your password and a verification code or recovery code.

## API Endpoints

The following API endpoints are available for managing two-factor authentication:

- `POST /two-factor/setup`: Initiates 2FA setup by generating a secret and URI for QR code generation.
- `POST /two-factor/enable`: Enables 2FA for a user.
- `POST /two-factor/disable`: Disables 2FA for a user.
- `POST /two-factor/recovery-codes`: Generates new recovery codes.
- `POST /verify-totp`: Verifies a TOTP code during login.
- `POST /verify-recovery-code`: Verifies a recovery code during login.
