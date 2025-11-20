# tesla-auth-py

A Python implementation of the Tesla authentication client that securely generates API tokens for third-party access to your Tesla account.

This is a simplified command-line version of the Rust implementation, implementing the same OAuth2 with PKCE authentication flow.

## Features

- OAuth2 authentication with PKCE (Proof Key for Code Exchange)
- Support for both global (auth.tesla.com) and China (auth.tesla.cn) endpoints
- CSRF protection with state validation
- Multi-factor authentication (MFA) and Captcha support through browser
- Secure token generation

## Requirements

- Python 3.7+
- `requests` library

## Installation

### From PyPI (when published)

```bash
pip install tesla-auth-py
```

### From source

```bash
# Clone the repository
git clone https://github.com/haim0n/tesla_auth
cd tesla_auth

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### Manual installation

```bash
pip install -r requirements.txt
```

## Usage

If installed via pip:

```bash
tesla-auth-py
```

Or run directly:

```bash
python tesla_auth.py
```

With debug output:

```bash
tesla-auth-py --debug
# or
python tesla_auth.py --debug
```

### Command-line Options

```
usage: tesla_auth.py [-h] [-d]

Tesla API tokens generator

options:
  -h, --help   show this help message and exit
  -d, --debug  print debug output
```

### Steps

1. Run the script
2. Your default browser will open with the Tesla login page
3. Log in with your Tesla credentials (MFA if enabled)
4. After successful login, you'll be redirected to a Tesla callback URL
5. Copy the **entire URL** from your browser's address bar
6. Paste it into the terminal when prompted
7. The script will exchange the authorization code for access and refresh tokens
8. Tokens will be displayed in the terminal

## How It Works

The implementation follows the OAuth2 authorization code flow with PKCE:

1. **Generate PKCE parameters**: Creates a code verifier and code challenge
2. **Generate state**: Creates a random state for CSRF protection
3. **Build authorization URL**: Constructs the OAuth URL with all required parameters
4. **User authentication**: Opens browser for user to log in
5. **Authorization code exchange**: Exchanges the code for access and refresh tokens
6. **Token validation**: Validates the response and extracts tokens

## Security Notes

- The code verifier is never transmitted; only the SHA256 hash (code challenge) is sent
- State parameter prevents CSRF attacks
- Tokens are only displayed locally and not stored anywhere
- Communication happens over HTTPS

## Differences from Rust Implementation

This Python version is a simplified implementation:

1. **No GUI WebView**: Uses the system browser instead of an embedded WebView
2. **Manual callback handling**: User must copy/paste the callback URL manually
3. **No browsing data management**: Doesn't handle clearing browsing data
4. **Simpler error handling**: More basic error messages
5. **No menu system**: Command-line only

For a full-featured GUI application with embedded WebView, use the original Rust implementation.

## Example Output

```
Tesla Authentication
================================================================================

Opening Tesla login page in your browser...

NOTE: This is a simplified implementation.
After logging in, you will be redirected to Tesla's void callback page.

To complete authentication, you need to:
1. Log in to your Tesla account in the browser
2. Copy the FULL URL from the address bar after redirect
3. Paste it below

Paste the full callback URL here: https://auth.tesla.com/void/callback?code=...

Retrieving tokens...

--------------------------------- ACCESS TOKEN ---------------------------------

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...

--------------------------------- REFRESH TOKEN --------------------------------

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...

----------------------------------- VALID FOR ----------------------------------

45 days
```

## Troubleshooting

### "CSRF state does not match" error

This means the state parameter in the callback doesn't match the one generated. This could indicate:
- You copied an old/incorrect callback URL
- Potential security issue (CSRF attack)

Solution: Restart the script and try again.

### "Missing required parameters" error

The callback URL you pasted is incomplete or invalid.

Solution: Make sure to copy the ENTIRE URL from the address bar, including all query parameters.

### Connection errors

Check your internet connection and ensure you can access auth.tesla.com.

## License

GPL-3.0

## Credits

Based on the [tesla_auth](https://github.com/adriankumpf/tesla_auth) Rust implementation by Adrian Kumpf.
