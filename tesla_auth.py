#!/usr/bin/env python3
"""
tesla-auth-py - Python implementation of Tesla authentication
Securely generate API tokens for third-party access to your Tesla.
"""

__version__ = "0.1.0"

import argparse
import hashlib
import logging
import secrets
import sys
import webbrowser
from base64 import urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

import requests


# Constants
CLIENT_ID = "ownerapi"
AUTH_URL = "https://auth.tesla.com/oauth2/v3/authorize"
TOKEN_URL = "https://auth.tesla.com/oauth2/v3/token"
TOKEN_URL_CN = "https://auth.tesla.cn/oauth2/v3/token"
REDIRECT_URL = "https://auth.tesla.com/void/callback"
LOCAL_REDIRECT_URL = "http://localhost:8888/callback"


class Tokens:
    """Container for Tesla OAuth tokens."""

    def __init__(self, access_token: str, refresh_token: str, expires_in: int):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in

    def __str__(self) -> str:
        duration_str = format_duration(self.expires_in)
        return f"""
--------------------------------- ACCESS TOKEN ---------------------------------

{self.access_token}

--------------------------------- REFRESH TOKEN --------------------------------

{self.refresh_token}

----------------------------------- VALID FOR ----------------------------------

{duration_str}
"""


class TeslaAuthClient:
    """Tesla OAuth2 client with PKCE flow."""

    def __init__(self):
        self.code_verifier = self._generate_code_verifier()
        self.code_challenge = self._generate_code_challenge(self.code_verifier)
        self.state = self._generate_state()
        self.auth_url = self._build_auth_url()
        self.authorization_code: Optional[str] = None
        self.received_state: Optional[str] = None
        self.issuer: Optional[str] = None

    @staticmethod
    def _generate_code_verifier() -> str:
        """Generate a PKCE code verifier (random 43-128 character string)."""
        return urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    @staticmethod
    def _generate_code_challenge(verifier: str) -> str:
        """Generate a PKCE code challenge from the verifier using SHA256."""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    @staticmethod
    def _generate_state() -> str:
        """Generate a random state parameter for CSRF protection."""
        return urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    def _build_auth_url(self) -> str:
        """Build the Tesla OAuth authorization URL."""
        params = {
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URL,
            'response_type': 'code',
            'scope': 'openid email offline_access',
            'state': self.state,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    def get_auth_url(self) -> str:
        """Get the authorization URL to display to the user."""
        return self.auth_url

    def retrieve_tokens(self, code: str, state: str, issuer: str) -> Tokens:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: The authorization code from the callback
            state: The state parameter from the callback (for CSRF validation)
            issuer: The issuer URL to determine which token endpoint to use

        Returns:
            Tokens object containing access_token, refresh_token, and expires_in

        Raises:
            ValueError: If state doesn't match (CSRF attack)
            requests.RequestException: If token exchange fails
        """
        # Validate CSRF state
        if state != self.state:
            raise ValueError("CSRF state does not match!")

        # Determine which token URL to use based on issuer
        issuer_host = urlparse(issuer).hostname
        token_url = TOKEN_URL_CN if issuer_host == "auth.tesla.cn" else TOKEN_URL

        # Prepare token exchange request
        data = {
            'grant_type': 'authorization_code',
            'client_id': CLIENT_ID,
            'code': code,
            'code_verifier': self.code_verifier,
            'redirect_uri': REDIRECT_URL,
        }

        # Exchange code for tokens
        response = requests.post(
            token_url,
            data=data,
            allow_redirects=False,
            timeout=30
        )
        response.raise_for_status()

        token_data = response.json()

        # Validate required fields
        if 'access_token' not in token_data:
            raise ValueError("access_token field missing from response")
        if 'refresh_token' not in token_data:
            raise ValueError("refresh_token field missing from response")
        if 'expires_in' not in token_data:
            raise ValueError("expires_in field missing from response")

        return Tokens(
            access_token=token_data['access_token'],
            refresh_token=token_data['refresh_token'],
            expires_in=token_data['expires_in']
        )


def format_duration(seconds: int) -> str:
    """
    Format duration in seconds to a human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string like "1 day 2 hours 30 minutes"
    """
    MINUTE = 60
    HOUR = 60 * MINUTE
    DAY = 24 * HOUR

    parts = []

    for divisor, singular, plural in [(DAY, "day", "days"),
                                       (HOUR, "hour", "hours"),
                                       (MINUTE, "minute", "minutes")]:
        if seconds < divisor:
            continue

        units = seconds // divisor
        parts.append(f"{units} {singular if units == 1 else plural}")
        seconds -= units * divisor

    return " ".join(parts) if parts else ""


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAuth callback."""

    auth_client: Optional[TeslaAuthClient] = None

    def do_GET(self):
        """Handle GET request for OAuth callback."""
        parsed = urlparse(self.path)

        if parsed.path == '/callback':
            query_params = parse_qs(parsed.query)

            # Check for login cancellation
            if 'error' in query_params and query_params['error'][0] == 'login_cancelled':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"""
                    <html>
                    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                        <h1>Login Cancelled</h1>
                        <p>You may close this window.</p>
                    </body>
                    </html>
                """)
                return

            # Extract callback parameters
            try:
                state = query_params['state'][0]
                code = query_params['code'][0]
                issuer = query_params['issuer'][0]

                # Store in auth client
                if self.auth_client:
                    self.auth_client.authorization_code = code
                    self.auth_client.received_state = state
                    self.auth_client.issuer = issuer

                # Send success response
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"""
                    <html>
                    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                        <h1>Authorization Successful!</h1>
                        <p>Generating tokens...</p>
                        <p>You may close this window.</p>
                    </body>
                    </html>
                """)
            except (KeyError, IndexError) as e:
                self.send_error(400, f"Missing required parameters: {e}")
        else:
            self.send_error(404, "Not found")

    def log_message(self, format, *args):
        """Suppress default logging."""
        if logging.getLogger().level == logging.DEBUG:
            super().log_message(format, *args)


def run_local_server(auth_client: TeslaAuthClient, port: int = 8888) -> bool:
    """
    Run a local HTTP server to receive the OAuth callback.

    Args:
        auth_client: The Tesla auth client instance
        port: Port to run the server on

    Returns:
        True if authorization was received, False if cancelled
    """
    CallbackHandler.auth_client = auth_client

    server = HTTPServer(('localhost', port), CallbackHandler)

    # Run server in background thread
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(f"Listening for callback on http://localhost:{port}/callback")
    print("Waiting for authorization...")

    # Wait for callback (with timeout)
    import time
    timeout = 300  # 5 minutes
    start_time = time.time()

    while auth_client.authorization_code is None:
        if time.time() - start_time > timeout:
            server.shutdown()
            return False
        time.sleep(0.1)

    server.shutdown()
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="tesla-auth-py",
        description="Tesla API tokens generator"
    )
    parser.add_argument('-d', '--debug', action='store_true', help="print debug output")
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(levelname)s: %(message)s'
    )

    # Create auth client
    auth_client = TeslaAuthClient()
    auth_url = auth_client.get_auth_url()

    print("tesla-auth-py - Tesla Authentication")
    print("=" * 80)
    print()
    print("Opening Tesla login page in your browser...")
    print()
    print("If the browser doesn't open automatically, please visit:")
    print(auth_url)
    print()

    logging.debug(f"Opening {auth_url}")

    # Open browser
    try:
        webbrowser.open(auth_url)
    except Exception as e:
        logging.warning(f"Could not open browser: {e}")

    # Note: In this simplified version, we instruct the user to manually handle the redirect
    # A full implementation would need a local server or webview like the Rust version
    print("\nNOTE: This is a simplified implementation.")
    print("After logging in, you will be redirected to Tesla's void callback page.")
    print()
    print("To complete authentication, you need to:")
    print("1. Log in to your Tesla account in the browser")
    print("2. Copy the FULL URL from the address bar after redirect")
    print("3. Paste it below")
    print()

    try:
        callback_url = input("Paste the full callback URL here: ").strip()

        # Parse the callback URL
        parsed = urlparse(callback_url)
        query_params = parse_qs(parsed.query)

        if 'error' in query_params and query_params['error'][0] == 'login_cancelled':
            print("\nLogin cancelled.")
            return 1

        # Extract parameters
        try:
            code = query_params['code'][0]
            state = query_params['state'][0]
            issuer = query_params['issuer'][0]
        except (KeyError, IndexError):
            print("\nError: Invalid callback URL. Missing required parameters.")
            return 1

        # Retrieve tokens
        print("\nRetrieving tokens...")
        tokens = auth_client.retrieve_tokens(code, state, issuer)

        # Display tokens
        print(tokens)

        return 0

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        return 1
    except ValueError as e:
        print(f"\nError: {e}")
        return 1
    except requests.RequestException as e:
        print(f"\nError exchanging code for tokens: {e}")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logging.exception(e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
