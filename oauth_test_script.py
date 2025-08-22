#!/usr/bin/env python
"""
OAuth 2.0 Test Script for BerlinHouse API

This script simulates the OAuth 2.0 flow to test BerlinHouse's OAuth implementation.
It includes both the client-side and server-side aspects of the flow.

Steps:
1. Generate an authorization URL (simulates "Login with BerlinHouse" button)
2. Open the URL in a browser and manually authorize (user interaction required)
3. Capture the authorization code from the callback URL
4. Exchange the authorization code for access and refresh tokens
5. Use the access token to access a protected resource
"""

import os
import sys
import secrets
import requests
import webbrowser
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import time
import hashlib
import base64

# Configuration
# Replace these values with your actual OAuth client credentials
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

# Debug output to check environment variables
print("\nCLIENT_ID:", CLIENT_ID)
print("CLIENT_SECRET:", CLIENT_SECRET[:5] + "..." if CLIENT_SECRET else None)

# Fallback to hardcoded values if environment variables are not set
if not CLIENT_ID or not CLIENT_SECRET:
    print("Warning: Environment variables not set, using hardcoded credentials")
    # Uncomment and set these if needed:
    # CLIENT_ID = "your_client_id_here"
    # CLIENT_SECRET = "your_client_secret_here"
    
REDIRECT_URI = "https://9000-firebase-oauthtest-1755815235789.cluster-cmxrewsem5htqvkvaud2drgfr4.cloudworkstations.dev/api/oauth"
API_BASE_URL = "https://api.berlinhouse.com"
AUTHORIZATION_URL = f"{API_BASE_URL}/o/authorize/"
TOKEN_URL = f"{API_BASE_URL}/o/token/"
USER_INFO_URL = f"{API_BASE_URL}/o/userinfo/"
SCOPES = ["read", "write", "openid"]

# Store for our authorization data
auth_data = {
    'state': None,
    'code': None,
    'code_verifier': None,
    'code_challenge': None,
    "access_token": None,
    "refresh_token": None,
    "token_type": None,
    "expires_in": None
}

# HTTP Server for handling callback
class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle the OAuth callback."""
        # Parse query parameters
        query = urlparse(self.path).query
        params = parse_qs(query)
        
        # Extract authorization code and state
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        
        # Check if there's an error
        error = params.get('error', [None])[0]
        
        response_html = "<html><body>"
        
        if error:
            response_html += f"<h1>Authorization Error</h1><p>{error}</p>"
            print(f"Error: {error}")
        elif code and state:
            # Verify state matches what we sent
            if state == auth_data['state']:
                auth_data['code'] = code
                response_html += "<h1>Authorization Successful</h1>"
                response_html += "<p>You can close this window and return to the script.</p>"
                print(f"Authorization code received: {code[:10]}...")
            else:
                response_html += "<h1>Invalid State</h1>"
                response_html += "<p>State parameter doesn't match. This could be a CSRF attack.</p>"
                print("Error: State mismatch. Possible CSRF attack.")
        else:
            response_html += "<h1>Invalid Request</h1>"
            print("Error: Invalid callback request.")
            
        response_html += "</body></html>"
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_html.encode('utf-8'))
        
        # Signal the main thread that we've received the response
        if code and state == auth_data['state']:
            self.server.received_code = True

def start_callback_server():
    """Start HTTP server to handle the OAuth callback."""
    server = HTTPServer(('localhost', 9002), CallbackHandler)
    server.received_code = False
    
    # Run server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    print(f"Callback server running on http://localhost:9002")
    
    return server

def generate_code_verifier():
    """Generate a code_verifier for PKCE."""
    # Generate a cryptographically random string between 43-128 chars
    code_verifier = secrets.token_urlsafe(96)  # Will be ~128 chars
    # Ensure it's within the allowed length (43-128)
    if len(code_verifier) > 128:
        code_verifier = code_verifier[:128]
    return code_verifier

def generate_code_challenge(code_verifier):
    """Generate a code_challenge from code_verifier using the S256 method."""
    # SHA-256 hash the verifier
    code_challenge_digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Base64url encode the hash
    code_challenge = base64.urlsafe_b64encode(code_challenge_digest).decode('utf-8')
    # Remove padding ('=') characters
    return code_challenge.replace('=', '')

def generate_authorization_url():
    """Generate the authorization URL."""
    auth_data['state'] = secrets.token_urlsafe(32)
    
    # Generate PKCE code_verifier and code_challenge
    auth_data['code_verifier'] = generate_code_verifier()
    auth_data['code_challenge'] = generate_code_challenge(auth_data['code_verifier'])
    
    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ' '.join(SCOPES),  # Use space-separated scopes (OAuth2 default)
        'state': auth_data['state'],
        'code_challenge': auth_data['code_challenge'],
        'code_challenge_method': 'S256'  # Using SHA-256
    }
    
    url = f"{AUTHORIZATION_URL}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"
    return url

def exchange_code_for_tokens(code):
    """Exchange authorization code for access and refresh tokens."""
    # Print debug info
    print("\nExchanging code for tokens with:")
    print(f"TOKEN_URL: {TOKEN_URL}")
    print(f"code: {code[:10]}..." if code else "None")
    print(f"redirectUri: {REDIRECT_URI}")
    print(f"codeVerifier length: {len(auth_data['code_verifier'])}" if auth_data['code_verifier'] else "None")
    
    # Use camelCase parameter names to match the CamelCaseJSONParser
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': auth_data['code_verifier']  # Include the code_verifier for PKCE
    }
    
    # Print headers for debugging
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    print(f"Headers: {headers}")
    
    # Try different client authentication methods
    try:
        print("\nTrying standard client credentials in request body...")
        response = requests.post(TOKEN_URL, data=data, headers=headers, verify=False)
        
        # If that fails with invalid_client, try HTTP Basic Auth
        if response.status_code == 401 and 'invalid_client' in response.text:
            print("\nTrying HTTP Basic Auth instead...")
            response = requests.post(
                TOKEN_URL,
                auth=(CLIENT_ID, CLIENT_SECRET),
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'code_verifier': auth_data['code_verifier']
                },
                headers=headers, verify=False
            )
        
        print(f"\nToken exchange response code: {response.status_code}")
        print(f"Response headers: {response.headers}")
        
        if response.status_code == 200:
            token_data = response.json()
            print("Token exchange successful!")
            
            # Check if response uses camelCase or snake_case
            if 'access_token' in token_data:
                auth_data['access_token'] = token_data.get('access_token')
                auth_data['refresh_token'] = token_data.get('refresh_token')
                auth_data['token_type'] = token_data.get('token_type')
                auth_data['expires_in'] = token_data.get('expires_in')
            else:
                auth_data['access_token'] = token_data.get('accessToken')
                auth_data['refresh_token'] = token_data.get('refreshToken')
                auth_data['token_type'] = token_data.get('tokenType')
                auth_data['expires_in'] = token_data.get('expiresIn')
            
            print("\nAccess token received!")
            print(f"Access Token: {auth_data['access_token'][:10]}...")
            print(f"Token Type: {auth_data['token_type']}")
            print(f"Expires In: {auth_data['expires_in']} seconds")
            return True
        else:
            print(f"\nFailed to exchange code for tokens. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Exception during token exchange: {e}")
        return None

def get_user_info():
    """Get user information using the access token."""
    headers = {
        'Authorization': f"{auth_data['token_type']} {auth_data['access_token']}"
    }
    
    response = requests.get(USER_INFO_URL, headers=headers, verify=False)
    
    if response.status_code == 200:
        user_info = response.json()
        print("\nUser Info Retrieved:")
        print(json.dumps(user_info, indent=2))
        return user_info
    else:
        print(f"\nFailed to get user info. Status: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def refresh_access_token():
    """Refresh the access token using the refresh token."""
    if not auth_data['refresh_token']:
        print("No refresh token available.")
        return False
        
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': auth_data['refresh_token'],
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    response = requests.post(TOKEN_URL, data=data, verify=False)
    
    if response.status_code == 200:
        token_data = response.json()
        
        # Check if response uses camelCase or snake_case
        if 'access_token' in token_data:
            auth_data['access_token'] = token_data.get('access_token')
            auth_data['refresh_token'] = token_data.get('refresh_token', auth_data['refresh_token'])
            auth_data['token_type'] = token_data.get('token_type')
            auth_data['expires_in'] = token_data.get('expires_in')
        else:
            auth_data['access_token'] = token_data.get('accessToken')
            auth_data['refresh_token'] = token_data.get('refreshToken', auth_data['refresh_token'])
            auth_data['token_type'] = token_data.get('tokenType')
            auth_data['expires_in'] = token_data.get('expiresIn')
            
        print("\nAccess token refreshed!")
        print(f"New Access Token: {auth_data['access_token'][:10]}...")
        print(f"Token Type: {auth_data['token_type']}")
        print(f"Expires In: {auth_data['expires_in']} seconds")
        return True
    else:
        print(f"\nFailed to refresh token. Status: {response.status_code}")
        print(f"Response: {response.text}")
        return False

def main():
    """Run the full OAuth flow."""
    print("=" * 80)
    print("BerlinHouse OAuth 2.0 Test Script")
    print("=" * 80)
    
    # Check if the user provided client credentials
    if CLIENT_ID == "your-client-id" or CLIENT_SECRET == "your-client-secret":
        print("Error: Please update the CLIENT_ID and CLIENT_SECRET in the script.")
        print("You can obtain these from the Django admin after registering an OAuth application.")
        sys.exit(1)
        
    # Start callback server
    server = start_callback_server()
    
    # Step 1: Generate authorization URL and open in browser
    auth_url = generate_authorization_url()
    print("\nStep 1: Opening authorization URL in your browser...")
    print(f"URL: {auth_url}")
    
    # Open the browser
    webbrowser.open(auth_url)
    
    # Wait for the callback server to receive the code
    print("\nWaiting for authorization...")
    timeout = 300  # 5 minutes timeout
    start_time = time.time()
    
    while not server.received_code and time.time() - start_time < timeout:
        time.sleep(1)
    
    if not server.received_code:
        print("Timeout waiting for authorization.")
        server.shutdown()
        sys.exit(1)
        
    # Step 2: Exchange authorization code for tokens
    print("\nStep 2: Exchanging authorization code for tokens...")
    if not exchange_code_for_tokens(auth_data['code']):
        server.shutdown()
        sys.exit(1)
        
    # Step 3: Get user information
    print("\nStep 3: Getting user information...")
    user_info = get_user_info()
    
    if not user_info:
        print("Failed to get user information.")
    
    # Step 4: Refresh the access token (optional)
    print("\nStep 4: Refreshing the access token...")
    if refresh_access_token():
        # Verify the new token works
        print("\nVerifying refreshed token by getting user info again...")
        get_user_info()
    
    print("\nOAuth test completed!")
    server.shutdown()

if __name__ == "__main__":
    main()
