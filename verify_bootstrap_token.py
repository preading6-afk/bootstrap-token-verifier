#!/usr/bin/env python3
"""
Verify a bootstrap JWT token signed with ES256.

Requires: pip install pyjwt cryptography
"""

import json
from jwt import PyJWT, InvalidTokenError
from jwt.algorithms import ECAlgorithm

# Public JWK (private "d" parameter removed)
PUBLIC_JWK = {
    "alg": "ES256",
    "kty": "EC",
    "x": "dxk0WKKhOyFbU0eZD0plgOB8l9rM-SD5NDgnGpvg99o",
    "y": "nIMebHLyyisqfQKkb-bCp6dVNwVqDR3FLA5ZWUZ_yQ8",
    "crv": "P-256",
}

# Example token produced by the Node.js signer
TOKEN = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImMwODRhODVkLWM0ODYtNDAzNS05YzYwLThjZWM4MWQ4YjhmNSJ9"
    ".eyJqdGkiOiI0ODk5ODVkMy1hMjNlLTRjYjctYjdlNC00NWEwOTFkN2Q2ZTUiLCJzb3VyY2UiOnsiYW1vdW50IjoiMTAwLjAwIiwiYXNzZXQiOiJVU0QifSwidGFyZ2V0Ijp7ImFkZHJlc3MiOiIweGI3OTRmNWVhMGJhMzk0OTRjZTgzOTYxM2ZmZmJhNzQyNzk1NzkyNjgiLCJhc3NldCI6IkVUSCIsIm5ldHdvcmsiOiJldGhlcmV1bSIsImxhYmVsIjoiTXkgd2FsbGV0In0sInN1YiI6ImQyNTlmNmFjLTNlOGQtNDZlYi05ZTZjLWM5MmUxMzhiNzY2MCIsImlhdCI6MTc5MzQxOTU2Nn0"
    ".D0LpwxlhdbqmLcxlP6_ZRFQKH6apG4ed7nDp0awV3DXe78nzzXvh1V66Mu2kzWSociRggxsPphWSfIaS2e83GA"
)


def load_public_key(jwk: dict):
    """Convert a public EC JWK into a cryptography public key."""
    return ECAlgorithm.from_jwk(json.dumps(jwk))


def verify_token(token: str, public_key) -> dict:
    """
    Verify the JWT signature and return the claims.
    Raises InvalidTokenError on any failure.
    """
    jwt_instance = PyJWT()
    # algorithms=["ES256"] pins the algorithm (security best practice)
    claims = jwt_instance.decode(
        token,
        public_key,
        algorithms=["ES256"],
        # Optional extra validation you can enable:
        # options={"require": ["sub", "jti", "iat"]},
        # audience=...,
        # issuer=...,
        # subject="d259f6ac-3e8d-46eb-9e6c-c92e138b7660",
    )
    return claims


def main():
    try:
        public_key = load_public_key(PUBLIC_JWK)
        claims = verify_token(TOKEN, public_key)

        print("Token is valid!")
        print("Claims:")
        print(json.dumps(claims, indent=2))

        # Example application-level checks
        expected_sub = "d259f6ac-3e8d-46eb-9e6c-c92e138b7660"
        if claims.get("sub") != expected_sub:
            print(f"Warning: unexpected subject (got {claims.get('sub')})")

        if "source" not in claims or "target" not in claims:
            print("Warning: missing source or target claim")

    except InvalidTokenError as e:
        print(f"Token verification failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
