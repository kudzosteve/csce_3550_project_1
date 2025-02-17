# csce_3550_project_1

JWKS SERVER WITH JWT AUTHENTICATION
===================================

Overview
This project implements a RESTful JWKS (JSON Web Key Set) server that provides public keys for verifying JSON Web Tokens (JWTs). It supports key expiry for enhanced security and allows issuing JWTs signed with both valid and expired keys.

Features
    - Generates RSA key pairs with unique `kid` (Key ID) and expiry timestamps.
    - Provides a JWKS endpoint (`/.well-known/jwks.json`) that serves only non-expired public keys.
    - Offers an authentication endpoint (`/auth`) that issues JWTs.
    - Supports issuing JWTs signed with expired keys when requested (`/auth?expired=true`).
    - Automatically deletes expired keys from the key store.

Endpoints
    1. JWKS Endpoint: `GET /.well-known/jwks.json`
        - Returns the active public keys in JWKS format.
        - Automatically removes expired keys before responding.
        - If no valid keys exist, new ones are generated.

    2. Authentication Endpoint: `POST /auth`
        - Returns a valid JWT signed with an active key.
        - If `?expired=true` is passed, returns a JWT signed with an expired key.


Prerequisites:
    - Python 3.x
    - Virtual environment (optional but recommended)
