# Go Passkeys Backend

A WebAuthn/Passkeys authentication server written in Go, converted from the original JavaScript implementation.

## Features

- WebAuthn registration and authentication
- Passkey support with platform authenticators
- CORS enabled for cross-origin requests
- In-memory storage for users and sessions
- Secure challenge generation

## Prerequisites

- Go 1.21 or later

## Installation

1. Initialize the Go module and download dependencies:
```bash
go mod tidy
```

2. Run the server:
```bash
go run main.go
```

The server will start on port 3000 by default, or you can set the `PORT` environment variable.

## API Endpoints

### Registration

#### POST /register/start
Initiates passkey registration for a user.

**Request:**
```json
{
  "username": "user@example.com"
}
```

**Response:**
Returns WebAuthn credential creation options.

#### POST /register/finish
Completes passkey registration.

**Request:**
```json
{
  "username": "user@example.com",
  "data": "<credential_creation_response>"
}
```

**Response:**
```json
{
  "res": true
}
```

### Authentication

#### POST /login/start
Initiates passkey authentication for a user.

**Request:**
```json
{
  "username": "user@example.com"
}
```

**Response:**
Returns WebAuthn credential request options.

#### POST /login/finish
Completes passkey authentication.

**Request:**
```json
{
  "username": "user@example.com",
  "data": "<credential_assertion_response>"
}
```

**Response:**
```json
{
  "res": true
}
```

## Configuration

The server is configured for:
- **RP ID**: `localhost`
- **Origins**: `http://localhost:3000`, `http://127.0.0.1:3000`
- **Authenticator**: Platform authenticators preferred
- **User Verification**: Required for registration, preferred for authentication

## Dependencies

- `github.com/go-webauthn/webauthn` - WebAuthn implementation
- `github.com/gorilla/mux` - HTTP router
- `github.com/rs/cors` - CORS middleware

## Security Notes

- This implementation uses in-memory storage for demonstration purposes
- For production use, implement persistent storage (database)
- Consider implementing session management and user authentication
- Ensure HTTPS in production environments

## Migration from JavaScript

This Go implementation maintains API compatibility with the original JavaScript version:
- Same endpoint paths and request/response formats
- Same WebAuthn configuration
- Same CORS and origin settings

The main differences:
- Uses Go's native HTTP server and routing
- Implements WebAuthn using the go-webauthn library
- Includes proper error handling and logging
- Uses Go's crypto/rand for secure challenge generation
