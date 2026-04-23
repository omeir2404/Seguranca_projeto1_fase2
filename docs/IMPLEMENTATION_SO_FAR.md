# Implementation So Far

This document summarizes the current implementation state of the project and highlights what is still pending to fully match the Phase 2 PDF requirements.

## 1. Current Goal of the Project

The project implements a secure smart-home client/server system in Java. A client connects to the server over TLS, performs remote attestation, authenticates with `user-id` and password, and issues commands for houses, permissions, devices, and data retrieval.

The codebase currently includes:

- TLS communication between client and server.
- Remote attestation based on `SHA-256(nonce || SpertaClient.jar)`.
- User authentication with single-session enforcement.
- Password storage with per-user salt and SHA-256 hash.
- Certificate upload on first login and server-side certificate repository.
- House creation, permission management, and device registration.
- Section-key wrapping/unwrapping flow for `CREATE`/`ADD`/`EC`/`RT`/`RH`.
- Encrypted-at-rest support for several server files through PBE-derived AES key.
- Integrity verification with `.hash` files.

## 2. High-Level Architecture

The system is split into:

- Server: `src/main/server/`
- Client: `src/main/client/`

Main entry points:

- Server startup: `src/main/server/SpertaServer.java`
- Client startup: `src/main/client/SpertaClient.java`

Main supporting classes:

- Server networking: `src/main/server/ServerNetwork.java`
- Server command logic: `src/main/server/ServerCommandHandler.java`
- Server persistence: `src/main/server/ServerFileManager.java`
- Client networking: `src/main/client/ClientNetwork.java`

## 3. Server Implementation

### 3.1 Server startup

`SpertaServer`:

- Parses startup arguments and optional port.
- Validates port range.
- Initializes `ServerFileManager` and persistence structure.
- Initializes crypto (`password-cifra`) and loads users/houses/permissions/device state.
- Runs integrity verification routine.
- Configures TLS with server keystore.
- Accepts secure connections and spawns one `ClientHandler` per client.

In-memory structures:

- `users`: `user -> hash:salt`
- `houses`: `house -> owner`
- `permissions`: `house -> (user -> section/all)`
- `deviceState`: `house -> (device -> value)`
- `activeUsers`: connected users set

### 3.2 Per-client handling

Per connection flow:

1. Create object streams (`ServerNetwork`).
2. Run remote attestation.
3. Authenticate user.
4. Request/store certificate on first login.
5. Enter command loop.
6. Cleanup user from `activeUsers` on disconnect.

## 4. Client Implementation

### 4.1 Client startup

`SpertaClient`:

- Parses `<host>[:port]` server address.
- Validates and loads truststore and keystore.
- Establishes TLS connection.
- Performs attestation.
- Authenticates.
- Enters interactive command loop.

### 4.2 TLS setup

`ClientNetwork`:

- Sets truststore system properties.
- Creates `SSLSocket`.
- Enables hostname verification (`HTTPS` endpoint identification).
- Starts TLS handshake explicitly.

### 4.3 Certificate handling on client

Client-side certificate flow currently implemented:

- Keeps a local cache of certificates.
- Reads certificate from truststore if already present.
- Fetches missing certificates from server (`GETCERT`).
- Stores fetched certificates in truststore and persists truststore to disk.

## 5. Remote Attestation

Implemented protocol:

1. Server sends random 8-byte nonce (`long`).
2. Client computes `SHA-256(nonce || client-jar-bytes)`.
3. Client sends hash.
4. Server computes expected hash from local reference JAR.
5. Server returns `OK-ATTEST` or `NOK-ATTEST`.

Reference JAR path is read from `server_data/auth/attestation.txt` (fallback `dist/SpertaClient.jar`).

## 6. Authentication

Current behavior:

- New user: auto-register with stored format `user:hash(password||salt):salt`.
- Existing user: verify hash using stored salt.
- Wrong password: one retry.
- Reject simultaneous second session for same user.

Server responses:

- `OK-NEW-USER`
- `OK-USER`
- `WRONG-PWD`
- `USER-ALREADY-CONNECTED`

## 7. Command Support

Supported commands:

- `CREATE <hm>`
- `ADD <user1> <hm> <s>`
- `RD <hm> <s>`
- `EC <hm> <d> <int>` (implemented as request+encrypted send protocol)
- `RT <hm>`
- `RH <hm> <d>`
- `LS`
- `LS <hm>` (extra)

### 7.1 `CREATE`

- Creates house and owner permissions.
- Persists metadata and counters.
- Client bootstrap publishes wrapped section keys for owner.

### 7.2 `ADD`

- Owner grants target user section permissions.
- Client re-wraps section key for target user and uploads wrapped key.

### 7.3 `RD`

- Owner-only device registration.
- Valid section validation.
- Section-specific device auto-numbering (`M1`, `L1`, etc).

### 7.4 `EC`

- Two-step flow: request wrapped section key, then send encrypted value.
- Client no longer sends plaintext device values to the server in the second-step `EC` message.
- Stores encrypted payload in server persistence.
- Logs encrypted command payload.

### 7.5 `RT`

- Server checks permissions.
- Returns payload with wrapped keys per section plus encrypted data entries.
- Client decrypts and writes human-readable output file.

### 7.6 `RH`

- Server checks permissions and device existence.
- Returns payload with wrapped section key plus encrypted history entries.
- Client decrypts and writes plaintext CSV history.

## 8. Persistence Model

Current structure:

```text
server_data/
  auth/
    users.txt
    attestation.txt
    pbe.salt
    certs/
  metadata/
    homes_registry.txt
    permissions.txt
    house_metadata.txt
    section_counters.txt
    device_sections.txt
    houses.log
  states/
    last_commands.txt
  keys/
    <house>/<section>/key.<house>.<section>.<owner>.<recipient>.bin
  homes/
    <house>/<section>/<device>.csv
```

Integrity files (`.hash`) are written for protected artifacts in multiple write paths.

## 9. File Transfer Design

For `RT` and `RH`, transfer over current object-stream channel is:

1. Server sends textual response (`OK` or error).
2. Server sends file size (`long`).
3. Server streams raw bytes.
4. Client writes payload to disk and post-processes/decrypts.

## 10. Current Compliance Snapshot

Phase 2 is no longer in the initial stage; major security features are now implemented. However, there are still important mismatches between implementation and strict PDF requirements.

## 11. Overall Status

Current status can be summarized as:

- Functionally complete command flow with multi-client operation.
- TLS and nonce-based attestation implemented.
- Password hashing with salt implemented.
- Certificate exchange and truststore persistence implemented.
- End-to-end encryption flow implemented for device data exchange.
- PBE-based encrypted persistence and integrity checks implemented in part.

Remaining work is now mostly about correctness/compliance hardening, not missing entire features.

## 12. To Fix

The following items should be fixed to confidently claim full PDF compliance:

1. **Re-validate README wording and examples.**
   - Some README text still references older states (phase wording and old formats). Align docs with current implementation and final protocol.
