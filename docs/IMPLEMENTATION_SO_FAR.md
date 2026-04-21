# Implementation So Far

This document summarizes the current implementation of the project as it exists in the repository today. It is meant to describe what is already working, how the main components are organized, and which Phase 2 requirements are still missing or only partially addressed.

## 1. Current Goal of the Project

The project implements a secure smart-home client/server system in Java. A client connects to the server over TLS, performs remote attestation, authenticates with a user ID and password, and can then issue commands related to houses, permissions, devices, and data retrieval.

At the moment, the codebase already includes:

- TLS communication between client and server
- Remote attestation based on `SHA-256(nonce || SpertaClient.jar)`
- User authentication and single-session enforcement
- House creation and permission management
- Device registration and device state updates
- Retrieval of current state and historical data through file transfer
- Server-side persistence using text and CSV files

The codebase does **not yet fully implement** the full Phase 2 security requirements such as encrypted server persistence, integrity verification with `.hash` files, hashed passwords with salt, or end-to-end confidentiality using per-section keys.

## 2. High-Level Architecture

The system is split into two main sides:

- Server: `src/main/server/`
- Client: `src/main/client/`

Main entry points:

- Server startup: [src/main/server/SpertaServer.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/SpertaServer.java)
- Client startup: [src/main/client/SpertaClient.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/client/SpertaClient.java)

Supporting classes:

- Server networking: [src/main/server/ServerNetwork.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerNetwork.java)
- Server command logic: [src/main/server/ServerCommandHandler.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java)
- Server persistence: [src/main/server/ServerFileManager.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java)
- Client networking: [src/main/client/ClientNetwork.java](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/client/ClientNetwork.java)

## 3. Server Implementation

### 3.1 Server startup

`SpertaServer`:

- Parses command-line arguments and accepts an optional port
- Validates the port range
- Initializes the persistence structure through `ServerFileManager`
- Loads users, houses, permissions, and device state into memory
- Configures TLS using the server keystore
- Listens for secure client connections using `SSLServerSocket`
- Creates one `ClientHandler` thread per connected client

In-memory structures currently used by the server:

- `users`: maps `user -> password`
- `houses`: maps `house -> owner`
- `permissions`: maps `house -> (user -> section/all)`
- `deviceState`: maps `house -> (device -> current value)`
- `activeUsers`: keeps track of users currently connected

### 3.2 Per-client handling

Each client connection is processed by the inner `ClientHandler` class inside `SpertaServer`.

The flow is:

1. Create object streams through `ServerNetwork`
2. Run remote attestation
3. Authenticate the user
4. Enter a command loop
5. Send responses or files back to the client
6. Remove the user from `activeUsers` when the session ends

This means the server already supports multiple simultaneous clients, while also preventing the same user from being logged in twice at the same time.

## 4. Client Implementation

### 4.1 Client startup

`SpertaClient`:

- Parses server address in the form `<host>[:port]`
- Validates truststore and keystore input
- Loads the user keystore
- Creates a TLS connection through `ClientNetwork`
- Performs remote attestation
- Authenticates with `user-id` and `password`
- Starts an interactive command loop

### 4.2 TLS setup

`ClientNetwork`:

- Sets the truststore system properties
- Creates an `SSLSocket`
- Enables hostname verification with `HTTPS` endpoint identification
- Starts the TLS handshake explicitly
- Uses object streams to exchange commands and responses

### 4.3 Client command loop

After successful login, the client:

- Reads commands from standard input
- Sends them to the server as strings
- Prints normal textual responses directly
- Handles file reception for `RT` and `RH`
- Stores received files under `client_data/<user>/`

Generated client files:

- `client_data/<user>/status_<hm>.txt`
- `client_data/<user>/history_<device>_<hm>.csv`

## 5. Remote Attestation

Remote attestation is already implemented on both sides.

### 5.1 Current protocol

1. The server generates a random `long` nonce using `SecureRandom`
2. The server sends that nonce to the client
3. The client locates its running `SpertaClient.jar`
4. The client computes `SHA-256(nonce || jar-bytes)`
5. The client sends the resulting hash to the server
6. The server computes the expected hash over its reference copy of the client JAR
7. The server compares both hashes and returns:
   - `OK-ATTEST`
   - `NOK-ATTEST`

### 5.2 Reference client JAR

The server obtains the expected client JAR path from:

- `server_data/auth/attestation.txt`

If no value is configured there, it falls back to:

- `dist/SpertaClient.jar`

So attestation is already functional, but it depends on the server having access to the correct reference JAR file.

## 6. Authentication

Authentication is also implemented, although still in a simplified form.

### 6.1 Current behavior

When a client connects:

- The client sends `user-id`
- The client sends `password`
- If the user does not exist yet, the server creates the account immediately
- If the user exists and the password matches, login succeeds
- If the password is wrong, the server gives one more attempt
- If the user is already connected in another session, login is rejected

Server responses used:

- `OK-NEW-USER`
- `OK-USER`
- `WRONG-PWD`
- `USER-ALREADY-CONNECTED`

### 6.2 Important limitation

Passwords are still stored in clear text in `users.txt`. The Phase 2 requirement for salted password hashing is still pending.

## 7. Command Support

The server dispatches commands in `ServerCommandHandler`.

Currently supported commands:

- `CREATE <hm>`
- `ADD <user1> <hm> <s>`
- `RD <hm> <s>`
- `EC <hm> <d> <int>`
- `RT <hm>`
- `RH <hm> <d>`
- `LS`
- `LS <hm>`

### 7.1 `CREATE`

Creates a new house and assigns the creator as owner.

Effects:

- Adds the house to the in-memory map
- Persists the house-owner relation
- Grants the owner permission `"all"`
- Initializes house device state

### 7.2 `ADD`

Allows the owner of a house to grant another user access to a section.

Checks performed:

- House exists
- Target user exists
- Requester is the owner
- Section exists in the house

### 7.3 `RD`

Registers a new device in a given section of a house.

Current behavior:

- Only the house owner can register devices
- Allowed sections are validated
- Device IDs are automatically allocated by section
- New devices start with value `0`
- Device-section mapping is persisted
- Initial state is stored
- A log entry is created

Examples of generated device IDs:

- `M1`, `M2`
- `L1`
- `P1`

### 7.4 `EC`

Updates the current integer value of a device.

Checks performed:

- Value must be an integer
- Value must be in range `0..600`
- House must exist
- Device must exist
- User must have access to the device section

Effects:

- Updates in-memory state
- Persists last known device value
- Appends a log entry to the device CSV file

### 7.5 `RT`

Returns the current state of all devices in the house that the requesting user is allowed to access.

Behavior:

- Validates house existence
- Validates house access
- Verifies that there is at least one accessible device
- Builds a text response dynamically from current in-memory device state
- Sends it as a file over the existing TLS connection

The generated file contains lines like:

```text
EC <house> <device> <value>
```

### 7.6 `RH`

Returns the stored CSV history of one device.

Behavior:

- Validates house existence
- Validates permission to the device
- Validates device existence
- Checks whether the device log file exists
- Sends the file to the client if available

### 7.7 `LS`

This is an extra command beyond the base project commands.

Supported forms:

- `LS`
- `LS <hm>`

Behavior:

- `LS` lists houses accessible to the user
- `LS <hm>` lists accessible devices of that house and their current values

## 8. Persistence Model

The server already persists its state into a `server_data/` directory tree.

### 8.1 Current structure

```text
server_data/
  auth/
    users.txt
    attestation.txt
  metadata/
    homes_registry.txt
    permissions.txt
    house_metadata.txt
    section_counters.txt
    device_sections.txt
    houses.log
  states/
    last_commands.txt
  homes/
    <house>/
      <section>/
        <device>.csv
```

### 8.2 What each file is used for

- `users.txt`: registered users and their passwords
- `attestation.txt`: path to the reference client JAR used for attestation
- `homes_registry.txt`: house ownership
- `permissions.txt`: per-house user permissions
- `section_counters.txt`: device numbering per section
- `device_sections.txt`: mapping from device to section
- `last_commands.txt`: latest value stored for each device
- `homes/<house>/<section>/<device>.csv`: historical log of commands affecting each device

### 8.3 State reconstruction on startup

`ServerFileManager.rebuildDeviceStateFromPersistence(...)` walks through device CSV logs and reconstructs the last known state of each device by extracting the latest valid `EC` command.

This is an important part of the implementation because the in-memory `deviceState` map is rebuilt after a server restart.

## 9. File Transfer Design

For `RT` and `RH`, the project uses binary transfer over the same object-stream connection.

Current format:

1. The server first sends a normal string response, usually `OK`
2. The server then sends the file size as a `long`
3. The raw file bytes are streamed in chunks
4. The client receives the bytes and writes them to disk

This logic is implemented in:

- Server side: `ServerNetwork.sendFile(...)`
- Client side: `ClientNetwork.receiveFile(...)`

## 10. What Is Still Missing for Full Phase 2

Based on the current code and the existing `TO-DO.md`, the following major requirements are still pending:

- Password-based encryption of server files using AES-128
- Salt handling for deterministic key derivation across restarts
- Integrity verification through SHA-256 `.hash` files
- Immediate termination with `NOK-INTEGRITY` on integrity failure
- Secure password storage using `hash(password || salt)`
- Certificate repository exchange on first login
- End-to-end confidentiality for shared section keys
- Public-key protection of per-section keys
- Re-encryption workflow for `ADD`
- Encryption of device values and protected delivery for `EC`, `RT`, and `RH`

## 11. Overall Status

The implementation so far already provides a solid functional base:

- secure TLS channel
- remote attestation
- user login
- multi-client support
- house/device/permission management
- persistent storage
- file-based retrieval of current and historical data

However, from a Phase 2 security perspective, the system is still in an intermediate state. The transport layer is secure and attestation exists, but most of the new cryptographic storage and end-to-end confidentiality requirements are not yet implemented.

## 12. Suggested Use of This Document

This file can be used as:

- a checkpoint summary for the team
- a support document for the report/readme
- a guide before implementing the remaining Phase 2 requirements

If needed, this document can later be extended with:

- sequence diagrams
- concrete examples of each command
- file format examples
- a section comparing implemented vs missing requirements line by line
