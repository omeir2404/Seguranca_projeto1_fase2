SE## 1. Communication & Infrastructure (TLS)
* [x] **Switch to TLS/SSL Sockets:** Replace all clear-text TCP connections with secure TLS sockets.
* [x] **Implement Unilateral Authentication:** Ensure the client verifies the server’s identity using the server's certificate.
* [ ] **Manage Key Material:**
    * [x] Create a **Keystore** for the server (containing its private key and self-signed certificate).
    * [ ] Create a **Keystore** for each user.
    * [x] Create a **Truststore** for the client to store the server's certificate and other users' certificates.
    * [x] Use **RSA 2048-bit** for all public-private key pairs.

---

## 2. Server-Side Data Protection
* [ ] **Implement File Encryption (PBE):**
    * [ ] Use **AES 128-bit** with Password-Based Encryption (PBE) to encrypt server files (houses, remote attestation data).
    * [ ] Implement the salt management logic to ensure the encryption key remains consistent across reboots.
* [ ] **Integrity Checks:**
    * [ ] Calculate **SHA256** hashes for every server file and save them as `<file>.hash`.
    * [ ] Verify integrity upon server startup and during execution; terminate with `NOK-INTEGRITY` if it fails.
* [ ] **Secure Password Storage:**
    * [ ] Update the user file to store: `<user-id>:<hash(password || salt)>:<salt>`.
    * [ ] Use **SHA256** for the hashing.

---

## 3. Remote Attestation
* [ ] **Upgrade Attestation Mechanism:** Move from file-size validation to a hash-based challenge-response.
* [ ] **Implement Anti-Replay Logic:**
    * [ ] **Server:** Generate and send an 8-byte random **nonce** (long) to the client.
    * [ ] **Client:** Concatenate the nonce with the `SpertaClient.jar` file, calculate the **SHA256** hash, and send it back.
    * [ ] **Server:** Compare the received hash against a local reference calculation.
    * [ ] Handle `OK-ATTEST` and `NOK-ATTEST` responses.

---

## 4. End-to-End (E2E) Confidentiality
* [ ] **Section Key Management:**
    * [ ] **Owner:** Generate a symmetric **AES 128-bit** "Section Key" whenever a new house is created.
    * [ ] **Owner:** Encrypt the Section Key with the owner's public key and store it on the server.
* [ ] **Secure Sharing (ADD Command):**
    * [ ] Modify the `ADD` command so the Owner retrieves the Section Key, re-encrypts it with the new user's public key, and sends it back to the server.
* [ ] **Certificate Distribution:**
    * [ ] Enable `SpertaServer` to act as a public key certificate repository.
    * [ ] Implement logic for the client to upload its certificate during the first authentication.
* [ ] **Encrypted Commands (EC, RT, RH):**
    * [ ] **EC:** Ensure the client fetches/decodes the Section Key and encrypts the device state (`<int>`) before sending it to the server.
    * [ ] **RT/RH:** Ensure the server sends the encrypted data along with the relevant Section Key (encrypted for the requester) so the client can decrypt locally.

---

## 5. Final Delivery Requirements
* [x] **Update CLI Arguments:** Adjust the startup commands for `SpertaServer` and `SpertaClient` to include the new keystore/truststore paths and passwords.
* [ ] **Prepare Submission Package:**
    * [ ] ZIP file named `SegC-grupoXX-proj1-fase2.zip`.
    * [ ] Include: Source code, Keystores, Truststores, Certificates, JAR files, and a `readme.txt`.
* [ ] **Individual Tasks:** Complete the Moodle self-assessment form by April 25th.

---

## Notes
* TLS client/server wiring is now in place in code.
* The client verifies the server certificate through the configured truststore and hostname verification.
* Local test materials created in the project root:
  * `serverkeystore.jks`
  * `server-cert.pem`
  * `clienttruststore.jks`
* Still missing for full project completion:
  * per-user keystores/certificates
  * encrypted server persistence with PBE
  * SHA-256 integrity checks
  * nonce-based remote attestation
  * end-to-end encryption for section/device data
