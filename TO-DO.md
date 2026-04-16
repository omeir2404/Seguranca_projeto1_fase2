To ensure you hit every requirement for the final submission on **April 24th**, here is the consolidated and complete **Phase 2 TO-DO list**.

---

## 1. Communication & Infrastructure (TLS)
* [x] **Switch to TLS/SSL Sockets:** Replace standard TCP with secure TLS/SSL connections to guarantee confidentiality and integrity.
* [x] **Unilateral Authentication:** Ensure the client verifies the server’s identity using the server's certificate.
* [x] **Key Material Generation:**
    * [x] Use **RSA 2048-bit** for all public-private key pairs.
    * [x] Create a **Keystore** for the server (private key + certificate).
    * [x] Create a **Keystore** for each user (private key + certificate).
    * [x] Create a **Truststore** for the client to hold the server's self-signed certificate and other users' certificates.

---

## 2. Server-Side Data Protection
* [ ] **Password-Based Encryption (PBE):**
    * [ ] Use **AES 128-bit** to cifrar server files (houses, user lists, and attestation data).
    * [ ] Implement salt management so the same encryption key is generated from the password across server restart.
* [ ] **Integrity Verification:**
    * [ ] Generate a **SHA256** hash for every file and store it in a corresponding `.hash` file.
    * [ ] Verify integrity **after** decryption.
    * [ ] **Crucial:** If verification fails at any point, print `NOK-INTEGRITY` and terminate immediately.
* [ ] **Secure Password Storage:**
    * [ ] Transition from clear-text to storing `<user-id>:<hash(password || salt)>:<salt>` using **SHA256**.
    * [ ] Recalculate and compare hashes for authentication.

---

## 3. Remote Attestation (Anti-Replay)
* [x] **Challenge-Response Logic:**
    * [x] **Server:** Generate and send a random **8-byte nonce** (long) upon connection.
    * [x] **Client:** Concatenate nonce with `SpertaClient.jar`, compute **SHA256**, and return the result.
    * [x] **Server:** Compare against a local calculation using its reference copy of the JAR.
* [x] **Response Handling:** Implement `OK-ATTEST` (proceed to login) and `NOK-ATTEST` (terminate connection).

---

## 4. End-to-End (E2E) Confidentiality
* [ ] **Certificate Distribution Repository:**
    * [ ] **First Login:** Server must request, receive, and store the user’s `.cert` file.
    * [ ] **Subsequent Logins:** Server distributes certificates as needed for E2E sharing.
* [ ] **Section Key Management:**
    * [ ] **CREATE:** Owner generates an **AES 128-bit** "Section Key" for each section.
    * [ ] **Key Storage:** Encrypt Section Keys with the Owner's public key and store them as `key.<hm>.<s>.<owner>` on the server.
* [ ] **Secure Sharing (ADD Command):**
    * [ ] Owner must fetch the key, re-encrypt it with the **new user's public key**, and upload the result.
* [ ] **Encrypted Commands (EC, RT, RH):**
    * [ ] **EC:** Client fetches the Section Key, decrypts it, and encrypts the device state value `<int>` before sending it to the server.
    * [ ] **RT/RH:** Server checks permissions and sends encrypted data alongside the Section Key (encrypted for the requester).

---

## 5. Final Delivery Prep
* [ ] **Updated CLI Syntax:**
    * [ ] **Server:** `SpertaServer <port> <password-cifra> <keystore> <password-keystore>`.
    * [ ] **Client:** `SpertaClient <serverAddress> <truststore> <pass-trust> <keystore> <pass-key> <user-id> <pass>`.
* [ ] **ZIP Package Creation:**
    * [ ] Name: `SegC-grupoXX-proj1-fase2.zip`.
    * [ ] Include all source code, keystores, truststores, certificates, and JAR files.
    * [ ] Write a `readme.txt` with compilation, execution instructions, and limitations.
* [ ] **Self-Assessment:** Complete the Moodle contribution form by April 25th.
