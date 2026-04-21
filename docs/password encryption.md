You can implement this cleanly by treating it as two separate problems:

1. `password-cifra` derives one server master key used to encrypt files at rest.
2. User login passwords get their own per-user salts and hashes for authentication.

Right now your server already accepts `password-cifra`, but it is assigned too late in startup: [`SpertaServer.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/SpertaServer.java:81) loads persisted data before setting `cipherPassword` at [`SpertaServer.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/SpertaServer.java:98). If files become encrypted, that order must change first.

**PBE for server files**

Use this model:

- Derive an AES-128 key from `password-cifra` with `PBKDF2WithHmacSHA256`.
- Store one persistent random salt in something like `server_data/auth/pbe.salt`.
- On every restart, read that same salt and derive the same key again.
- Encrypt file contents with `AES/GCM/NoPadding`.
- Store a fresh random IV per encrypted file write inside the file header.
- Do not reuse IVs.
- Salt and IV are different things:
  - Salt makes the same password derive the same key across restarts only if the same salt is reused.
  - IV must be new for every encryption operation.

Recommended parameters:

```java
SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 150_000, 128);
byte[] keyBytes = skf.generateSecret(spec).getEncoded();
SecretKey key = new SecretKeySpec(keyBytes, "AES");
```

For file encryption:

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
secureRandom.nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal(plaintext);
```

Store file bytes as:

```text
MAGIC(4 bytes) | VERSION(1 byte) | IV_LEN(1 byte) | IV | CIPHERTEXT
```

That gives you versioning and lets you detect whether a file is already encrypted.

**Where to integrate it in your code**

The natural place is [`ServerFileManager.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:72), because that class already owns persistence. Add helper methods conceptually like:

- `loadOrCreatePbeSalt()`
- `deriveMasterKey(password, salt)`
- `readProtectedTextFile(Path path)`
- `writeProtectedTextFile(Path path, String content)`
- `isEncryptedFile(Path path)`

Then replace plain file reads/writes in:
- [`loadUsers()`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:150)
- [`loadHouses()`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:189)
- [`loadPermissions()`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:225)
- [`appendUser()`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:442)

And in [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:67) you’d stop calling `Files.readAllLines`, `Files.write`, `Files.writeString`, `FileInputStream` directly for protected files. The most important write points are:
- device section persistence at [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:67)
- last command persistence at [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:132)
- house creation metadata at [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:410)
- counters at [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:361)
- device logs at [`ServerCommandHandler.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerCommandHandler.java:169)

For `RH` and startup rebuild, logs are currently read as plaintext CSV in [`ServerFileManager.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/ServerFileManager.java:346). So if you encrypt logs too, both `rebuildDeviceStateFromPersistence()` and `RH_sendFile()` need decrypt-before-read / decrypt-before-send behavior.

**Salt management**

For the server encryption key, use one persistent server salt:

- File: `server_data/auth/pbe.salt`
- Size: 16 bytes random
- Encoding: raw bytes or Base64
- Lifecycle:
  - if missing, create once
  - if present, reuse forever
- If this salt changes, the password will derive a different key and all encrypted files become unreadable

For user authentication, do not reuse that salt. Each user must have their own salt. Store users as:

```text
<user-id>:<password-hash>:<user-salt>
```

Your TODO says `SHA256(password || salt)`, which is workable for the assignment, but if allowed, `PBKDF2WithHmacSHA256` per user is much better. Either way:

- new user:
  - generate `userSalt = SecureRandom(16 bytes)`
  - compute hash from password + userSalt
  - store `user:hash:salt`
- login:
  - load stored salt for that user
  - recompute hash from supplied password + stored salt
  - compare with `MessageDigest.isEqual(...)`

Important: the per-user authentication salt and the server PBE salt are not the same file and not the same value.

**Recommended implementation order**

1. Move `cipherPassword = args[...]` before any persistence loading in [`SpertaServer.java`](/home/oharoon/Desktop/FCUL/SC/Seguranca_projeto1_fase2/src/main/server/SpertaServer.java:94).
2. Teach `ServerFileManager` to create/load `pbe.salt` and derive the AES key once.
3. Add encrypted read/write helpers for text files.
4. Replace plaintext persistence calls in `ServerFileManager` and `ServerCommandHandler`.
5. Add a simple encrypted file header so you can detect old plaintext files.
6. Migrate `users.txt` from `user:password` to `user:hash:salt`.
7. Keep IV per file-write, persistent salt per server, per-user salt per account.

One subtle but important design choice: for `RT` and `RH`, you probably want files encrypted only on disk, not over the TLS socket. So decrypt server-side, then send plaintext over the already secure TLS channel.

If you want, I can do the next step without editing anything and give you a concrete patch plan method-by-method for `ServerFileManager` and `SpertaServer`.

