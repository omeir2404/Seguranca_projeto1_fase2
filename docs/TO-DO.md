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
* [x] **Password-Based Encryption (PBE):**
    * [x] Use **AES 128-bit** to cifrar server files (houses, user lists, and attestation data).
    * [x] Implement salt management so the same encryption key is generated from the password across server restart.
* [x] **Integrity Verification:**
    * [x] Generate a **SHA256** hash for every file and store it in a corresponding `.hash` file.
    * [x] Verify integrity **after** decryption.
    * [x] **Crucial:** If verification fails at any point, print `NOK-INTEGRITY` and terminate immediately.
* [x] **Secure Password Storage:**
    * [x] Transition from clear-text to storing `<user-id>:<hash(password || salt)>:<salt>` using **SHA256**.
    * [x] Recalculate and compare hashes for authentication.

---

## 3. Remote Attestation (Anti-Replay)
* [x] **Challenge-Response Logic:**
    * [x] **Server:** Generate and send a random **8-byte nonce** (long) upon connection.
    * [x] **Client:** Concatenate nonce with `SpertaClient.jar`, compute **SHA256**, and return the result.
    * [x] **Server:** Compare against a local calculation using its reference copy of the JAR.
* [x] **Response Handling:** Implement `OK-ATTEST` (proceed to login) and `NOK-ATTEST` (terminate connection).

---

## 4. End-to-End (E2E) Confidentiality
* [x] **Certificate Distribution Repository:**
    * [x] **First Login:** Server must request, receive, and store the user’s `.cert` file.
    * [x] **Subsequent Logins:** Server distributes certificates as needed for E2E sharing.
* [x] **Section Key Management:**
    * [x] **CREATE:** Owner generates an **AES 128-bit** "Section Key" for each section.
    * [x] **Key Storage:** Encrypt Section Keys with the Owner's public key and store them as `key.<hm>.<s>.<owner>` on the server.
* [x] **Secure Sharing (ADD Command):**
    * [x] Owner must fetch the key, re-encrypt it with the **new user's public key**, and upload the result.
* [x] **Encrypted Commands (EC, RT, RH):**
    * [x] **EC:** Client fetches the Section Key, decrypts it, and encrypts the device state value `<int>` before sending it to the server.
    * [x] **RT/RH:** Server checks permissions and sends encrypted data alongside the Section Key (encrypted for the requester).

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





# Correções
O vosso projeto está com uma estrutura excelente e a maior parte dos requisitos complexos (TLS, PBE, Atestação Remota e Confidencialidade Fim-a-Fim) já estão muito bem encaminhados. No entanto, o resumo detetou algumas falhas críticas em relação ao enunciado, principalmente na parte da **integridade dos ficheiros** e no **armazenamento de certificados no cliente**.

Aqui tens um TODO detalhado, passo a passo, para corrigires o que falta e garantires a nota máxima.

---

## TODO: Correções Finais do Projeto 1 - Fase 2

### 1. Corrigir a Verificação de Integridade de Ficheiros (Servidor)
O enunciado exige que, se um ficheiro for modificado (ou se a password de cifra estiver errada), o servidor deve imprimir `NOK-INTEGRITY` e terminar imediatamente. Atualmente, o servidor está a (re)gerar os hashes no arranque em vez de os verificar. [cite_start]Além disso, o hash tem de ser calculado sobre o **texto limpo (plaintext)**, ou seja, *após* a decifragem[cite: 88].

* **1.1. Alterar a lógica de cálculo do Hash:**
    * No `ServerFileManager.java`, cria um método que calcule o SHA-256 de uma `String` ou `byte[]` em memória (o conteúdo já decifrado), em vez de ler os bytes diretamente do ficheiro no disco.
* **1.2. Reescrever o método `verifyIntegrity`:**
    * O método atual não está a ser usado. Atualiza-o para:
        1. Ler o conteúdo decifrado do ficheiro (usando o teu `readProtectedFile`).
        2. Calcular o hash SHA-256 desse conteúdo decifrado.
        3. Ler o valor guardado no respetivo ficheiro `.hash`.
        4. Comparar ambos. [cite_start]Se forem diferentes (ou se o `.hash` não existir num ficheiro que já deveria ter), faz `System.out.println("NOK-INTEGRITY");` e `System.exit(-1);`[cite: 87, 88].
* **1.3. Aplicar a verificação no arranque do servidor (`SpertaServer.java`):**
    * No método `main`, **antes** de carregares os dados para a memória (`initialize_server_vars()`), itera sobre todos os ficheiros cruciais da diretoria `server_data` (utilizadores, casas, permissões, histórico, etc.) e chama o novo `verifyIntegrity`.
    * *Dica:* Remove ou comenta a chamada a `generateHashesForServerData()` no arranque. Os hashes só devem ser gerados/atualizados no momento em que o servidor **escreve/altera** um ficheiro validamente.

### 2. Persistir Certificados na Truststore (Cliente)
Atualmente, o `SpertaClient.java` pede os certificados dos outros utilizadores ao servidor e guarda-os apenas em memória (`cachedCertificates`). [cite_start]O enunciado diz explicitamente que o cliente deve guardá-los na sua *truststore* para uso futuro[cite: 97].

* **2.1. Carregar a Truststore em memória:**
    * No `SpertaClient.java`, precisas de instanciar a truststore fornecida nos argumentos (geralmente via `KeyStore.getInstance("JKS")` ou `PKCS12`), passando a password da truststore.
* **2.2. Guardar o certificado recebido:**
    * No método `fetchCertificateFromServer` (ou onde processas o certificado recebido), após criares o objeto `Certificate`, adiciona-o à truststore com `trustStore.setCertificateEntry(userId, cert)`.
* **2.3. Escrever a Truststore no disco:**
    * Usa um `FileOutputStream` para guardar a truststore atualizada no ficheiro original: `trustStore.store(fos, truststorePassword.toCharArray())`.
* **2.4. Ler da Truststore antes de pedir ao Servidor:**
    * Sempre que precisares do certificado de um utilizador, verifica primeiro se ele já existe na truststore local. Só se não existir é que deves pedir ao `SpertaServer`.

### 3. Ajuste de Formatação: Base64 vs Hexadecimal (Opcional, mas Recomendado)
O vosso projeto está a guardar os hashes e salts das passwords em formato Hexadecimal. [cite_start]Embora a lógica esteja 100% correta, o exemplo no enunciado do projeto utiliza Base64 [cite: 135] (ex: `efnsuwiBuk+...`). Para evitar perder pontos em testes automáticos dos professores:

* **3.1. Alterar a codificação em `SpertaServer.java`:**
    * Substitui as tuas funções `bytesToHexadecimal` e `hexadecimalToBytes` pelas funções nativas do Java: `Base64.getEncoder().encodeToString(bytes)` e `Base64.getDecoder().decode(string)`.

---

