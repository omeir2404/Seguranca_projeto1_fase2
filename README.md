# Sperta - Projeto 1 (Fase 2)

### **Grupo 4**

| Aluno | Numero |
|---|---:|
| **Isa David** | `61871` |
| **Omeir Haroon** | `61810` |
| **Diogo Roque** | `61857` |

Projeto da disciplina de Segurança e Confiabilidade (2025/2026).

Esta fase (Fase 2) adiciona segurança completa ao sistema Sperta:
- **TLS/SSL** com autenticação unilateral do servidor
- **Passwords** com SHA-256 + salt (`user:hash:salt`)
- **Atestação remota** via SHA-256(nonce || SpertaClient.jar)
- **Cifra de ficheiros** PBE com PBKDF2 + AES-128-GCM
- **Integridade de ficheiros** SHA-256 (`.hash` por cada ficheiro)
- **Confidencialidade fim-a-fim** nos comandos EC/RT/RH (AES-128-GCM por secção)

## Arquitetura

- Linguagem: Java
- Transporte: TLS/SSL sockets (autenticação unilateral do servidor)
- Protocolo: objetos Java serializados + stream binária para transferência de ficheiros (`RT` e `RH`)
- Multi-cliente: servidor aceita clientes em simultâneo (1 thread por cliente)

## Execução

### Sintaxe esperada

```
SpertaServer [port] <password-cifra> <keystore> <password-keystore>
SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>
```

`serverAddress` aceita `<IP/hostname>[:porto]`. Porto por omissão: **22345** (código) / **2223** (Makefile).

### Requisitos

- Java JDK 17+ (testado com OpenJDK 21)
- `keytool` disponível (incluído no JDK)
- `make`

---

### Execução Local (mesma máquina)

```bash
make certs       # gera certificados TLS
make serverJAR   # compila, cria ambos os JARs e inicia o servidor
```

Noutro terminal:
```bash
make client      # Nexus / ehBueFixe
make client2     # Eclipse / tbmEhFixe (utilizador alternativo)
```

---

### Execução em Duas Máquinas

**Máquina 1 (Servidor):**
```bash
make certs TLS_SERVER_IP=<IP_DA_MAQUINA>   # forçar IP correto se necessário
make serverJAR
```

O `make serverJAR` imprime o comando exato para copiar para a Máquina 2.

**Transferência para Máquina 2:**
Copiar pelo menos: `dist/SpertaClient.jar`, `clienttruststore.jks`, `clientkeystore.jks`, `server_ip.txt`

**Máquina 2 (Cliente):**
> **IMPORTANTE:** Não execute `make client` na Máquina 2. Isso recompila o JAR, gerando uma hash diferente e causando falha na Atestação Remota (`NOK-ATTEST`).

```bash
java -jar dist/SpertaClient.jar $(cat server_ip.txt):2223 \
     clienttruststore.jks truststorepass \
     clientkeystore.jks clientkeypass \
     Nexus ehBueFixe
```

**Resolução de IP incorreto (Docker/VMs):**
```bash
make certs TLS_SERVER_IP=<IP_REAL_DA_REDE>
```

---

### Execução nos Labs da FCUL (sem Makefile)

Se o `make` não estiver disponível nos laboratórios, usar diretamente:

**Passo 1 — Gerar certificados (uma vez):**
```bash
SERVER_IP=$(hostname -I | awk '{print $1}')

keytool -genkeypair -alias sperta-server -keyalg RSA -keysize 2048 \
  -validity 3650 -keystore serverkeystore.jks -storepass keystorepass \
  -keypass keystorepass \
  -dname "CN=$(hostname), OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT" \
  -ext SAN=dns:$(hostname),ip:$SERVER_IP

keytool -exportcert -alias sperta-server -keystore serverkeystore.jks \
  -storepass keystorepass -rfc -file server-cert.pem

keytool -importcert -alias sperta-server -file server-cert.pem \
  -keystore clienttruststore.jks -storepass truststorepass -noprompt

keytool -genkeypair -alias sperta-client -keyalg RSA -keysize 2048 \
  -validity 3650 -keystore clientkeystore.jks -storepass clientkeypass \
  -keypass clientkeypass \
  -dname "CN=client-default, OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT"
```

**Passo 2 — Servidor:**
```bash
java -jar dist/SpertaServer.jar 2223 cipherpass serverkeystore.jks keystorepass
```

**Passo 3 — Cliente (noutro terminal):**
```bash
java -jar dist/SpertaClient.jar 127.0.0.1:2223 \
     clienttruststore.jks truststorepass \
     clientkeystore.jks clientkeypass \
     Nexus ehBueFixe
```

Não é necessário compilar — os JARs pré-compilados em `dist/` já estão prontos.

---

### Alvos do Makefile

| Alvo | Descrição |
|---|---|
| `make certs` | Gera certificados TLS; guarda IP em `server_ip.txt` |
| `make serverJAR` | Compila, cria ambos os JARs e inicia o servidor |
| `make createJARs` | Só cria os JARs em `dist/` (sem iniciar) |
| `make client` | Executa cliente (Nexus / ehBueFixe) |
| `make client2` | Executa cliente (Eclipse / tbmEhFixe) |
| `make wrongclient` | Executa cliente com password errada (teste de WRONG-PWD) |
| `make clean` | Remove ficheiros `.class` compilados |
| `make cleanFULL` | Limpa tudo (dados, certificados, `.class`) |

---

## TLS e Atestação Remota

O cliente valida o certificado do servidor. O Makefile injeta o IP no campo `Subject Alternative Name (SAN)` do certificado.

**Fluxo de Atestação:**
1. Servidor envia nonce aleatório de 8 bytes (long)
2. Cliente calcula `SHA-256(nonce || SpertaClient.jar)` e envia ao servidor
3. Servidor calcula o mesmo sobre a sua cópia de referência (`dist/SpertaClient.jar`)
4. Se coincidir → `OK-ATTEST`; se não coincidir → `NOK-ATTEST` (ligação encerrada)
5. Autenticação por `user-id` e `password`:
   - `OK-NEW-USER`: novo utilizador registado; cliente envia certificado X.509
   - `OK-USER`: utilizador existente validado
   - `WRONG-PWD`: password incorreta (1 retry)
   - `USER-ALREADY-CONNECTED`: sessão duplicada

## Comandos Suportados

| Comando | Descrição |
|---|---|
| `CREATE <hm>` | Criar casa (utilizador fica Owner) |
| `ADD <user> <hm> <s>` | Adicionar utilizador à secção `<s>` da casa `<hm>` (`<s>` pode ser M/G/L/P/B/E ou `all`) |
| `RD <hm> <s>` | Registar dispositivo na secção `<s>` da casa `<hm>` |
| `EC <hm> <d> <int>` | Enviar estado/temporização [0..600] ao dispositivo `<d>` (cifrado fim-a-fim) |
| `RT <hm>` | Receber estado atual dos dispositivos acessíveis (decifrado localmente) |
| `RH <hm> <d>` | Receber histórico CSV do dispositivo `<d>` (decifrado localmente) |
| `LS [<hm>]` | Listar casas ou dispositivos acessíveis (extra) |
| `EXIT` / `QUIT` | Terminar ligação |

## Confidencialidade Fim-a-Fim

- No `CREATE`: o Owner gera uma **Chave de Secção** AES-128 para cada secção, cifra com a sua chave pública RSA e envia ao servidor (`PUTWKEY`).
- No `ADD`: o Owner obtém a chave da secção (`GETWKEY`), decifra com a sua chave privada, cifra com a chave pública do utilizador adicionado e envia ao servidor.
- No `EC`: o cliente obtém a chave da secção cifrada do servidor, decifra-a com a sua chave privada e usa-a para cifrar o valor antes de enviar.
- No `RT`/`RH`: o servidor envia as chaves de secção cifradas juntamente com os dados. O cliente decifra primeiro as chaves (com a chave privada) e depois os dados.
- O servidor **não consegue** decifrar os valores dos dispositivos.

## Persistência

```
server_data/
  auth/
    users.txt                  utilizadores (cifrado + .hash)
    attestation.txt            caminho do JAR de referência (cifrado + .hash)
    pbe.salt                   sal para derivação da chave PBE
    certs/                     certificados X.509 dos utilizadores (.cer + .hash)
  metadata/
    homes_registry.txt         casas/owners (cifrado + .hash)
    permissions.txt            permissões (cifrado + .hash)
    house_metadata.txt         metadados (cifrado + .hash)
    section_counters.txt       contadores de IDs (cifrado + .hash)
    device_sections.txt        mapeamento dispositivo→secção (cifrado + .hash)
    houses.log                 log de auditoria (cifrado + .hash)
  states/
    last_commands.txt          último EC por dispositivo (cifrado + .hash)
  homes/<casa>/<seccao>/       histórico CSV por dispositivo (cifrado + .hash)
  keys/<casa>/<seccao>/        chaves de secção cifradas por utilizador (.bin + .hash)

client_data/<user-id>/
  status_<hm>.txt              resultado decifrado do RT
  history_<d>_<hm>.csv         resultado decifrado do RH
```

## Integridade de Ficheiros

- Cada ficheiro protegido tem um ficheiro `.hash` com o SHA-256 do conteúdo em texto simples.
- Na inicialização do servidor, todos os ficheiros são verificados. Falha → `NOK-INTEGRITY` e servidor termina.
- A cifra PBE incorreta resulta em falha de decifra que causa `NOK-INTEGRITY`.

## Limitações Conhecidas

- O formato de hash/salt de passwords está em hexadecimal (não Base64 como no exemplo do enunciado). O funcionamento está correto.
- O comando `LS` é extra ao enunciado e mantido por conveniência.
- Para testes em duas máquinas, o `SpertaClient.jar` no cliente deve ser o mesmo binário que está em `dist/` no servidor (não recompilar na máquina cliente).
- O utilizador a adicionar com `ADD` deve ter-se autenticado pelo menos uma vez antes (necessário para o servidor ter o seu certificado).
