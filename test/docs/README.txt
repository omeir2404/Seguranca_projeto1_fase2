# Sperta - Projeto 1 (Fase 2)

### **Grupo 4**

| Aluno | Numero |
|---|---:|
| **Isa David** | `61871` |
| **Omeir Haroon** | `61810` |
| **Diogo Roque** | `61857` |

Projeto da disciplina de Segurança e Confiabilidade (2025/2026).

Este trabalho implementa um sistema de casas inteligentes em arquitetura cliente-servidor sobre TLS/SSL:
- `SpertaServer`: gere autenticação, permissões, estado e histórico dos dispositivos.
- `SpertaClient`: autentica no servidor, envia comandos e recebe dados/ficheiros.

O objetivo desta fase é focar funcionalidades e persistência.

## Arquitetura

- Linguagem: Java
- Transporte: TLS/SSL sockets
- Protocolo aplicacional: objetos Java para comandos/respostas + stream binária para transferência de ficheiros (`RT` e `RH`)
- Multi-cliente: servidor aceita clientes em simultâneo (1 thread por cliente)

## Execução

### Sintaxe esperada

- Servidor: `SpertaServer [port] <password-cifra> <keystore> <password-keystore>`
- Cliente: `SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>`

`serverAddress` aceita formato `<ip-ou-hostname>[:porto]`.
Se o porto não for indicado, o servidor usa por omissão o porto `2223` (conforme configurado no `Makefile`).

### Execução Local (Na mesma máquina)

Para testar tudo rapidamente na mesma máquina, basta usar os comandos automáticos:

```bash
make certs
make serverJAR
```

Noutro terminal (na mesma máquina):
```bash
make client
```

### Execução em Duas Máquinas Diferentes

O `Makefile` está configurado para detetar o teu IP automaticamente e guardá-lo no ficheiro `server_ip.txt` para facilitar a conexão. O fluxo correto para não quebrar a **Atestação Remota** é o seguinte:

**1. Na Máquina 1 (Servidor):**
```bash
make certs
make serverJAR
```
*(Nota: O comando `make serverJAR` vai imprimir no terminal o comando exato que deves usar no cliente).*

**2. Transferência:**
Copia a pasta inteira do projeto (ou pelo menos os ficheiros `dist/SpertaClient.jar`, `clienttruststore.jks`, `clientkeystore.jks` e `server_ip.txt`) para a Máquina 2.

**3. Na Máquina 2 (Cliente):**
⚠️ **NÃO executes** `make client` na Máquina 2. O `Makefile` irá recompilar o código, gerando uma nova hash no `.jar` e causando falha na Atestação Remota.
Em vez disso, executa o JAR diretamente. Como o IP foi guardado no `server_ip.txt`, podes usar:

```bash
java -jar dist/SpertaClient.jar $(cat server_ip.txt):2223 clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus ehBueFixe
```

### Resolução de Problemas com IP (Docker/VMs)
Se o servidor tiver o Docker instalado, o `Makefile` pode detetar o IP virtual errado (ex: `172.17.x.x`). Podes forçar o IP correto da rede Wi-Fi/Ethernet ao gerar os certificados:
```bash
make certs TLS_SERVER_IP=<O_TEU_IP_REAL>
```

---

### Alvos do Makefile (Auxiliares)

- `make certs`: Gera certificados e guarda o IP em `server_ip.txt`.
- `make serverJAR`: Compila, cria o JAR do servidor, imprime o menu de IP e executa.
- `make createJARs`: Gera apenas os JARs em `dist/`.
- `make client2` / `make wrongclient`: Executa o cliente com utilizadores alternativos.
- `make clean`: Limpa ficheiros `.class`.
- `make cleanFULL`: Limpa tudo, incluindo dados persistentes e certificados.

## TLS e Atestação Remota

O cliente valida o certificado do servidor com verificação de hostname/IP. O `Makefile` injeta automaticamente o IP da máquina no campo `Subject Alternative Name (SAN)` do certificado usando a variável `TLS_SERVER_IP`.

**Fluxo de Autenticação e Atestação:**
1. O servidor envia um nonce aleatório de 8 bytes ao cliente.
2. O cliente localiza o `SpertaClient.jar` em execução, calcula `SHA-256(nonce || jar)` e devolve o digest.
3. O servidor calcula localmente o mesmo digest sobre a sua cópia de referência do cliente (`server_data/auth/attestation.txt`).
4. Se coincidir, o servidor responde `OK-ATTEST`; se não coincidir, responde `NOK-ATTEST` e a ligação termina.
5. Autenticação por `user-id` e `password`:
   - Novo utilizador: `OK-NEW-USER` (registado e envia certificado);
   - Utilizador existente válido: `OK-USER`;
   - Password errada: `WRONG-PWD`;
   - Sessão duplicada: `USER-ALREADY-CONNECTED`.

## Comandos suportados

Comandos do enunciado implementados:

- `CREATE <hm>`
- `ADD <user1> <hm> <s>`
- `RD <hm> <s>`
- `EC <hm> <d> <int>`
- `RT <hm>`
- `RH <hm> <d>`

Comando extra implementado no projeto:

- `LS` ou `LS <hm>`

Cliente também aceita:

- `EXIT` / `QUIT` para terminar.

## Respostas por comando (comportamento atual)

### `CREATE <hm>`
- `OK`: casa criada, utilizador passa a owner.
- `NOK`: casa já existe ou erro de persistência.

### `ADD <user1> <hm> <s>`
- `OK`
- `NOHM`: casa inexistente.
- `NOUSER`: utilizador alvo não existe.
- `NOPERM`: quem executa não é owner da casa.
- `NOK`: secção inválida/inexistente na casa no momento do pedido.

### `RD <hm> <s>`
- `OK`
- `NOHM` / `NOPERM` / `NOK`: secção inválida.
Ao registar dispositivo, o servidor cria IDs automaticamente por secção (`M1`, `M2`, `L1`, ...).

### `EC <hm> <d> <int>`
- `OK`
- `NOK`: valor inválido (não inteiro ou fora de `0..600`).
- `NOHM` / `NOD` / `NOPERM`
Observação: o valor é cifrado no cliente e apenas o payload cifrado é enviado para o servidor.

### `RT <hm>`
- `OK` + envio de ficheiro texto com estado atual dos dispositivos acessíveis (cifrado e decifrado localmente no cliente).
- `NOHM` / `NOPERM` / `NODATA`
No cliente, guardado em: `client_data/<user-id>/status_<hm>.txt`

### `RH <hm> <d>`
- `OK` + envio do ficheiro CSV de histórico do dispositivo (cifrado e decifrado localmente no cliente).
- `NOHM` / `NOD` / `NOPERM` / `NODATA`
No cliente, guardado em: `client_data/<user-id>/history_<d>_<hm>.csv`

### `LS` e `LS <hm>` (extra)
- `LS`: lista casas onde o utilizador tem acesso.
- `LS <hm>`: lista os dispositivos acessíveis dessa casa.
Observação: O comando não revela valores em claro. Para obter estados legíveis, usar `RT <hm>`.

## Persistência

O servidor cria/usa a seguinte estrutura:

```text
server_data/
  auth/
    users.txt
    attestation.txt
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
    <house>/
      <section>/
        key.<house>.<section>.<owner>.<recipient>.bin
  homes/
    <house>/
      <section>/
        <device>.csv
```

O cliente guarda:

```text
client_data/
  <user-id>/
    status_<hm>.txt
    history_<d>_<hm>.csv
```