# Sperta - Projeto 1 (Fase 1)

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
Se o porto não for indicado, cliente e servidor usam por omissão `22345`.

### Compilar e correr com Makefile

No projeto:

```bash
make compile
make server
make client
```

Também existem alvos auxiliares:

- `make client2`
- `make wrongclient`
- `make server_no_port`
- `make client_no_port`
- `make createServerJAR`
- `make createClientJar`
- `make createJARs`
- `make serverJAR`
- `make clientJAR`
- `make clean`
- `make cleanFULL`

Nota: o `Makefile` usa comandos Unix (`mkdir -p`, `stat -c%s`, `rm -rf`).
No Windows, usar Git Bash, WSL, MSYS2 ou adaptar os comandos para PowerShell.

### JARs (via Makefile)

Os JARs são gerados na pasta `dist/`:

- `dist/SpertaServer.jar`
- `dist/SpertaClient.jar`

Gerar JARs:

```bash
make createJARs
```

Ou gerar separadamente:

```bash
make createServerJAR
make createClientJar
```

Executar servidor pelo JAR:

```bash
make serverJAR
```

Executar cliente pelo JAR (substituir pelos teus valores):

```bash
java -jar dist/SpertaClient.jar localhost:22345 clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus ehBueFixe
```

### Compilação manual (alternativa)

```bash
javac -d bin src/main/server/*.java src/main/client/*.java
```

Servidor:

```bash
java -cp bin main.server.SpertaServer 22345 cipherpass serverkeystore.jks keystorepass
```

Cliente:

```bash
java -cp bin main.client.SpertaClient localhost:22345 clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus ehBueFixe
```

## Fluxo de autenticação e atestação

1. O cliente envia atestação: `ATTEST SpertaClient:<tamanho-do-class>`.
2. O servidor compara com `server_data/auth/attestation.txt`.
3. Se falhar: cliente imprime `ATTESTATION FAILED` e termina.
4. Se passar: cliente imprime `ATTESTATION OK`.
5. Depois acontece autenticacao por `user-id` e `password`:
   - novo utilizador: `OK-NEW-USER` (registado no servidor);
   - utilizador existente com password correta: `OK-USER`;
   - password errada: `WRONG-PWD` (há nova tentativa);
   - se o mesmo user ja estiver ligado noutra sessão: `USER-ALREADY-CONNECTED`.

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

Cliente tambem aceita:

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
- `NOHM`
- `NOPERM`
- `NOK`: secção inválida.

Ao registar dispositivo, o servidor cria IDs automaticamente por secção (`M1`, `M2`, `L1`, ...).

### `EC <hm> <d> <int>`

- `OK`
- `NOK`: valor inválido (não inteiro ou fora de `0..600`).
- `NOHM`
- `NOD`: dispositivo não existe.
- `NOPERM`

### `RT <hm>`

- `OK` + envio de ficheiro texto com estado atual dos dispositivos acessíveis.
- `NOHM`
- `NOPERM`
- `NODATA`: sem dispositivos acessíveis ou sem dados.

No cliente, o ficheiro é guardado em:

- `client_data/<user-id>/status_<hm>.txt`

### `RH <hm> <d>`

- `OK` + envio do ficheiro CSV de histórico do dispositivo.
- `NOHM`
- `NOD`
- `NOPERM`
- `NODATA`: sem log para o dispositivo.

No cliente, o ficheiro e guardado em:

- `client_data/<user-id>/history_<d>_<hm>.csv`

### `LS` e `LS <hm>` (extra)

- `LS`: lista casas onde o utilizador tem acesso.
- `LS <hm>`: lista dispositivos acessíveis dessa casa e o valor atual.

Possíveis respostas: `NOHM`, `NOPERM`, `NODATA`.

## Persistência

O servidor cria/usa a seguinte estrutura:

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

Nota: as secções default (`M`, `G`, `L`, `P`, `B`, `E`) ficam inicializadas logicamente por casa (via `section_counters.txt`), mas as pastas/ficheiros em `server_data/homes/<house>/<section>/` só são criados quando existe pelo menos um dispositivo registado nessa secção.

E o cliente guarda:

```text
client_data/
  <user-id>/
    status_<hm>.txt
    history_<d>_<hm>.csv
```

### Formatos relevantes

- `users.txt`: `user:password`
- `homes_registry.txt`: `House:Owner`
- `permissions.txt`: `House:User:Section`
- `section_counters.txt`: `House:Section=NextCounter,...`
- `last_commands.txt`: `Home:Device:Value`
- logs de dispositivos (`.csv`):
  - header: `time; command`
  - linhas de eventos, ex.: `2026-03-26T18:31:10;EC Casa1 M1 45`

## Estrutura de código

- `src/main/server/SpertaServer.java`: servidor TLS, atestação, autenticação, gestão de clientes.
- `src/main/server/ServerCommandHandler.java`: lógica de comandos (`CREATE`, `ADD`, `RD`, `EC`, `RT`, `RH`, `LS`).
- `src/main/server/ServerFileManager.java`: leitura/escrita e preparação da persistência.
- `src/main/server/ServerNetwork.java`: envio/receção de objetos e ficheiros no servidor.
- `src/main/client/SpertaClient.java`: CLI do cliente, autenticação, loop de comandos.
- `src/main/client/ClientNetwork.java`: comunicação de rede e receção de ficheiros no cliente.

## Limitações conhecidas

- Validação de nomes (`user`, `house`, etc.) e básica; não há filtros fortes de caracteres.

## Exemplo rápido

1. Terminal 1: iniciar servidor.
2. Terminal 2: iniciar cliente (`user` novo ou existente).
3. Comandos típicos:

```text
CREATE Casa1
RD Casa1 Multimedia
EC Casa1 M1 45
RT Casa1
RH Casa1 M1
```
