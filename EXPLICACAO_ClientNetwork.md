# ClientNetwork - Explicação Completa

## 📋 O QUE É ClientNetwork?

É uma classe Java que **faz a comunicação entre Cliente e Servidor** de forma segura.

### Responsabilidades:
1. ✅ **Conectar ao servidor** com encriptação TLS/SSL
2. ✅ **Enviar comandos** (objetos Java serializados)
3. ✅ **Enviar ficheiros** (históricos, CSVs, etc)
4. ✅ **Receber respostas** do servidor
5. ✅ **Desconectar** de forma limpa

---

## 🔐 SEGURANÇA - Como Funciona TLS/SSL?

```
CLIENTE                                    SERVIDOR
  │                                          │
  │─── TLS Handshake ──────────────────────→│
  │                                          │
  │← Certificado X.509 do servidor ─────────│
  │                                          │
  │─── Valida certificado ─────────────────→│
  │                                          │
  │     (Negociam chaves de encriptação)    │
  │                                          │
  │      ║║║ Ligação Encriptada ║║║         │
  │─────→║ Comando: "EC casa1" ║║║ ────────→│
  │      ║║║                   ║║║          │
  │←─────║ Resposta: "OK"      ║║║ ←────────│
  │      ║║║                   ║║║          │
```

### Garantias TLS:
- **Confidencial**: Ninguém consegue ler o conteúdo (encriptado com AES)
- **Íntegro**: Mensagens não podem ser alteradas (verificação MAC)
- **Autenticado**: Servidor é quem diz ser (certificado X.509)

---

## 📦 VARIÁVEIS DE INSTÂNCIA (3 apenas)

```java
Socket clientSocket;                // Socket encriptado TLS
ObjectOutputStream out;             // Para ENVIAR objetos
ObjectInputStream in;               // Para RECEBER objetos
```

| Variável | O que é | Para quê |
|----------|---------|----------|
| `clientSocket` | Socket TLS | Ligação encriptada com servidor |
| `out` | ObjectOutputStream | Serializa e envia objetos Java |
| `in` | ObjectInputStream | Recebe e desserializa objetos Java |

---

## 🔄 MÉTODO: `send(Object obj)`

### O que faz:
Envia um objeto Java qualquer ao servidor através da ligação TLS.

### Fluxo:
```
Objeto Java ("EC casa1 lampada 25")
         │
         ▼
ObjectOutputStream serializa → bytes
         │
         ▼
TLS encripta os bytes
         │
         ▼
Envia pela rede ao servidor
         │
         ▼
Servidor recebe → TLS desencripta → desserializa → Objeto original
```

### Código:
```java
public void send(Object obj) {
    out.writeObject(obj);    // Serializa e escreve
    out.flush();             // Envia logo (não fica em buffer)
}
```

---

## 📤 MÉTODO: `sendFile(ByteArrayOutputStream baos)`

### O que faz:
Envia um ficheiro (conteúdo em bytes) ao servidor.

### Protocolo:
```
┌─────────────────────────────┐
│ 1. Tamanho (long) = 1000    │ Primeiro envia tamanho
├─────────────────────────────┤
│ 2. Conteúdo (1000 bytes)    │ Depois envia conteúdo
└─────────────────────────────┘
```

### Por quê este protocolo?
Servidor precisa saber **quantos bytes vai receber** para saber quando terminou!

### Exemplo:
```
Cliente: "Atenção servidor, vai receber 1000 bytes!"
Cliente: [envia 1000 bytes]
Servidor: "Recebi 1000 bytes, transferência completa ✓"
```

---

## 📥 MÉTODO: `receive()`

### O que faz:
Recebe um objeto Java do servidor e retorna.

### Fluxo:
```
Servidor envia resposta ("OK")
         │
         ▼
TLS encriptação recebe bytes
         │
         ▼
TLS desencripta
         │
         ▼
ObjectInputStream desserializa → objeto Java
         │
         ▼
Retorna "OK" como String
```

### Código:
```java
public Object receive() {
    return in.readObject();  // Desserializa e retorna
}
```

---

## 📥 MÉTODO: `receiveFile()` - Versão Memória

### O que faz:
Recebe ficheiro e guarda em **RAM** (memória).

### Vantagens:
- Rápido (acesso à RAM é muito rápido)
- Simples (tudo em memória)

### Desvantagens:
- Se ficheiro for grande (> 100MB), usa muita RAM
- Pode dar "out of memory"

### Quando usar:
- Ficheiros pequenos (< 50MB)
- Quando precisa do conteúdo logo em memória

### Fluxo:
```
1. Cria ByteArrayOutputStream (buffer em RAM)
2. Chama receiveFileToOutputStream (método auxiliar)
3. Converte bytes → String em UTF-8
4. Retorna String
```

---

## 📥 MÉTODO: `receiveFile(Path outputPath)` - Versão Disco

### O que faz:
Recebe ficheiro e guarda em **DISCO** (ficheiro local).

### Vantagens:
- Pode receber ficheiros gigantescos
- Usa pouca RAM (lê em chunks)

### Quando usar:
- Ficheiros grandes (> 50MB)
- Históricos CSV de dispositivos

### Fluxo:
```
1. Cria diretório se não existir
2. Abre ficheiro em modo escrita
3. Chama receiveFileToOutputStream
4. Escreve cada chunk em disco
5. Fecha ficheiro
```

---

## 🔧 MÉTODO PRIVADO: `receiveFileToOutputStream(OutputStream outputStream)`

### O que faz:
Faz o trabalho REAL de receber ficheiros em chunks (pedaços).

### Por quê chunks?
```
Ficheiro de 100MB

❌ MÁ FORMA: Ler tudo de uma vez
    - Precisa 100MB de RAM
    - Se falhar a meio, perde tudo

✅ BOA FORMA: Ler em chunks de 8KB
    - Precisa só 8KB de RAM
    - Se falhar a meio, já tem 95MB guardado
    - Muito mais eficiente
```

### Algoritmo:
```
1. Lê tamanho total (long)
2. Cria buffer de 8KB
3. Enquanto faltarem bytes:
   a. Lê até 8KB do servidor
   b. Escreve no ficheiro/memória
   c. Atualiza contador
4. Flush (garante que tudo foi escrito)
5. Retorna tamanho total
```

### Código esquemático:
```java
long fileSize = in.readLong();      // Tamanho total
byte[] buffer = new byte[8192];     // Buffer 8KB
long remaining = fileSize;           // Contador

while (remaining > 0) {
    int toRead = Math.min(buffer.length, remaining);
    int bytesRead = in.read(buffer, 0, toRead);
    outputStream.write(buffer, 0, bytesRead);
    remaining -= bytesRead;
}
```

---

## 🔌 MÉTODO: `initClientNetwork(String host, int port, String truststorePath, String truststorePass)`

### O que faz:
**CONECTA ao servidor** estabelecendo ligação TLS segura.

### Passos:

#### 1️⃣ Configurar propriedades do sistema
```java
System.setProperty("javax.net.ssl.trustStore", truststorePath);
System.setProperty("javax.net.ssl.trustStorePassword", truststorePass);
```
Diz ao Java: "Os certificados que confio estão neste ficheiro .jks"

#### 2️⃣ Criar factory (fábrica) de SSL sockets
```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
```

#### 3️⃣ Criar socket TLS conectado ao servidor
```java
SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);
```

#### 4️⃣ Validar hostname (proteção MITM)
```java
SSLParameters sslParameters = sslSocket.getSSLParameters();
sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
sslSocket.setSSLParameters(sslParameters);
```

**EXEMPLO DE PROTEÇÃO:**
```
Tentamos conectar a: 192.168.1.10
Servidor envia certificado para: "outro.com"
❌ ERRO! Alguém está a enganar-nos (ataque MITM)
```

#### 5️⃣ Iniciar TLS handshake
```java
sslSocket.startHandshake();
```

Durante o handshake:
- Cliente e servidor trocam certificados
- Validam certificados
- Negoceiam algoritmo de encriptação
- Criam chaves de sessão

#### 6️⃣ Abrir streams de comunicação
```java
out = new ObjectOutputStream(clientSocket.getOutputStream());
in = new ObjectInputStream(clientSocket.getInputStream());
```

### Retorna:
- `true` se sucesso
- `false` se erro

---

## 🔌 MÉTODO: `closeClientNetwork()`

### O que faz:
**DESCONECTA do servidor** e liberta recursos.

### Por quê é importante?
```
SE NÃO FECHAR:
❌ Socket fica aberto desnecessariamente
❌ Servidor mantém thread aberta
❌ Consome recursos
❌ Com 1000 clientes, tem 1000 threads vazias

SE FECHAR:
✅ Socket encerrado
✅ Porta libertada
✅ Servidor pode eliminar thread
✅ Recursos libertados
```

### Passos:
1. Fecha `ObjectOutputStream` (envia EOF ao servidor)
2. Fecha `ObjectInputStream`
3. Fecha socket TLS (termina ligação TCP)

### Código:
```java
if (out != null) out.close();
if (in != null) in.close();
if (clientSocket != null) clientSocket.close();
```

---

## 🔗 COMO É USADO? (SpertaClient)

```java
// 1. CRIAR INSTÂNCIA
ClientNetwork network = new ClientNetwork();

// 2. CONECTAR AO SERVIDOR
boolean success = network.initClientNetwork(
    "localhost",           // host
    22345,                 // port
    "clienttruststore.jks", // ficheiro com certificados
    "truststorepass"        // password
);

if (!success) {
    System.out.println("Erro ao conectar!");
    return;
}

// 3. ENVIAR COMANDO
network.send("EC casa1 lampada 25");

// 4. RECEBER RESPOSTA
Object response = network.receive();
System.out.println("Resposta: " + response);

// 5. RECEBER FICHEIRO (opcional)
String conteudo = network.receiveFile();

// 6. DESCONECTAR
network.closeClientNetwork();
```

---

## 📊 RESUMO VISUAL

```
┌─────────────────────────────────────┐
│       ClientNetwork.java            │
├─────────────────────────────────────┤
│                                     │
│  send(Object obj)                   │ → Envia comandos
│                                     │
│  sendFile(ByteArrayOutputStream)    │ → Envia ficheiros
│                                     │
│  receive()                          │ → Recebe objetos
│                                     │
│  receiveFile()                      │ → Recebe ficheiro→RAM
│  receiveFile(Path)                  │ → Recebe ficheiro→Disco
│                                     │
│  initClientNetwork(...)             │ → CONECTA ao servidor
│  closeClientNetwork()               │ → DESCONECTA
│                                     │
└─────────────────────────────────────┘
```

---

## 🎯 FLUXO COMPLETO DE UM COMANDO

```
1. Cliente: "Quer fazer comando EC"
   └─→ ClientNetwork.send("EC casa1 lampada 100")

2. Serialização: "EC casa1 lampada 100" → bytes
   └─→ ObjectOutputStream

3. Encriptação: bytes → TLS/AES encriptado
   └─→ SSLSocket

4. Transmissão: envia pela rede
   └─→ Internet (segura)

5. Servidor recebe
   └─→ SSLSocket

6. Desencriptação: TLS desencripta
   └─→ ObjectInputStream

7. Desserialização: bytes → "EC casa1 lampada 100"
   └─→ Servidor processa comando

8. Servidor responde: "OK"
   └─→ ClientNetwork.send("OK")

9. Cliente recebe: Object response = network.receive()
   └─→ response = "OK"
```

---

## 🔐 SEGURANÇA - Resumo

| Aspecto | Como | Implementação |
|---------|------|-----------------|
| **Confidencialidade** | Encriptação TLS | AES-128 |
| **Integridade** | MAC | HMAC-SHA256 |
| **Autenticidade** | Certificado X.509 | RSA-2048 |
| **Validação Hostname** | HTTPS Validation | Protege contra MITM |

---

## ✨ CONCLUSÃO

**ClientNetwork** é a ponte segura entre Cliente e Servidor:
- Usa **TLS/SSL** para encriptação
- Usa **Serialização** para transmitir objetos
- Usa **Chunking** para ficheiros grandes
- Gerencia a **ligação** de forma limpa

Toda a comunicação é:
- 🔒 **Confidencial** (encriptada)
- ✅ **Íntegra** (não alterada)
- 🆔 **Autenticada** (servidor é real)
