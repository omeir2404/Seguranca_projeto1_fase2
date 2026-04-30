// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLServerSocketFactory;

/**
 * SpertaServer - Servidor central de Smart Home com segurança TLS/SSL
 * 
 * Responsabilidades principais:
 * 1. Escuta conexões de clientes na porta segura (TLS 1.3+)
 * 2. Autentica clientes via atestação remota (validação do JAR com nonce + SHA-256)
 * 3. Valida credenciais de utilizadores (SHA-256 com salt aleatório)
 * 4. Gerencia utilizadores autenticados evitando logins duplicados via ConcurrentHashMap
 * 5. Processa comandos de clientes através de ServerCommandHandler (CREATE, ADD, RD, EC, etc)
 * 6. Mantém estado sincronizado: users (credenciais), houses (casas), permissions (acesso), deviceState
 * 
 * Segurança:
 * - TLS 1.3 obrigatório (SSLServerSocketFactory com keystore/certificado)
 * - Senha master (cipher password) para encriptar dados em repouso (PBKDF2+AES-128-GCM)
 * - Atestação remota: server envia nonce (64-bit), cliente retorna SHA-256(nonce || SpertaClient.jar)
 * - Passwords de utilizador: SHA-256(password || salt aleatório de 16 bytes), armazenadas em formato hash:salt
 * - Comparação constante de hashes (MessageDigest.isEqual) previne timing attacks
 * - Utiliza ConcurrentHashMap para activeUsers - thread-safe sem locks explícitos
 * 
 * Threading:
 * - Main thread: aceita clientes em loop infinito (serverSocket.accept)
 * - ClientHandler thread (1 por cliente): autentica, atesta, processa comandos
 * - Todas as operações de arquivo usam ServerFileManager sincronizado
 * 
 * Fluxo de conexão:
 * 1. TLS handshake (valida servidor para cliente)
 * 2. Atestação: server envia nonce → cliente retorna proof → server valida SHA-256
 * 3. Autenticação: username + password (detecta novos utilizadores)
 * 4. Se novo: requite certificado X.509 do cliente
 * 5. Loop de comandos: processa REQUEST, GETCERT, etc até disconnect
 * 6. Cleanup: remove user de activeUsers, fecha socket/streams
 */
public class SpertaServer extends Thread {

    private static final int DEFAULT_PORT = 22345;
    private static final int MIN_PORT = 1024;
    private static final int MAX_PORT = 65535;

    private ServerSocket serverSocket;
    private boolean running = true;

    private static Map<String, String> users;
    private static Map<String, String> houses;
    private static Map<String, Map<String, String>> permissions;
    private static Map<String, Map<String, Integer>> deviceState;
	private static Set<String> activeUsers;
    private static ServerFileManager fileManager;


	private static String cipherPassword;
	private static String keystorePath;
	private static String keystorePass;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int USER_SALT_BYTES = 16;

    // ============ INITIALIZATION METHODS ============

    /**
     * Inicializa o gerenciador de arquivos para leitura/escrita sincronizada.
     * ServerFileManager encapsula I/O encriptado (PBKDF2+AES-128-GCM) e operações
     * atômicas sobre arquivos de persistência (users.txt, houses.txt, permissions.txt, etc).
     */
    private static void initializeFileManager() {
        fileManager = new ServerFileManager();
    }

    /**
     * Verifica e cria a estrutura de diretórios necessária em server_data/.
     * Garante que auth/, homes/, keys/, metadata/, states/ existem antes de qualquer operação.
     */
	private static void verifyPersistenceStructure() {
		fileManager.ensurePersistenceStructure();
	}

    /**
     * Valida o número de porta fornecido como argumento.
     * Portas < 1024 requerem privilégios de root; > 65535 inválidas.
     * 
     * @param portValue String com número da porta
     * @return porta validada
     * @throws System.exit(-1) se inválido
     */
    private static int validatePort(String portValue) {
        try {
            int port = Integer.parseInt(portValue);
            if (port < MIN_PORT || port > MAX_PORT) {
                System.err.println("A porta tem de estar entre " + MIN_PORT + " e " + MAX_PORT + ".");
                System.exit(-1);
            }
            return port;
        } catch (Exception e) {
            System.out.println("A porta tem de ser de tipo Integer.");
            System.exit(-1);
        }
        return 0;
    }

    /**
     * Converte array de bytes para String hexadecimal.
     * Necessário para serializar salt e hash de password em formato legível em arquivo.
     * Exemplo: byte[] {0xAB, 0xCD} → "abcd"
     * 
     * @param bytes Array de bytes a converter
     * @return Representação hexadecimal lowercase
     */
	private static String bytesToHexadecimal(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2); // 1 Byte = 2 caracteres hex
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

    /**
     * Converte String hexadecimal de volta para array de bytes.
     * Inverso de bytesToHexadecimal(). Usado para recuperar salt e hash do arquivo.
     * Exemplo: "abcd" → byte[] {0xAB, 0xCD}
     * 
     * @param hex String em hexadecimal lowercase (comprimento deve ser par)
     * @return Array de bytes ou null se inválido
     */
	private static byte[] hexadecimalToBytes(String hex) {
		if (hex == null || (hex.length() % 2) != 0) {
			return null;
		}

		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i += 2) {
			int high = Character.digit(hex.charAt(i), 16);
			int low = Character.digit(hex.charAt(i + 1), 16);
			if (high < 0 || low < 0) {
				return null; // Caractere não é hexadecimal válido
			}
			bytes[i / 2] = (byte) ((high << 4) + low);
		}
		return bytes;
	}

    /**
     * Calcula SHA-256(password || salt).
     * Ordem importante: password bytes primeiro, depois salt bytes (concatenação em memoria).
     * Resultado retornado em hexadecimal para armazenamento.
     * 
     * @param password String da password do utilizador
     * @param salt Bytes aleatórios (16 bytes, gerados por SecureRandom)
     * @return Hash em hexadecimal lowercase (64 caracteres para SHA-256)
     * @throws IllegalStateException se SHA-256 não disponível (nunca deve acontecer)
     */
	private static String hashPasswordWithSalt(String password, byte[] salt) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Algoritmo criptográfico
			digest.update(password.getBytes(StandardCharsets.UTF_8)); // Ingere password em UTF-8
			digest.update(salt); // Ingere salt após password
			return bytesToHexadecimal(digest.digest()); // Finaliza cálculo e converte para hex
		} catch (Exception e) {
			throw new IllegalStateException("Falha ao calcular hash da password.", e);
		}
	}

    /**
     * Gera credencial de armazenamento para novo utilizador.
     * Cria salt aleatório (16 bytes), calcula hash, devolve formato "hash:salt".
     * Cada utilizador tem salt único, logo mesmo password tem hash diferentes.
     * 
     * @param password String da password do utilizador novo
     * @return String no formato "<hash-hex>:<salt-hex>" para armazenamento em users.txt
     */
	private static String buildStoredCredential(String password) {
		byte[] salt = new byte[USER_SALT_BYTES]; // 16 bytes
		SECURE_RANDOM.nextBytes(salt); // Preenche com números aleatórios criptograficamente seguros
		String saltHex = bytesToHexadecimal(salt); // Converte salt para hexadecimal
		String hashHex = hashPasswordWithSalt(password, salt); // Calcula SHA-256(password || salt)
		return hashHex + ":" + saltHex; // Formato: hash:salt
	}

    /**
     * Verifica se password do cliente coincide com credencial armazenada.
     * Estratégia: recalcular hash com salt armazenado, comparar com hash armazenado.
     * CRÍTICO: usa MessageDigest.isEqual() para comparação constante-em-tempo
     * (impede timing attacks onde atacante mede tempo de resposta para deduzir hash)
     * 
     * Processo:
     * 1. Parse credencialGuardada = "hash:salt" (armazenado em users.txt)
     * 2. Calcula candidate = SHA-256(passwordCandidata || salt armazenado)
     * 3. Compara bytes de forma constante-em-tempo
     * 
     * @param passwordCandidata Password fornecida pelo cliente (durante login)
     * @param credencialGuardada String "hash:salt" armazenada em users.txt
     * @return true se senha coincide, false caso contrário ou se formato inválido
     */
	private static boolean verifyPassword(String passwordCandidata, String credencialGuardada) {
		if (passwordCandidata == null || credencialGuardada == null) {
			return false;
		}
		// Parse formato "hash:salt"
		String[] parts = credencialGuardada.split(":", 2);
		if (parts.length != 2) {
			return false;
		}

		String hashHex = parts[0].trim();
		String saltHex = parts[1].trim();

		// Converte de hexadecimal para bytes
		byte[] salt = hexadecimalToBytes(saltHex);
		byte[] storedHash = hexadecimalToBytes(hashHex);
		if (salt == null || storedHash == null) {
			return false;
		}

		// Recalcula hash com password candidata e salt armazenado
		String candidateHashHex = hashPasswordWithSalt(passwordCandidata, salt);
		byte[] candidateHash = hexadecimalToBytes(candidateHashHex);
		if (candidateHash == null) {
			return false;
		}

		// Comparação constante-em-tempo: MessageDigest.isEqual() compara todos os bytes
		// (não retorna false na primeira diferença, previne timing attacks)
		return MessageDigest.isEqual(storedHash, candidateHash);
	}

    /**
     * Inicializa engine de criptografia (PBKDF2 + AES-128-GCM).
     * ServerFileManager usa cipher password para derivar chave criptográfica
     * e encriptar/decriptar todos os arquivos em server_data/.
     * 
     * @param cipherPassword String da senha para encriptação em repouso
     */
    private static void initializeCrypto() {
		fileManager.initCrypto(cipherPassword);
    }

    /**
     * Carrega estado persistente do servidor a partir de server_data/.
     * Executa durante startup para restaurar estado anterior (houses, permissions, logs).
     * Deve ser chamado APÓS initializeCrypto() para garantir que fileManager pode decriptar.
     * 
     * Carrega:
     * - users: Map<String, "hash:salt"> de users.txt (credenciais)
     * - houses: Map<String, owner> de homes_registry.txt
     * - permissions: Map<String, Map<String, "M,G,L">> de permissions.txt
     * - deviceState: Map<String, Map<String, estado>> reconstruído a partir de device_sections.txt
     * - activeUsers: ConcurrentHashMap.newKeySet() vazio (preenchido com logins durante runtime)
     */
    public static void initialize_server_vars() {
        users = fileManager.loadUsers();
        houses = fileManager.loadHouses();
        permissions = fileManager.loadPermissions();
        deviceState = fileManager.rebuildDeviceStateFromPersistence(houses);
		activeUsers = ConcurrentHashMap.newKeySet(); // Thread-safe Set para logins ativos
    }

    // ============ MAIN ENTRY POINT ============

    /**
     * Ponto de entrada do servidor Sperta.
     * 
     * Sintaxe: java SpertaServer [porta] <senha-cifra> <keystore-path> <keystore-password>
     *   - [porta] (opcional): porta TCP para escuta (default 22345)
     *   - <senha-cifra> (obrigatório): senha mestre para encriptar dados em repouso
     *   - <keystore-path> (obrigatório): caminho para keystore (p.ex. "server_certs/keystore.jks")
     *   - <keystore-password> (obrigatório): senha do keystore (para desbloquear chave privada do servidor)
     * 
     * Exemplos:
     *   java SpertaServer 22345 mySuperPassword /path/to/keystore.jks keystoreSecret
     *   java SpertaServer myPassword /path/to/keystore.jks keystoreSecret (usa porta default 22345)
     * 
     * Fluxo de inicialização:
     * 1. Valida argumentos (comprimento e formato de porta)
     * 2. Extrai configurações: porta, senha-cifra, caminho-keystore, password-keystore
     * 3. initializeFileManager(): cria ServerFileManager
     * 4. initializeCrypto(): prepara engine PBKDF2+AES-128-GCM com cipher password
     * 5. verifyPersistenceStructure(): cria diretórios server_data/ se não existem
     * 6. fileManager.verifyAllFilesIntegrity(): valida integridade arquivos encriptados
     * 7. initialize_server_vars(): carrega estado (users, houses, permissions, deviceState)
     * 8. Cria hook de shutdown (ao pressionar CTRL+C)
     * 9. Inicia loop de aceitação de clientes (startServer)
     * 
     * @param args Array de argumentos de linha de comando
     */
    public static void main(String[] args) {
        if (args.length != 3 && args.length != 4) {
            System.out.println("Usage: SpertaServer [port] <password-cifra> <keystore> <password-keystore>");
            System.exit(-1);
        }

        int port = DEFAULT_PORT;
        int firstCredentialArg = 0;
        // Se 4 argumentos fornecidos: primeiro é porta, restante são credenciais
        if (args.length == 4) {
            port = validatePort(args[0]);
            firstCredentialArg = 1;
        }
        // Se 3 argumentos: usa porta default, todos são credenciais
		cipherPassword = args[firstCredentialArg]; // Senha para encriptar dados em repouso
		keystorePath = args[firstCredentialArg + 1]; // Caminho para keystore com certificado servidor
		keystorePass = args[firstCredentialArg + 2]; // Senha do keystore

        // Inicializa componentes do servidor
        initializeFileManager();
        initializeCrypto();
		verifyPersistenceStructure();
		fileManager.verifyAllFilesIntegrity(); // Valida integridade de todos os arquivos encriptados
        initialize_server_vars(); // Carrega maps de memória (users, houses, permissions, deviceState)

        // Imprime OK para confirmar inicialização bem-sucedida
		System.out.println("OK");

        // Cria instância do servidor (thread principal)
        SpertaServer server = new SpertaServer();
        
        // Registra handler para CTRL+C (shutdown gracioso)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nCTRL+C detetado. A fechar o servidor...");
            server.closeServer();
        }));
        
        // Inicia loop de aceitação de clientes
        server.startServer(port);
    }

    // ============ SERVER MANAGEMENT METHODS ============

    /**
     * Inicia o servidor TLS e aceita conexões de clientes em loop infinito.
     * 
     * Fluxo:
     * 1. Valida existéncia e acessibilidade do keystore
     * 2. Configura sistema properties para TLS (javax.net.ssl.keyStore, keyStorePassword)
     * 3. Cria SSLServerSocketFactory (fabrica de sockets SSL/TLS)
     * 4. Cria SSLServerSocket na porta fornecida
     * 5. Loop infinito: aceita cliente → cria ClientHandler thread → chama .start()
     *    (cada ClientHandler executa em thread separada, permitindo múltiplos clientes)
     * 6. Loop continua enquanto running == true
     * 
     * TLS Config:
     * - Protocol: TLS 1.3+ (negociado automaticamente)
     * - Cipher suites: selecionadas pelo SSLServerSocketFactory
     * - Certificado: carregado do keystore (X.509 RSA 2048 bits)
     * - Autenticação: unilateral (servidor autentica para cliente)
     * 
     * @param port Porta TCP para escuta (1024-65535)
     * @throws System.exit(-1) se erro TLS ou keystore
     */
	public void startServer(int port) {
		// Valida keystore antes de iniciar
		Path keystore = Path.of(keystorePath);
		if (!Files.isRegularFile(keystore) || !Files.isReadable(keystore)) {
			System.err.println("Erro TLS: keystore não encontrado ou sem permissões de leitura: " + keystore.toAbsolutePath());
			System.exit(-1);
		}

		// Configura system properties para TLS (javax.net.ssl.SSLServerSocketFactory os lê)
		System.setProperty("javax.net.ssl.keyStore", keystorePath);
		System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);

		try {
			// Obtém factory de sockets TLS
			SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			serverSocket = ssf.createServerSocket(port); // Cria socket servidor TLS
			System.out.println("Servidor Seguro (TLS) à espera de clientes...");
			
			// Loop principal: aceita clientes
			while(running) {
				Socket clientSocket = serverSocket.accept(); // Bloqueia até cliente conectar
				// Cria e inicia thread ClientHandler (executa autenticação e processamento de comandos)
				new ClientHandler(clientSocket).start();
			}
		} catch (IOException e) {
			System.err.println("Erro TLS: " + e.getMessage());
			System.exit(-1);
		} catch (Exception e) {
			System.err.println("Erro TLS ao inicializar keystore/certificado: " + e.getMessage());
			System.exit(-1);
		}
	}

    /**
     * Fecha o servidor graciosamente.
     * Define running = false para sair do loop de aceitação,
     * depois fecha o ServerSocket (bloqueia qualquer nova conexão).
     * Clientes conectados não são afetados (suas threads ClientHandler continuam).
     * 
     * Chamado por:
     * - Shutdown hook (quando CTRL+C é pressionado)
     * - closeServer() explícito
     */
    public void closeServer() {
        running = false; // Sinaliza loop para sair
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close(); // Fecha socket servidor
                System.out.println("O Servidor fechou!");
            }
        } catch (IOException e) {
            System.err.println("Erro ao fechar o servidor: " + e.getMessage());
        }
    }

    // ============ CLIENT HANDLER (INNER CLASS) ============

    /**
     * ClientHandler - Manipulador de cliente (executa em thread separada).
     * 
     * Uma instância ClientHandler é criada para cada cliente conectado.
     * Thread dedicada gerencia:
     * 1. Atestação remota (valida JAR do cliente)
     * 2. Autenticação (username/password com detecção de novo utilizador)
     * 3. Upload de certificado (se novo utilizador)
     * 4. Loop de comandos (READ/EC/RT/RH/CREATE/ADD/LS/GETCERT/PUTWKEY/GETWKEY)
     * 5. Cleanup (remove user de activeUsers, fecha socket)
     * 
     * Estado por cliente:
     * - socket: Socket TLS para comunicação
     * - network: ServerNetwork wrapper para I/O serializado
     * - commandHandler: Referencia para dispatcher de comandos (sincronizado)
     * - requiresCertificateUpload: flag se novo utilizador requer cert upload
     * 
     * Thread-safety:
     * - users, houses, permissions, deviceState são acessadas por ServerCommandHandler
     * - activeUsers usa ConcurrentHashMap (thread-safe)
     * - Cada cliente tem sua própria ServerNetwork (não compartilhada)
     */
    class ClientHandler extends Thread {
    	/**
    	 * Socket TLS para comunicação com cliente.
    	 * TLS 1.3 fornece criptografia ponta-a-ponta (confidencialidade + integridade).
    	 */
    	private Socket socket;
    	
    	/**
    	 * Referencia para dispatcher de comandos (ServerCommandHandler).
    	 * Compartilhado entre threads: cada ClientHandler chama handleCommand() sincronizado.
    	 */
		private ServerCommandHandler commandHandler;
    	
    	/**
    	 * Wrapper de socket para I/O serializado (ObjectOutputStream/ObjectInputStream).
    	 * Cada cliente tem sua própria instância (não thread-safe entre threads).
    	 */
		private ServerNetwork network;
    	
    	/**
    	 * Flag: true se cliente é novo utilizador e requer upload de certificado X.509.
    	 * Definido por authenticateClient() se retorna "OK-NEW-USER".
    	 */
		private boolean requiresCertificateUpload;

        /**
         * Construtor ClientHandler.
         * Envolve socket em ServerNetwork (prepara streams para I/O).
         * Cria ServerCommandHandler com referências aos maps compartilhados.
         * 
         * @param sock Socket TLS já conectado com cliente
         */
		ClientHandler(Socket sock) {
			this.socket = sock;
			try{
				// Envolve socket em ServerNetwork para I/O serializado
				this.network = new ServerNetwork(sock);
				// Cria dispatcher de comandos com referências aos maps compartilhados
				this.commandHandler = new ServerCommandHandler(users, houses, permissions, deviceState, network, fileManager);
				System.out.println("Thread do servidor criada para cliente.");
			} catch (Exception e){
				System.out.println("Erro ao criar thread do servidor");
				e.printStackTrace();
			}
    	}

        /**
         * Valida/registra utilizador durante autenticação.
         * 
         * Lógica:
         * 1. Se utilizador NÃO existe em map (novo utilizador):
         *    - Gera credencial (SHA-256 com salt aleatório)
         *    - Adiciona ao map em memória
         *    - Persiste em users.txt (fileManager.appendUser)
         *    - Retorna 1 (NEW USER)
         * 
         * 2. Se utilizador EXISTE:
         *    - Valida password com verifyPassword() (compara SHA-256 constante-em-tempo)
         *    - Se password correta: retorna 0 (EXISTING USER)
         *    - Se password errada: retorna -1 (WRONG PASSWORD)
         * 
         * @param user Username fornecido pelo cliente
         * @param pass Password fornecida pelo cliente (primeira tentativa)
         * @return 1 se novo utilizador, 0 se utilizador existente com password correta, -1 se password errada
         */
		private int clientInFile(String user, String pass) {
			int correct = -1;
			if (user == null || pass == null) {
				return -1;
			}

			// Verifica se utilizador já existe
			String storedCredential = users.get(user);
			if (storedCredential == null) {
				// NOVO UTILIZADOR: gera credencial com salt aleatório
				String newStoredCredential = buildStoredCredential(pass);
				users.put(user, newStoredCredential); // Adiciona ao map em memória
				// Extrai hash e salt para persistir
				String[] credentialParts = newStoredCredential.split(":", 2);
				// Persiste em users.txt (encriptado com cipher password)
				fileManager.appendUser(user, credentialParts[0], credentialParts[1]);
				return 1; // NEW USER
			}
			// UTILIZADOR EXISTENTE: valida password
			if (verifyPassword(pass, storedCredential)) {
				correct = 0; // Password correta
			}

			return correct; // 0 se correto, -1 se errado
		}

        /**
         * Calcula hash de atestação remota para verificar integridade do cliente.
         * 
         * Processo:
         * 1. Lê arquivo de referencia SpertaClient.jar (bin/main/client/SpertaClient.jar)
         * 2. Calcula SHA-256(nonce || jarBytes)
         *    - Nonce: 64-bit long fornecido pelo servidor (randomizado)
         *    - jarBytes: contéudo inteiro do JAR do cliente
         *    - Ordem: nonce em primeiro lugar (como bytes de long big-endian)
         * 3. Retorna digest de 32 bytes (256 bits)
         * 
         * Propósito: Cliente também calcula mesmo hash e envia. Se coinciderem,
         * prova que cliente tem JAR legítimo (não foi modificado).
         * 
         * @param nonce Número aleatório de 64 bits fornecido pelo servidor
         * @param referenceJarPath Caminho para JAR de referência (arquivo original)
         * @return Array de 32 bytes com SHA-256(nonce || jarBytes)
         * @throws IOException se JAR não encontrado ou erro de leitura
         */
		private byte[] calculateAttestationHash(long nonce, Path referenceJarPath) throws IOException {
			try {
				// Lê arquivo JAR de referéncia
				byte[] jarBytes = Files.readAllBytes(referenceJarPath);
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				// Ingere nonce como bytes big-endian
				digest.update(ByteBuffer.allocate(Long.BYTES).putLong(nonce).array());
				// Ingere bytes do JAR
				digest.update(jarBytes);
				return digest.digest(); // Retorna hash de 32 bytes
			} catch (Exception e) {
				throw new IOException("Não foi possível calcular a hash de atestação do cliente.", e);
			}
		}

		private boolean attestClient() throws IOException {
			Path referenceJarPath = fileManager.getReferenceClientJarPath();
			if (!Files.isRegularFile(referenceJarPath) || !Files.isReadable(referenceJarPath)) {
				System.err.println("Ficheiro de referência para atestação não encontrado: " + referenceJarPath);
				network.send("NOK-ATTEST");
				return false;
			}

			long nonce = SECURE_RANDOM.nextLong();
			network.send(nonce);

			Object receivedProof = network.receive();
			if (!(receivedProof instanceof byte[] receivedHash)) {
				network.send("NOK-ATTEST");
				return false;
			}

			byte[] expectedHash = calculateAttestationHash(nonce, referenceJarPath);
			boolean valid = MessageDigest.isEqual(expectedHash, receivedHash);
			network.send(valid ? "OK-ATTEST" : "NOK-ATTEST");
			return valid;
		}

		// ============ COMMAND EXECUTION METHODS ============

		private String authenticateClient() throws IOException {
			requiresCertificateUpload = false;
			String user = (String) network.receive();
			String passwd = (String) network.receive();
			System.out.println("Tentativa de autenticacao do utilizador: " + user);

			int authenticated = clientInFile(user, passwd);
			if (user != null && !user.isEmpty() && authenticated >= 0) {
				if (!activeUsers.add(user)) {
					network.send("USER-ALREADY-CONNECTED");
					return null;
				}
				if (authenticated == 1) {
					network.send("OK-NEW-USER");
					requiresCertificateUpload = true;

				} else {
					network.send("OK-USER");
				}
				return user;
			}

			network.send("WRONG-PWD");

			passwd = (String) network.receive();
			System.out.println("Nova tentativa de password para o utilizador: " + user);
			authenticated = clientInFile(user, passwd);
			if (authenticated >= 0) {
				if (!activeUsers.add(user)) {
					network.send("USER-ALREADY-CONNECTED");
					return null;
				}
				network.send("OK-USER");
				return user;
			}

			network.send("WRONG-PWD");
			return null;
		}

		private boolean handleCertificateUploadIfNeeded(String user) {
			if (!requiresCertificateUpload) {
				return true;
			}

			network.send("REQ-CERT");
			Object certObject = network.receive();
			if (!(certObject instanceof byte[] certBytes)) {
				network.send("NOK-CERT-EXPECTED");
				return false;
			}

			if (certBytes.length == 0) {
				network.send("NOK-CERT-EMPTY");
				return false;
			}

			if (!fileManager.saveUserCertificate(user, certBytes)) {
				network.send("NOK-CERT-IO");
				return false;
			}

			network.send("OK-CERT-STORED");
			return true;
		}

		@Override
		public void run() {
			String user = null;
			try {
				if (!attestClient()) {
					return;
				}

				user = authenticateClient();
				if (user == null || user.isEmpty()) {
					return;
				}

				if (!handleCertificateUploadIfNeeded(user)) {
					return;
				}

				handleClientCommands(user);

			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (user != null && !user.isEmpty()) {
					activeUsers.remove(user);
				}
				try {
					closeConnection();
				} catch (IOException e) {
					System.err.println("Erro ao fechar conexão do cliente: " + e.getMessage());
				}
			}
		}

		private void handleClientCommands(String user) throws IOException {
			boolean connected = true;
			while (connected) {
				String cmdStr = (String) network.receive();
				if (cmdStr == null) {
					break;
				}
				System.out.printf("Comando de %s: %s%n", user, cmdStr);

				String response = commandHandler.handleCommand(cmdStr, user);
				String[] parts = cmdStr.trim().split("\\s+");
				if (parts[0].equalsIgnoreCase("RH")) {
					if (response.equals("OK")) {
						System.out.println("RH RETURNED OK");
						String device = parts[2];
						String house = parts[1];
						System.out.printf("RH: house=%s, device=%s%n", house, device);
						commandHandler.RH_sendFile(house, user, device);
					} else {
						network.send(response);
					}
				} else if (parts[0].equalsIgnoreCase("RT")) {
					if (response.equals("OK")) {
						System.out.println("RT RETURNED OK");
						String house = parts[1];
						System.out.printf("RT: house=%s%n", house);
						commandHandler.RT_sendFile(house, user);
					} else {
						network.send(response);
					}
				} else {
					network.send(response);
				}
			}
		}

		private void closeConnection() throws IOException {
			network.close();
			socket.close();
		}
	}

}
