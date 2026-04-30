// ##############################################################
//           Autores:                Numero Aluno:              #
//        - Omeir Haroon               61810                    #
//        - Isa David                  61871                    #
//        - Diogo Roque                61857                    #
// ##############################################################

package main.client;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cliente principal da aplicacao Sperta.
 *
 * Responsabilidades principais:
 * 1) Validar argumentos de arranque.
 * 2) Inicializar truststore/keystore.
 * 3) Estabelecer ligacao TLS com o servidor.
 * 4) Executar atestacao remota (nonce + hash do JAR).
 * 5) Autenticar utilizador.
 * 6) Processar comandos interativos.
 * 7) Cifrar/decifrar payloads por secao (EC/RT/RH).
 */
public class SpertaClient {

    // Texto de ajuda mostrado no login e no comando help.
    private static final String HELP_TEXT = String.join("\n",
            "Comandos disponiveis:",
            " - CREATE <hm> # Criar casa <hm> - utilizador e Owner",
            " - ADD <user1> <hm> <s> # Adicionar utilizador <user1> a casa <hm>, secao <s>",
            " - RD <hm> <s> # Registar um dispositivo na casa <hm>, na secao <s>",
            " - EC <hm> <d> <int> # Enviar valor <int> de estado/temporizacao do dispositivo <d> da casa <hm> para o servidor",
            " - RT <hm> # Receber a informacao do ultimo comando enviado a cada dispositivo da casa <hm> (com permissoes)",
            " - RH <hm> <d> # Receber o historico (ficheiro .csv) de comandos enviados ao dispositivo <d> da casa <hm> (com permissoes)",
            " - EXIT ou QUIT # Terminar a ligacao ao servidor e fechar o cliente",
            " - LS ou LS <hm> # Listar casas com acesso, ou listar dispositivos acessiveis de uma casa <hm>");

    // Camada de rede para TLS + troca de objetos/ficheiros.
    private static ClientNetwork network;

    // Keystore do utilizador (certificado e chave privada local do cliente).
    private static KeyStore userKeyStore;

    // Truststore local onde guardamos certificados confiados (servidor e utilizadores).
    private static KeyStore trustStore;

    // Caminho e password da truststore para persistencia local.
    private static String trustStorePath;
    private static char[] trustStorePassword;

    // Password da keystore em formato char[] para operar com chave privada.
    private static char[] keyPasswordChars;

    // Secoes permitidas por casa.
    private static final String[] HOUSE_SECTIONS = {"M", "G", "L", "P", "B", "E"};

    // Cache local de certificados de utilizadores para evitar pedidos repetidos ao servidor.
    private final Map<String, Certificate> cachedCertificates = new LinkedHashMap<>();

    /**
     * Representa endereco do servidor apos validacao.
     */
    public static class ServerAddress {
        String host;
        int port;

        ServerAddress(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    /**
     * Valida e interpreta o parametro serverAddress.
     * Formatos aceites: host ou host:porto.
     */
    public static ServerAddress validateServerAddress(String serverAddress) {
        String host;
        int port = 22345; // Porta por omissao.

        if (serverAddress.contains(":")) {
            String[] parts = serverAddress.split(":");
            if (parts.length != 2) {
                System.err.println("Formato do serverAddress invalido. Use: <IP/hostname>[:Port]");
                System.exit(-1);
            }

            try {
                port = Integer.parseInt(parts[1]);
                if (port < 1024 || port > 65535) {
                    System.err.println("Porto tem de ser entre 1024 e 65535");
                    System.exit(-1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Numero do porto invalido");
                System.exit(-1);
            }

            host = parts[0];
        } else {
            host = serverAddress;
        }

        if (host.isEmpty()) {
            System.err.println("Hostname/IP nao pode estar vazio.");
            System.exit(-1);
        }

        return new ServerAddress(host, port);
    }

    /**
     * Resolve caminho para absoluto e impede path traversal fora da pasta de trabalho.
     */
    @SuppressWarnings("java:S2083")
    private static Path resolveValidatedFilePath(String rawPath, String label) {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException(label + " path vazio.");
        }

        Path baseDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path candidate = Paths.get(rawPath);
        Path resolved = (candidate.isAbsolute() ? candidate : baseDir.resolve(candidate)).normalize().toAbsolutePath();

        // Bloqueia escapes do diretorio base (../../...).
        if (!resolved.startsWith(baseDir)) {
            throw new IllegalArgumentException(label + " fora da diretoria permitida.");
        }

        return resolved;
    }

    /**
     * Carrega keystore do utilizador para acesso ao certificado e chave privada.
     */
    @SuppressWarnings({"java:S2083", "java:S3329"})
    private static KeyStore loadUserKeyStore(String keystorePath, String keystorePassword) {
        Path path;
        try {
            path = resolveValidatedFilePath(keystorePath, "Keystore");
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
            return null;
        }

        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            System.err.println("Keystore do utilizador nao encontrado ou sem permissoes de leitura: " + path);
            System.exit(-1);
        }

        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fis, keystorePassword.toCharArray()); // NOSONAR - password local do operador
            return keyStore;
        } catch (Exception e) {
            System.err.println("Nao foi possivel carregar a keystore do utilizador: " + e.getMessage());
            System.exit(-1);
            return null;
        }
    }

    /**
     * Ponto de entrada da aplicacao cliente.
     */
    public static void main(String[] args) {
        // O cliente tem de arrancar com 7 argumentos porque precisa de saber:
        // - onde está o servidor
        // - que truststore usar para confiar no certificado do servidor
        // - que keystore usar para identificar o utilizador localmente
        // - qual o userId e password para a autenticação na aplicação
        if (args.length != 7) {
            System.err.println("Uso: SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>");
            System.exit(-1);
        }

        // Leitura e separação dos argumentos de arranque.
        ServerAddress server = validateServerAddress(args[0]);
        String truststorePath = args[1];
        String truststorePassword = args[2];
        String keystorePath = args[3];
        String keystorePassword = args[4];
        String userId = args[5];
        String password = args[6];

        // Proteção básica contra argumentos vazios, que dariam erros mais à frente.
        if (truststorePath.isEmpty() || truststorePassword.isEmpty() || keystorePath.isEmpty() || keystorePassword.isEmpty() || userId.isEmpty() || password.isEmpty()) {
            System.err.println("Truststore, password-truststore, keystore, password-keystore, user-id e password nao podem estar vazios.");
            System.exit(-1);
        }

        // A truststore é o ficheiro local que guarda certificados confiáveis.
        // Aqui é carregada antes de qualquer ligação TLS para que o cliente
        // saiba validar o certificado apresentado pelo servidor.
        if (initTruststore(truststorePath, truststorePassword)) {
            System.out.println("Truststore carregado com sucesso.");
        } else {
            System.err.println("Erro ao carregar truststore.");
            System.exit(-1);
        }

        // A keystore guarda o certificado e a chave privada do cliente.
        // Esta chave privada é usada em operações como unwrap de chaves de secção.
        userKeyStore = loadUserKeyStore(keystorePath, keystorePassword);
        keyPasswordChars = keystorePassword.toCharArray();

        // Cria a instância do cliente e a camada de rede TLS.
        SpertaClient client = new SpertaClient();
        network = new ClientNetwork();

        // Estabelece ligação TLS segura com o servidor.
        if (!network.initClientNetwork(server.host, server.port, truststorePath, truststorePassword)) {
            System.exit(-1);
        }

        // Só depois de TLS e configurações prontas é que o fluxo principal começa.
        client.run(userId, password);
    }

    /**
     * Inicializa truststore a partir de ficheiro local.
     */
    @SuppressWarnings({"java:S2083", "java:S3329"})
    public static boolean initTruststore(String path, String password) {
        try {
            // Normaliza e valida o caminho para evitar path traversal.
            Path trustPath = resolveValidatedFilePath(path, "Truststore");
            if (!Files.isRegularFile(trustPath) || !Files.isReadable(trustPath)) {
                System.err.println("Truststore nao encontrado ou sem permissoes de leitura: " + trustPath);
                return false;
            }

            // Carrega o KeyStore do disco para memória.
            try (FileInputStream fis = new FileInputStream(trustPath.toFile())) {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(fis, password.toCharArray()); // NOSONAR - password local do operador
            }

            // Guarda o caminho/password para permitir alterações persistentes
            // como acrescentar certificados novos durante a execução.
            trustStorePath = trustPath.toString();
            trustStorePassword = password.toCharArray();
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao carregar keystore do utilizador: " + e.getMessage());
            return false;
        }
    }

    /**
     * Persiste truststore atual em disco.
     */
    public static boolean saveTrustStore() {
        try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
            trustStore.store(fos, trustStorePassword);
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao salvar truststore: " + e.getMessage());
            return false;
        }
    }

    /**
     * Traduz resposta de autenticacao do servidor para comportamento do cliente.
     */
    private boolean isAuthenticatedResponse(String authResponse, String userId) {
        if (authResponse == null) {
            return false;
        }

        // Se o servidor disser que é um utilizador novo, o cliente envia o seu
        // certificado para o servidor o guardar e associar ao userId.
        if ("OK-NEW-USER".equals(authResponse)) {
            return sendClientCertificate(userId);
        }

        // Se o utilizador já existir, tentamos garantir que o certificado dele
        // está disponível localmente para operações futuras de cifragem/partilha.
        if ("OK-USER".equals(authResponse)) {
            fetchCertificateFromServer(userId); // best-effort
            return true;
        }

        return false;
    }

    /**
     * Processo de autenticacao por userId/password.
     */
    private boolean authenticate(Scanner sc, String userId, String password) {
        // O protocolo começa sempre com envio do userId e da password.
        // O servidor responde depois com o estado da autenticação.
        network.send(userId);
        network.send(password);

        String authResponse = (String) network.receive();
        System.out.println("Servidor: " + authResponse);

        // Se a password estiver errada, o cliente dá uma segunda oportunidade.
        // Isto evita terminar logo a sessão por um simples erro de digitação.
        if ("WRONG-PWD".equals(authResponse)) {
            System.out.print("Escreva aqui a password correta: ");
            password = sc.nextLine();
            network.send(password);

            authResponse = (String) network.receive();
            System.out.println("Servidor: " + authResponse);
        }

        // Quando a autenticação fica válida, o cliente mostra a ajuda inicial
        // e avança para a fase de comandos interativos.
        if (isAuthenticatedResponse(authResponse, userId)) {
            System.out.println("Conectado a main.server!");
            System.out.println(HELP_TEXT);
            return true;
        }

        // Mensagens específicas para tornar os erros mais claros ao utilizador.
        if ("WRONG-PWD".equals(authResponse)) {
            System.out.println("Password Errada!");
        } else if ("USER-ALREADY-CONNECTED".equals(authResponse)) {
            System.out.println("Este utilizador ja esta ligado noutra sessao.");
        } else {
            System.out.println("A Autenticacao falhou: " + authResponse);
        }

        return false;
    }

    /**
     * Ciclo interativo de comandos apos autenticacao.
     */
    private void commandLoop(Scanner sc, String userId) {
        boolean running = true;

        while (running) {
            // O loop continua até o utilizador escrever exit/quit.
            System.out.print("Insere aqui o comando: ");
            System.out.flush();
            String command = sc.nextLine();

            // Comando de ajuda local, sem ir ao servidor.
            if (command.equalsIgnoreCase("help")) {
                System.out.println(HELP_TEXT);
            // Saída limpa da aplicação.
            } else if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("quit")) {
                running = false;
                System.out.println("A desconectar...");
            } else if (!command.trim().isEmpty()) {
                // Divide o comando em partes para perceber o nome e argumentos.
                String[] parts = command.trim().split("\\s+");
                String commandName = parts[0].toUpperCase();

                // EC é especial: o valor tem de ser cifrado no cliente antes do envio.
                if ("EC".equals(commandName)) {
                    if (parts.length != 4) {
                        System.out.println("ERRO: O correto e: EC <hm> <d> <int>");
                    } else {
                        handleEcCommand(userId, parts[1], parts[2], parts[3]);
                    }
                    continue;
                }

                // Outros comandos seguem o fluxo simples: envia -> recebe resposta.
                network.send(command);

                Object responseObj = network.receive();
                if (!(responseObj instanceof String response)) {
                    System.out.printf("Resposta inesperada do servidor: %s%n", responseObj);
                    continue;
                }

                // RT devolve um payload de estado encriptado que o cliente guarda
                // primeiro em disco para depois o processar localmente.
                if ("OK".equals(response) && "RT".equals(commandName) && parts.length == 2) {
                    String house = parts[1];
                    Path encryptedOut = Paths.get("client_data", userId, "status_" + house + ".enc");
                    Path plainOut = Paths.get("client_data", userId, "status_" + house + ".txt");
                    long sizeBytes = network.receiveFile(encryptedOut);
                    if (sizeBytes >= 0) {
                        if (processRtPayload(encryptedOut, plainOut, userId, house)) {
                            System.out.println("OK");
                            System.out.println("Ficheiro RT decifrado: " + plainOut);
                        } else {
                            System.out.println("Erro ao decifrar ficheiro RT.");
                        }
                    } else {
                        System.out.println("Erro ao receber ficheiro RT.");
                    }
                // RH é semelhante ao RT, mas produz um CSV de histórico por dispositivo.
                } else if ("OK".equals(response) && "RH".equals(commandName) && parts.length == 3) {
                    String house = parts[1];
                    String device = parts[2].toUpperCase();
                    Path encryptedOut = Paths.get("client_data", userId, "history_" + device + "_" + house + ".enc");
                    Path plainOut = Paths.get("client_data", userId, "history_" + device + "_" + house + ".csv");
                    long sizeBytes = network.receiveFile(encryptedOut);
                    if (sizeBytes >= 0) {
                        if (processRhPayload(encryptedOut, plainOut, userId, house, device)) {
                            System.out.println("OK");
                            System.out.println("Ficheiro RH decifrado: " + plainOut);
                        } else {
                            System.out.println("Erro ao decifrar ficheiro RH.");
                        }
                    } else {
                        System.out.println("Erro ao receber ficheiro RH.");
                    }
                } else {
                    // Nos restantes casos, a resposta é apenas textual.
                    System.out.println(response);
                }

                // Depois de CREATE, o owner gera/publica a chave de cada secção da casa.
                if ("OK".equals(response) && "CREATE".equals(commandName) && parts.length == 2) {
                    if (!bootstrapOwnerSectionKeys(parts[1], userId)) {
                        System.out.println("Aviso: falha ao publicar uma ou mais chaves de secao apos CREATE.");
                    }
                }

                // Depois de ADD, o owner partilha com o novo utilizador as chaves das secções a que ele passa a ter acesso.
                if ("OK".equals(response) && "ADD".equals(commandName) && parts.length == 4) {
                    String targetUser = parts[1];
                    String house = parts[2];
                    String sectionArg = parts[3].trim().toUpperCase();
                    if ("ALL".equals(sectionArg)) {
                        for (String s : HOUSE_SECTIONS) {
                            if (!shareSectionKeyWithUser(house, s, userId, targetUser)) {
                                System.out.println("Aviso: falha ao partilhar chave de secao " + s + " para o utilizador adicionado.");
                            }
                        }
                    } else {
                        String section = normalizeSectionName(sectionArg);
                        if (section != null && !shareSectionKeyWithUser(house, section, userId, targetUser)) {
                            System.out.println("Aviso: falha ao partilhar chave de secao para o utilizador adicionado.");
                        }
                    }
                }
            }
        }
    }

    /**
     * Normaliza secao para 1 letra maiuscula e valida contra lista permitida.
     */
    private String normalizeSectionName(String section) {
        if (section == null) {
            return null;
        }
        String trimmed = section.trim().toUpperCase();
        if (trimmed.length() != 1) {
            return null;
        }
        for (String allowed : HOUSE_SECTIONS) {
            if (allowed.equals(trimmed)) {
                return trimmed;
            }
        }
        return null;
    }

    /**
     * Carrega chave privada do utilizador a partir da keystore local.
     */
    @SuppressWarnings({"java:S2083", "java:S3329"})
    private PrivateKey loadUserPrivateKey(String userId) throws Exception {
        String alias = resolveCertificateAlias(userId);
        if (alias == null) {
            return null;
        }
        Key key = userKeyStore.getKey(alias, keyPasswordChars); // NOSONAR - dados locais confiados
        if (key instanceof PrivateKey privateKey) {
            return privateKey;
        }
        return null;
    }

    /**
     * Gera chave simetrica AES-128 para uma secao.
     */
    private SecretKey generateSectionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    /**
     * Envolve (wrap) chave de secao com chave publica de um certificado destino.
     */
    @SuppressWarnings("java:S5542")
    private byte[] wrapSectionKeyForCertificate(SecretKey sectionKey, Certificate cert) throws Exception {
        // Compatibilidade de protocolo: manter esquema existente.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        return cipher.doFinal(sectionKey.getEncoded());
    }

    /**
     * Desfaz wrap de chave de secao com chave privada local.
     */
    @SuppressWarnings("java:S5542")
    private SecretKey unwrapSectionKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        // Compatibilidade de protocolo: manter esquema existente.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawKey = cipher.doFinal(wrappedKey);
        return new SecretKeySpec(rawKey, "AES");
    }

    /**
     * Publica chave de secao wrapped no servidor para um destinatario.
     */
    @SuppressWarnings("java:S3329")
    private boolean putWrappedSectionKey(String house, String section, String recipient, byte[] wrappedKeyBytes) {
        String payloadB64 = Base64.getEncoder().encodeToString(wrappedKeyBytes);
        network.send("PUTWKEY " + house + " " + section + " " + recipient + " " + payloadB64);
        Object responseObj = network.receive();
        return responseObj instanceof String response && "OK".equals(response);
    }

    /**
     * Pede ao servidor chave wrapped de uma secao para um owner.
     */
    private byte[] getWrappedSectionKey(String house, String section, String owner) {
        network.send("GETWKEY " + house + " " + section + " " + owner);
        Object responseObj = network.receive();
        if (!(responseObj instanceof String response)) {
            return null;
        }
        if (!response.startsWith("OK ")) {
            return null;
        }
        String b64 = response.substring(3).trim();
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Obtem certificado de utilizador, preferindo cache/truststore local e
     * fazendo fallback para GETCERT no servidor.
     */
    private Certificate fetchCertificateFromServer(String user) {
        if (cachedCertificates.containsKey(user)) {
            return cachedCertificates.get(user);
        }

        try {
            Certificate storedCert = trustStore.getCertificate(user);
            if (storedCert != null) {
                cachedCertificates.put(user, storedCert);
                return storedCert;
            }
        } catch (KeyStoreException e) {
            System.err.println("Erro ao ler certificado da truststore para o utilizador: " + user);
            return null;
        }

        network.send("GETCERT " + user);
        Object responseObj = network.receive();
        if (!(responseObj instanceof String response) || !response.startsWith("OK ")) {
            return null;
        }

        String certB64 = response.substring(3).trim();
        try {
            byte[] certBytes = Base64.getDecoder().decode(certB64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));

            // Guarda em cache + truststore para futuras execucoes.
            cachedCertificates.put(user, cert);
            trustStore.setCertificateEntry(user, cert);
            if (!saveTrustStore()) return null;
            return cert;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Apos CREATE, owner gera e publica chaves para todas as secoes da casa.
     */
    private boolean bootstrapOwnerSectionKeys(String house, String userId) {
        try {
            String alias = resolveCertificateAlias(userId);
            if (alias == null) {
                return false;
            }
            Certificate ownerCert = userKeyStore.getCertificate(alias);
            if (ownerCert == null) {
                return false;
            }

            for (String section : HOUSE_SECTIONS) {
                SecretKey sectionKey = generateSectionKey();
                byte[] wrapped = wrapSectionKeyForCertificate(sectionKey, ownerCert);
                if (!putWrappedSectionKey(house, section, userId, wrapped)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Partilha chave de secao de owner para targetUser:
     * 1) obtem wrapped para owner
     * 2) unwrap com private key do owner
     * 3) wrap com cert do target
     * 4) publica no servidor
     */
    private boolean shareSectionKeyWithUser(String house, String section, String ownerUser, String targetUser) {
        try {
            byte[] ownerWrappedKey = getWrappedSectionKey(house, section, ownerUser);
            if (ownerWrappedKey == null) {
                return false;
            }

            PrivateKey ownerPrivateKey = loadUserPrivateKey(ownerUser);
            if (ownerPrivateKey == null) {
                return false;
            }

            SecretKey sectionKey = unwrapSectionKey(ownerWrappedKey, ownerPrivateKey);
            Certificate targetCert = fetchCertificateFromServer(targetUser);
            if (targetCert == null) {
                return false;
            }

            byte[] rewrappedForTarget = wrapSectionKeyForCertificate(sectionKey, targetCert);
            return putWrappedSectionKey(house, section, targetUser, rewrappedForTarget);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Cifra valor inteiro de EC com AES/GCM e devolve [ivB64, ciphertextB64].
     */
    private String[] encryptEcValue(int value, SecretKey sectionKey) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv); // IV unico por mensagem.

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sectionKey, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(Integer.toString(value).getBytes(StandardCharsets.UTF_8));

        return new String[]{
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ciphertext)
        };
    }

    /**
     * Decifra payload EC (ivB64 + ciphertextB64) com chave de secao.
     */
    private String decryptEcValue(String ivB64, String ciphertextB64, SecretKey sectionKey) throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sectionKey, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, StandardCharsets.UTF_8).trim();
    }

    /**
     * Resolve chave de secao usando cache local e wrapped recebido.
     */
    private SecretKey resolveSectionKey(String section, String wrappedB64, Map<String, SecretKey> keyCache, PrivateKey privateKey) throws Exception {
        SecretKey cached = keyCache.get(section);
        if (cached != null) {
            return cached;
        }
        if (wrappedB64 == null || wrappedB64.isBlank()) {
            return null;
        }
        byte[] wrapped = Base64.getDecoder().decode(wrappedB64);
        SecretKey sectionKey = unwrapSectionKey(wrapped, privateKey);
        keyCache.put(section, sectionKey);
        return sectionKey;
    }

    /**
     * Processa ficheiro RT encriptado, decifra por secao e grava texto plano.
     */
    private boolean processRtPayload(Path encryptedPath, Path plainOut, String userId, String house) {
        try {
            List<String> lines = Files.readAllLines(encryptedPath, StandardCharsets.UTF_8);
            Map<String, String> wrappedKeys = new LinkedHashMap<>();
            List<String> outputLines = new ArrayList<>();
            Map<String, SecretKey> keyCache = new LinkedHashMap<>();
            PrivateKey privateKey = loadUserPrivateKey(userId);
            if (privateKey == null) {
                return false;
            }

            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || "RT".equalsIgnoreCase(line)) {
                    continue;
                }

                String[] parts = line.split("\\s+");

                // Linhas KEY: mapeiam secao -> wrappedKey.
                if (parts.length >= 3 && "KEY".equalsIgnoreCase(parts[0])) {
                    wrappedKeys.put(parts[1], parts[2]);
                    continue;
                }

                // Linhas DATA: contem device, secao, iv e ciphertext.
                if (parts.length == 5 && "DATA".equalsIgnoreCase(parts[0])) {
                    String device = parts[1];
                    String section = parts[2];
                    String ivB64 = parts[3];
                    String ciphertextB64 = parts[4];

                    SecretKey sectionKey = resolveSectionKey(section, wrappedKeys.get(section), keyCache, privateKey);
                    if (sectionKey == null) {
                        return false;
                    }

                    String value = decryptEcValue(ivB64, ciphertextB64, sectionKey);
                    outputLines.add("EC " + house + " " + device + " " + value);
                }
            }

            Path parent = plainOut.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(plainOut, outputLines, StandardCharsets.UTF_8);
            Files.deleteIfExists(encryptedPath); // Limpeza do artefacto cifrado local.
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Processa ficheiro RH encriptado, decifra historico e grava CSV plano.
     */
    private boolean processRhPayload(Path encryptedPath, Path plainOut, String userId, String house, String device) {
        try {
            List<String> lines = Files.readAllLines(encryptedPath, StandardCharsets.UTF_8);
            String section = null;
            String wrappedB64 = null;
            List<String> outputLines = new ArrayList<>();
            outputLines.add("time; command");

            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("RH ")) {
                    continue;
                }
                String[] parts = line.split("\\s+");

                // Linha KEY contem secao + chave wrapped.
                if (parts.length >= 3 && "KEY".equalsIgnoreCase(parts[0])) {
                    section = parts[1];
                    wrappedB64 = parts[2];
                    continue;
                }

                // Linha H contem timestamp + iv + ciphertext.
                if (parts.length == 4 && "H".equalsIgnoreCase(parts[0])) {
                    if (section == null || wrappedB64 == null || wrappedB64.isBlank()) {
                        return false;
                    }
                    PrivateKey privateKey = loadUserPrivateKey(userId);
                    if (privateKey == null) {
                        return false;
                    }
                    SecretKey sectionKey = unwrapSectionKey(Base64.getDecoder().decode(wrappedB64), privateKey);
                    String value = decryptEcValue(parts[2], parts[3], sectionKey);
                    outputLines.add(parts[1] + ";EC " + house + " " + device + " " + value);
                }
            }

            Path parent = plainOut.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(plainOut, outputLines, StandardCharsets.UTF_8);
            Files.deleteIfExists(encryptedPath); // Limpeza do artefacto cifrado local.
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Fluxo EC seguro:
     * 1) valida valor
     * 2) pede wrapped key ao servidor
     * 3) unwrap local com private key
     * 4) cifra valor (AES/GCM)
     * 5) envia payload cifrado
     */
    private void handleEcCommand(String userId, String house, String device, String valueStr) {
        int value;
        try {
            value = Integer.parseInt(valueStr);
        } catch (NumberFormatException e) {
            System.out.println("NOK");
            return;
        }

        // Limite de negocio definido no protocolo.
        if (value < 0 || value > 600) {
            System.out.println("NOK");
            return;
        }

        String normalizedDevice = device.toUpperCase();

        // Pedido inicial para obter contexto e chave wrapped.
        network.send("EC " + house + " " + normalizedDevice);
        Object reqResponseObj = network.receive();
        if (!(reqResponseObj instanceof String reqResponse)) {
            System.out.println("Resposta inesperada do servidor: " + reqResponseObj);
            return;
        }
        if (!reqResponse.startsWith("OK ")) {
            System.out.println(reqResponse);
            return;
        }

        String[] responseParts = reqResponse.split("\\s+", 4);
        if (responseParts.length != 4) {
            System.out.println("NOK");
            return;
        }

        String wrappedKeyB64 = responseParts[3];

        try {
            byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
            PrivateKey requesterPrivateKey = loadUserPrivateKey(userId);
            if (requesterPrivateKey == null) {
                System.out.println("NOK");
                return;
            }

            SecretKey sectionKey = unwrapSectionKey(wrappedKey, requesterPrivateKey);
            String[] encryptedPayload = encryptEcValue(value, sectionKey);

            // Envio final do comando com valor cifrado.
            network.send("EC " + house + " " + normalizedDevice + " " + encryptedPayload[0] + " " + encryptedPayload[1]);
            Object sendResponseObj = network.receive();
            if (sendResponseObj instanceof String sendResponse) {
                System.out.println(sendResponse);
            } else {
                System.out.println("Resposta inesperada do servidor: " + sendResponseObj);
            }
        } catch (Exception e) {
            System.out.println("NOK");
        }
    }

    /**
     * Resolve caminho do JAR do cliente para atestacao.
     */
    private Path resolveClientJarPath() throws IOException {
        try {
            // Tenta primeiro localizar o artefacto em execucao.
            Path clientArtifact = Paths.get(
                    SpertaClient.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .toAbsolutePath()
                    .normalize();

            if (Files.isRegularFile(clientArtifact)) {
                return clientArtifact;
            }

            // Fallback para dist/SpertaClient.jar no projeto.
            Path projectRoot = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
            Path fallbackJar = projectRoot.resolve("dist").resolve("SpertaClient.jar").toAbsolutePath().normalize();
            if (Files.isRegularFile(fallbackJar)) {
                return fallbackJar;
            }

            throw new IOException("A atestacao remota requer um ficheiro SpertaClient.jar disponivel em execucao ou em dist/.");
        } catch (Exception e) {
            throw new IOException("Nao foi possivel localizar o ficheiro SpertaClient.jar em execucao.", e);
        }
    }

    /**
     * Calcula prova de atestacao: SHA-256(nonce || bytesDoJar).
     */
    private byte[] calculateAttestationHash(long nonce, Path clientJarPath) throws IOException {
        try {
            byte[] jarBytes = Files.readAllBytes(clientJarPath);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(nonce).array());
            digest.update(jarBytes);
            return digest.digest();
        } catch (Exception e) {
            throw new IOException("Nao foi possivel calcular a prova de atestacao do cliente.", e);
        }
    }

    /**
     * Executa protocolo de atestacao remota com o servidor.
     */
    private boolean attestation() throws IOException {
        Object nonceObj = network.receive();
        if (!(nonceObj instanceof Long nonce)) {
            System.out.println("ATTESTATION FAILED");
            return false;
        }

        Path clientJarPath = resolveClientJarPath();
        byte[] attestationHash = calculateAttestationHash(nonce, clientJarPath);
        network.send(attestationHash);

        String response = (String) network.receive();
        if ("OK-ATTEST".equals(response)) {
            System.out.println("ATTESTATION OK");
            return true;
        }

        System.out.println("ATTESTATION FAILED");
        return false;
    }

    /**
     * Fluxo de vida principal do cliente ja conectado por TLS.
     */
    public void run(String userId, String password) {
        try (Scanner sc = new Scanner(System.in)) {
            // Hook para garantir fecho da ligacao em CTRL+C.
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                @Override
                public void run() {
                    System.out.println("\nCTRL+C detetado. A fechar o cliente...");
                    network.closeClientNetwork();
                }
            }));

            // 1) Atestacao
            if (!attestation()) {
                System.exit(-1);
            }

            // 2) Autenticacao
            if (authenticate(sc, userId, password)) {
                // 3) Interacao por comandos
                commandLoop(sc, userId);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Resolve alias de certificado na keystore:
     * tenta userId primeiro, caso contrario escolhe primeiro alias com certificado.
     */
    private String resolveCertificateAlias(String userId) throws Exception {
        if (userId != null && !userId.isBlank() && userKeyStore.containsAlias(userId)
                && userKeyStore.getCertificate(userId) != null) {
            return userId;
        }

        Enumeration<String> aliases = userKeyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (userKeyStore.getCertificate(alias) != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Envia certificado do cliente para servidor no onboarding de novo utilizador.
     */
    private boolean sendClientCertificate(String userId) {
        try {
            // O servidor confirma primeiro que quer receber o certificado.
            Object reqObj = network.receive();
            if (!(reqObj instanceof String req) || !"REQ-CERT".equals(req)) {
                System.out.println("Resposta inesperada do servidor durante upload do certificado: " + reqObj);
                return false;
            }

            // Resolve qual o alias correto na keystore local.
            String alias = resolveCertificateAlias(userId);
            if (alias == null) {
                network.send(new byte[0]);
                System.out.println("Nao foi encontrado nenhum certificado na keystore do cliente.");
                return false;
            }

            // Extrai o certificado público que será enviado ao servidor.
            Certificate cert = userKeyStore.getCertificate(alias);
            if (cert == null) {
                network.send(new byte[0]);
                return false;
            }

            // Envia o certificado em bytes codificados ASN.1/X.509.
            byte[] certBytes = cert.getEncoded();
            network.send(certBytes);

            // O servidor confirma se o certificado foi guardado.
            Object responseObj = network.receive();
            if (responseObj instanceof String response && "OK-CERT-STORED".equals(response)) {
                System.out.println("Certificado do cliente enviado com sucesso.");
                return true;
            }
            System.out.println("Falha no upload do certificado: " + responseObj);
            return false;
        } catch (Exception e) {
            System.err.println("Erro ao enviar o certificado do cliente: " + e.getMessage());
        }
        return false;
    }
}
