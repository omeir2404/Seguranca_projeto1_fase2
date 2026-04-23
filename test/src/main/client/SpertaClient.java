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

public class SpertaClient {
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
    private static ClientNetwork network;
    private static KeyStore userKeyStore;
    private static KeyStore trustStore;
    private static String trustStorePath;
    private static char[] trustStorePassword;
    private static char[] keyPasswordChars;
    private static final String[] HOUSE_SECTIONS = {"M", "G", "L", "P", "B", "E"};
    private final Map<String, Certificate> cachedCertificates = new LinkedHashMap<>();


    public static class ServerAddress {
        String host;
        int port;
        ServerAddress(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
    

    public static ServerAddress validateServerAddress(String serverAddress) {
        String host;
        int port = 22345; // porta default
        
        if (serverAddress.contains(":")) {
            String[] parts = serverAddress.split(":");
            if (parts.length != 2) {
                System.err.println("Formato do serverAddress inválido. Use: <IP/hostname>[:Port]");
                System.exit(-1);
            }
            
            try {
                port = Integer.parseInt(parts[1]);
                if (port < 1024 || port > 65535) {
                    System.err.println("Porto tem de ser entre 1024 e 65535");
                    System.exit(-1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Número do porto inválido");
                System.exit(-1);
            }

            host = parts[0];
        } else {
            host = serverAddress;
        }
        
        if (host.isEmpty()) {
            System.err.println("Hostname/IP não pode estar vazio.");
            System.exit(-1);
        }
        
        return new ServerAddress(host, port);
    }

    @SuppressWarnings("java:S2083")
    private static Path resolveValidatedFilePath(String rawPath, String label) {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException(label + " path vazio.");
        }

        Path baseDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path candidate = Paths.get(rawPath);
        Path resolved = (candidate.isAbsolute() ? candidate : baseDir.resolve(candidate)).normalize().toAbsolutePath();

        // Prevent path traversal outside the expected working tree.
        if (!resolved.startsWith(baseDir)) {
            throw new IllegalArgumentException(label + " fora da diretoria permitida.");
        }

        return resolved;
    }

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
            System.err.println("Keystore do utilizador não encontrado ou sem permissões de leitura: " + path);
            System.exit(-1);
        }

        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fis, keystorePassword.toCharArray()); // NOSONAR - password provided by local operator for keystore unlock
            return keyStore;
        } catch (Exception e) {
            System.err.println("Não foi possível carregar a keystore do utilizador: " + e.getMessage());
            System.exit(-1);
            return null;
        }
    }


    public static void main(String[] args) {
        if (args.length != 7){
            System.err.println("Uso: SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>");
            System.exit(-1);
        }
        
        ServerAddress server = validateServerAddress(args[0]);
        String truststorePath = args[1];
        String truststorePassword = args[2];
        String keystorePath = args[3];
        String keystorePassword = args[4];
        String userId = args[5];
        String password = args[6];
        
        if (truststorePath.isEmpty() || truststorePassword.isEmpty() || keystorePath.isEmpty() || keystorePassword.isEmpty() || userId.isEmpty() || password.isEmpty()) {
            System.err.println("Truststore, password-truststore, keystore, password-keystore, user-id e password não podem estar vazios.");
            System.exit(-1);
        }


        if(initTruststore(truststorePath, truststorePassword)){
            System.out.println("Truststore carregado com sucesso.");
        } else {
            System.err.println("Erro ao carregar truststore.");
            System.exit(-1);
        }

        userKeyStore = loadUserKeyStore(keystorePath, keystorePassword);
        keyPasswordChars = keystorePassword.toCharArray();
        SpertaClient client = new SpertaClient();
        network = new ClientNetwork();
        if (!network.initClientNetwork(server.host, server.port, truststorePath, truststorePassword)) {
            System.exit(-1);
        }
        client.run(userId, password);
    }


    @SuppressWarnings({"java:S2083", "java:S3329"})
    public static boolean initTruststore(String path, String password){
        try {
            Path trustPath = resolveValidatedFilePath(path, "Truststore");
            if (!Files.isRegularFile(trustPath) || !Files.isReadable(trustPath)) {
                System.err.println("Truststore não encontrado ou sem permissões de leitura: " + trustPath);
                return false;
            }
            try (FileInputStream fis = new FileInputStream(trustPath.toFile())) {
                trustStore = KeyStore.getInstance("JKS");
                trustStore.load(fis, password.toCharArray()); // NOSONAR - password provided by local operator for truststore unlock
            }
            trustStorePath = trustPath.toString();
            trustStorePassword = password.toCharArray();
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao carregar keystore do utilizador: " + e.getMessage());
            return false;
        }
    }

    public static boolean saveTrustStore(){
        try(FileOutputStream fos = new FileOutputStream(trustStorePath)) {
            trustStore.store(fos, trustStorePassword);
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao salvar truststore: " + e.getMessage());
            return false;
        }
    }


    private boolean isAuthenticatedResponse(String authResponse, String userId) {
        if (authResponse == null) {
            return false;
        }

        if ("OK-NEW-USER".equals(authResponse)) {
            return sendClientCertificate(userId);
        }

        if ("OK-USER".equals(authResponse)) {
            Certificate cert = fetchCertificateFromServer(userId);
            if (cert == null) {
                System.err.println("Erro ao obter certificado do utilizador autenticado: " + userId);
                return false;
            }
            return true;
        }

        return false;
    }

    private boolean authenticate(Scanner sc, String userId, String password){
        network.send(userId);
        network.send(password);

        String authResponse = (String) network.receive();
        System.out.println("Servidor: " + authResponse);

        if ("WRONG-PWD".equals(authResponse)) {
            System.out.print("Escreva aqui a password correta: ");
            password = sc.nextLine();
            network.send(password);

            authResponse = (String) network.receive();
            System.out.println("Servidor: " + authResponse);
        }

        if (isAuthenticatedResponse(authResponse, userId)) {
            System.out.println("Conectado a main.server!");
            System.out.println(HELP_TEXT);
            return true;
        }

        if ("WRONG-PWD".equals(authResponse)) {
            System.out.println("Password Errada!");
        } else if ("USER-ALREADY-CONNECTED".equals(authResponse)) {
            System.out.println("Este utilizador já está ligado noutra sessão.");
        } else {
            System.out.println("A Autenticação falhou: " + authResponse);
        }

        return false;
    }

    private void commandLoop(Scanner sc, String userId){
        boolean running = true;

        while (running) {
            System.out.print("Insere aqui o comando: ");
            System.out.flush();
            String command = sc.nextLine();

            if (command.equalsIgnoreCase("help")){
                System.out.println(HELP_TEXT);
            } else if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("quit")) {
                running = false;
                System.out.println("A desconectar...");
            } else if (!command.trim().isEmpty()) {
                String[] parts = command.trim().split("\\s+");
                String commandName = parts[0].toUpperCase();

                if ("EC".equals(commandName)) {
                    if (parts.length != 4) {
                        System.out.println("ERRO: O correto e: EC <hm> <d> <int>");
                    } else {
                        handleEcCommand(userId, parts[1], parts[2], parts[3]);
                    }
                    continue;
                }

                network.send(command);

                Object responseObj = network.receive();
                if (!(responseObj instanceof String response)) {
                    System.out.printf("Resposta inesperada do servidor: %s%n", responseObj);
                    continue;
                }

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
                    System.out.println(response);
                }

                if ("OK".equals(response) && "CREATE".equals(commandName) && parts.length == 2) {
                    if (!bootstrapOwnerSectionKeys(parts[1], userId)) {
                        System.out.println("Aviso: falha ao publicar uma ou mais chaves de secao apos CREATE.");
                    }
                }

                if ("OK".equals(response) && "ADD".equals(commandName) && parts.length == 4) {
                    String targetUser = parts[1];
                    String house = parts[2];
                    String section = normalizeSectionName(parts[3]);
                    if (section != null && !shareSectionKeyWithUser(house, section, userId, targetUser)) {
                        System.out.println("Aviso: falha ao partilhar chave de secao para o utilizador adicionado.");
                    }
                }
            }
        }
    }

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

    @SuppressWarnings({"java:S2083", "java:S3329"})
    private PrivateKey loadUserPrivateKey(String userId) throws Exception {
        String alias = resolveCertificateAlias(userId);
        if (alias == null) {
            return null;
        }
        Key key = userKeyStore.getKey(alias, keyPasswordChars); // NOSONAR - alias/password come from local keystore configuration
        if (key instanceof PrivateKey privateKey) {
            return privateKey;
        }
        return null;
    }

    private SecretKey generateSectionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    @SuppressWarnings("java:S5542")
    private byte[] wrapSectionKeyForCertificate(SecretKey sectionKey, Certificate cert) throws Exception {
        // Compatibilidade de protocolo: servidor e cliente usam o mesmo esquema de wrapping.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        return cipher.doFinal(sectionKey.getEncoded());
    }

    @SuppressWarnings("java:S5542")
    private SecretKey unwrapSectionKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        // Compatibilidade de protocolo: servidor e cliente usam o mesmo esquema de wrapping.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawKey = cipher.doFinal(wrappedKey);
        return new SecretKeySpec(rawKey, "AES");
    }

    @SuppressWarnings("java:S3329")
    private boolean putWrappedSectionKey(String house, String section, String recipient, byte[] wrappedKeyBytes) {
        String payloadB64 = Base64.getEncoder().encodeToString(wrappedKeyBytes);
        network.send("PUTWKEY " + house + " " + section + " " + recipient + " " + payloadB64);
        Object responseObj = network.receive();
        return responseObj instanceof String response && "OK".equals(response);
    }

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

            cachedCertificates.put(user, cert);
            trustStore.setCertificateEntry(user, cert);
            if(!saveTrustStore()) return null;
            return cert;
        } catch (Exception e) {
            return null;
        }
    }

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

    private String[] encryptEcValue(int value, SecretKey sectionKey) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sectionKey, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(Integer.toString(value).getBytes(StandardCharsets.UTF_8));

        return new String[]{
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ciphertext)
        };
    }

    private String decryptEcValue(String ivB64, String ciphertextB64, SecretKey sectionKey) throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sectionKey, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, StandardCharsets.UTF_8).trim();
    }

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
                if (parts.length >= 3 && "KEY".equalsIgnoreCase(parts[0])) {
                    wrappedKeys.put(parts[1], parts[2]);
                    continue;
                }

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
            Files.deleteIfExists(encryptedPath);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

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
                if (parts.length >= 3 && "KEY".equalsIgnoreCase(parts[0])) {
                    section = parts[1];
                    wrappedB64 = parts[2];
                    continue;
                }

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
            Files.deleteIfExists(encryptedPath);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void handleEcCommand(String userId, String house, String device, String valueStr) {
        int value;
        try {
            value = Integer.parseInt(valueStr);
        } catch (NumberFormatException e) {
            System.out.println("NOK");
            return;
        }

        if (value < 0 || value > 600) {
            System.out.println("NOK");
            return;
        }

        String normalizedDevice = device.toUpperCase();
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

    private Path resolveClientJarPath() throws IOException {
        try {
            Path clientArtifact = Paths.get(
                    SpertaClient.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .toAbsolutePath()
                    .normalize();

            if (Files.isRegularFile(clientArtifact)) {
                return clientArtifact;
            }

            Path projectRoot = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
            Path fallbackJar = projectRoot.resolve("dist").resolve("SpertaClient.jar").toAbsolutePath().normalize();
            if (Files.isRegularFile(fallbackJar)) {
                return fallbackJar;
            }

            throw new IOException("A atestação remota requer um ficheiro SpertaClient.jar disponível em execução ou em dist/.");
        } catch (Exception e) {
            throw new IOException("Não foi possível localizar o ficheiro SpertaClient.jar em execução.", e);
        }
    }

    private byte[] calculateAttestationHash(long nonce, Path clientJarPath) throws IOException {
        try {
            byte[] jarBytes = Files.readAllBytes(clientJarPath);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(nonce).array());
            digest.update(jarBytes);
            return digest.digest();
        } catch (Exception e) {
            throw new IOException("Não foi possível calcular a prova de atestação do cliente.", e);
        }
    }

    private boolean attestation() throws IOException{
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

    public void run(String userId, String password) {
        try (Scanner sc = new Scanner(System.in)) {
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                @Override
                public void run() {
                    System.out.println("\nCTRL+C detetado. A fechar o cliente...");
                    network.closeClientNetwork();
                }
            }));
            if(!attestation()){
                System.exit(-1);
            }
            if (authenticate(sc, userId, password)) {
                commandLoop(sc, userId);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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

    private boolean sendClientCertificate(String userId) {
        try {
            Object reqObj = network.receive();
            if (!(reqObj instanceof String req) || !"REQ-CERT".equals(req)) {
                System.out.println("Resposta inesperada do servidor durante upload do certificado: " + reqObj);
                return false;
            }

            String alias = resolveCertificateAlias(userId);
            if (alias == null) {
                network.send(new byte[0]);
                System.out.println("Não foi encontrado nenhum certificado na keystore do cliente.");
                return false;
            }

            Certificate cert = userKeyStore.getCertificate(alias);
            if (cert == null) {
                network.send(new byte[0]);
                return false;
            }

            byte[] certBytes = cert.getEncoded();
            network.send(certBytes);

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
