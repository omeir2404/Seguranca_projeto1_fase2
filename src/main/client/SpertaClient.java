// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.client;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
            " - LS ou LS <hm> # Listar casas com acesso, ou listar dispositivos e temporizadores de uma casa <hm>");
    private static ClientNetwork network;
    private static KeyStore userKeyStore;
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


    private static KeyStore loadUserKeyStore(String keystorePath, String keystorePassword) {
        Path path = Paths.get(keystorePath);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            System.err.println("Keystore do utilizador não encontrado ou sem permissões de leitura: " + path.toAbsolutePath());
            System.exit(-1);
        }

        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fis, keystorePassword.toCharArray());
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

        userKeyStore = loadUserKeyStore(keystorePath, keystorePassword);
        keyPasswordChars = keystorePassword.toCharArray();
        SpertaClient client = new SpertaClient();
        network = new ClientNetwork();
        if (!network.initClientNetwork(server.host, server.port, truststorePath, truststorePassword)) {
            System.exit(-1);
        }
        client.run(userId, password);
    }


    private boolean isAuthenticatedResponse(String authResponse, String userId) {
        if (authResponse == null) {
            return false;
        }

        if ("OK-NEW-USER".equals(authResponse)) {
            return sendClientCertificate(userId);
        }

        return "OK-USER".equals(authResponse);
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

            if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("quit")) {
                running = false;
                System.out.println("A desconectar...");
            } else if (!command.trim().isEmpty()) {
                network.send(command);
                String[] parts = command.trim().split("\\s+");
                String commandName = parts[0].toUpperCase();

                Object responseObj = network.receive();
                if (!(responseObj instanceof String response)) {
                    System.out.printf("Resposta inesperada do servidor: %s%n", responseObj);
                    continue;
                }

                if ("OK".equals(response) && "RT".equals(commandName) && parts.length == 2) {
                    String house = parts[1];
                    Path out = Paths.get("client_data", userId, "status_" + house + ".txt");
                    long sizeBytes = network.receiveFile(out);
                    if (sizeBytes >= 0) {
                        System.out.println("OK");
                        System.out.println("Tamanho recebido: " + sizeBytes + " bytes");
                        System.out.println("Ficheiro RT recebido: " + out);
                    } else {
                        System.out.println("Erro ao receber ficheiro RT.");
                    }
                } else if ("OK".equals(response) && "RH".equals(commandName) && parts.length == 3) {
                    String house = parts[1];
                    String device = parts[2];
                    Path out = Paths.get("client_data", userId, "history_" + device + "_" + house + ".csv");
                    long sizeBytes = network.receiveFile(out);
                    if (sizeBytes >= 0) {
                        System.out.println("OK");
                        System.out.println("Tamanho recebido: " + sizeBytes + " bytes");
                        System.out.println("Ficheiro RH recebido: " + out);
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

    private PrivateKey loadUserPrivateKey(String userId) throws Exception {
        String alias = resolveCertificateAlias(userId);
        if (alias == null) {
            return null;
        }
        Key key = userKeyStore.getKey(alias, keyPasswordChars);
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

    private byte[] wrapSectionKeyForCertificate(SecretKey sectionKey, Certificate cert) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        return cipher.doFinal(sectionKey.getEncoded());
    }

    private SecretKey unwrapSectionKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawKey = cipher.doFinal(wrappedKey);
        return new SecretKeySpec(rawKey, "AES");
    }

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
