// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.server;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages all file I/O operations for the Sperta Server.
 * Handles reading/writing user data, houses, permissions, and device logs.
 * Contains the following methods by sections:

*      ============ FILE LOADING METHODS ============
- loadUsers()
- loadHouses()
- loadPermissions()

*      ============ DEVICE STATE METHODS ============
- rebuildDeviceStateFromPersistence(Map<String, String> houses)

*      ============ LOG FILE METHODS ============
- normalizeLogHeader(Path logPath)
- readLastDeviceValue(Path logPath, String expectedHouse, String expectedDevice)
- extractEcCommandFromLine(String line)
- appendUser(String user, String pass)

*      ============ UTILITY METHODS ============
- getAttestationData()
- printRebuildSummary(Map<String, Integer> restoredPerHouse, int totalRestored)

 */
public class ServerFileManager {

    public static final class EncryptedLastCommand {
        public final String house;
        public final String device;
        public final String ivB64;
        public final String ciphertextB64;

        public EncryptedLastCommand(String house, String device, String ivB64, String ciphertextB64) {
            this.house = house;
            this.device = device;
            this.ivB64 = ivB64;
            this.ciphertextB64 = ciphertextB64;
        }
    }

    private static final String DELIMITER = ":";
    private static final String CSV_EXTENSION = ".csv";
    private static final String HASH_EXTENSION = ".hash";
    private static final String LOG_HEADER = "time; command";
    private static final String EC_COMMAND = "EC";
    private static final int MIN_DEVICE_VALUE = 0;
    private static final int MAX_DEVICE_VALUE = 600;
    private static final String SERVER_DATA_DIR = "server_data";
    private static final String AUTH_DIR = "auth";
    private static final String METADATA_DIR = "metadata";
    private static final String STATES_DIR = "states";
    private static final String HOMES_DIR = "homes";
    private static final String USERS_FILENAME = "users.txt";
    private static final String USERS_HEADER = "User:Hash:Salt";
    private static final String HOUSES_FILENAME = "homes_registry.txt";
    private static final String PERMISSIONS_FILENAME = "permissions.txt";
    private static final String HOUSE_METADATA_FILENAME = "house_metadata.txt";
    private static final String SECTION_COUNTERS_FILENAME = "section_counters.txt";
    private static final String LAST_COMMANDS_FILENAME = "last_commands.txt";
    private static final String ATTESTATION_FILENAME = "attestation.txt";
    private static final String DEFAULT_REFERENCE_CLIENT_JAR = "dist/SpertaClient.jar";
    private static final String CERTS = "certs";
    private static final String KEYS = "keys";

    private Path projectRoot;
    private String usersFile;
    private String housesFile;
    private String permissionsFile;
    private String logsDir;
    private String attestationFile;
    private String certsDir;
    private String keysDir;

    private SecretKey masterKey;
    private static final byte[] MAGIC_HEADER = "SPRT".getBytes(StandardCharsets.UTF_8); // 4 bytes
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    public ServerFileManager() {
        initializeFilePaths();
        ensurePersistenceDirectories();
    }

    /*
     * Encrypted file layout (written by writeProtectedFile):
     * - 4 bytes: MAGIC_HEADER ("SPRT") to identify protected files
     * - 1 byte : version (currently 1)
     * - 1 byte : IV length (typically 12)
     * - N bytes: IV
     * - remaining bytes: AES-GCM ciphertext (ciphertext includes authentication tag)
     *
     * A separate "<filename>.hash" file contains the SHA-256 of the plaintext
     * (in hexadecimal) and is used to detect tampering or incomplete writes.
     */

    public static String generateHashFromString(String content) throws Exception {
        return generateHashFromBytes(content.getBytes(StandardCharsets.UTF_8));
    }

    public static String generateHashFromBytes(byte[] content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(content);

        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public void initCrypto(String password) {
        try {
            Path saltPath = projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve("pbe.salt");
            byte[] salt;
            
            if (Files.exists(saltPath)) {
                salt = Files.readAllBytes(saltPath);
            } else {
                salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                Files.write(saltPath, salt);
            }
            // Deriva uma chave a partir da password mestra usando PBKDF2-HMAC-SHA256.
            // Parâmetros escolhidos:
            // - Iterations: 150000 (balance entre CPU cost e usabilidade)
            // - Key length: 128 bits (AES-128)
            // O salt é persistido em server_data/auth/pbe.salt para permitir a
            // derivação da mesma chave em arrancos subsequentes.
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 150_000, 128);
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            // Master key para cifragem AES-GCM usada por writeProtectedFile/readProtectedFile
            this.masterKey = new SecretKeySpec(keyBytes, "AES");
            
        } catch (Exception e) {
            System.err.println("Erro ao inicializar o motor criptográfico: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void writeProtectedFile(Path path, String content) throws Exception {
        // Cria um IV (nonce) único para esta cifragem. AES-GCM requer um IV
        // não-repetido com a mesma chave para garantir segurança.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Inicializa o cipher em modo ENCRYPT com a masterKey derivada
        // previamente por initCrypto(). O GCMParameterSpec inclui o tamanho da tag.
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        /*
         * Escreve o ficheiro protegido com o seguinte formato:
         * [MAGIC_HEADER (4 bytes)] [version (1 byte)] [ivLength (1 byte)] [iv (N bytes)] [ciphertext (...)]
         * Separámos o hash do plaintext para um ficheiro ".hash" paralelo, de forma a
         * permitir deteção de corrupção/tampering antes de tentar decifrar (ou como
         * forma simples de validar ficheiros binários como certificados).
         */
        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(path))) {
            dos.write(MAGIC_HEADER);
            dos.writeByte(1); // Versão do formato
            dos.writeByte(iv.length);
            dos.write(iv);
            dos.write(ciphertext);
        }

        // Calcula e grava o hash do plaintext para validação de integridade.
        String hash = generateHashFromString(content);
        Path hashPath = path.resolveSibling(path.getFileName().toString() + ".hash");
        Files.writeString(hashPath, hash + System.lineSeparator(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }
    

    public String readProtectedFile(Path path) throws Exception {
        if (!Files.exists(path)) return "";
        
        byte[] fileData = Files.readAllBytes(path);
        if (fileData.length < 4) return new String(fileData, StandardCharsets.UTF_8); // Empty or too small
        
        // Check if it has our encrypted magic header
        if (fileData[0] == MAGIC_HEADER[0] && fileData[1] == MAGIC_HEADER[1] && 
            fileData[2] == MAGIC_HEADER[2] && fileData[3] == MAGIC_HEADER[3]) {
            
            ByteBuffer buffer = ByteBuffer.wrap(fileData);
            buffer.position(4); // Skip magic
            buffer.get(); // Skip version
            int ivLength = buffer.get();
            byte[] iv = new byte[ivLength];
            buffer.get(iv);
            
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        }
        
        // Fallback for reading old plaintext files during the transition
        return new String(fileData, StandardCharsets.UTF_8);
    }


    /**
     * Gera o SHA-256 para um ficheiro (binário ou texto) e devolve em hexadecimal.
     * Utilizado para criar o ficheiro ".hash" que acompanha ficheiros protegidos
     * e certificados binários. Lê o ficheiro em blocos para suportar ficheiros grandes.
     *
     * @param path Caminho para o ficheiro a hashear
     * @return String hexadecimal lowercase com o digest SHA-256
     * @throws Exception em caso de I/O ou falha no MessageDigest
     */
    public static String generateHashFile(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = input.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hashBytes = digest.digest();

        // Converts bytes to lowercase hexadecimal string.
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Backward-compatible overload for existing callers that provide String paths.
    public static String generateHashFile(String path) throws Exception {
        return generateHashFile(Paths.get(path));
    }

    
    private void failIntegrity() {
        System.out.println("NOK-INTEGRITY");
        System.exit(1);
    }

    private String readSavedHash(Path filePath) throws Exception {
        Path hashPath = filePath.resolveSibling(filePath.getFileName().toString() + HASH_EXTENSION);
        if (!Files.isRegularFile(hashPath)) {
            throw new IOException("Hash em falta para " + filePath.getFileName());
        }
        return Files.readString(hashPath).trim();
    }

    public void verifyIntegrity(Path filePath) {
        try {
            if (!Files.exists(filePath)) {
                return;
            }

            String plaintext = readProtectedFile(filePath);
            String calculatedHash = generateHashFromString(plaintext);
            String savedHash = readSavedHash(filePath);
            if (!calculatedHash.equals(savedHash)) {
                failIntegrity();
            }
        } catch (Exception e) {
            failIntegrity();
        }
    }

    /**
     * Verifica a integridade de um ficheiro textual/criptografado comparando
     * o hash calculado do plaintext com o hash guardado em <file>.hash.
     * Em caso de diferença, termina a execução com failIntegrity().
     */
    public void verifyBinaryIntegrity(Path filePath) {
        try {
            if (!Files.exists(filePath)) {
                return;
            }

            byte[] raw = Files.readAllBytes(filePath);
            String calculatedHash = generateHashFromBytes(raw);
            String savedHash = readSavedHash(filePath);
            if (!calculatedHash.equals(savedHash)) {
                failIntegrity();
            }
        } catch (Exception e) {
            failIntegrity();
        }
    }

    public void verifyAllFilesIntegrity() {
        Path serverDataRoot = projectRoot.resolve(SERVER_DATA_DIR).toAbsolutePath().normalize();
        if (!Files.exists(serverDataRoot) || !Files.isDirectory(serverDataRoot)) {
            return;
        }

        try {
            Files.walkFileTree(serverDataRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path filePath, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile()) {
                        return FileVisitResult.CONTINUE;
                    }

                    String fileName = filePath.getFileName().toString();
                    if (fileName.endsWith(HASH_EXTENSION) || fileName.equals("pbe.salt")) {
                        return FileVisitResult.CONTINUE;
                    }

                    if (fileName.endsWith(".bin") || fileName.endsWith(".cer")) {
                        verifyBinaryIntegrity(filePath);
                    } else {
                        verifyIntegrity(filePath);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            failIntegrity();
        }
    }


    //Initializes and validates all file paths based on project structure.
    private void initializeFilePaths() {
        this.projectRoot = findProjectRoot();
        this.usersFile = projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve(USERS_FILENAME).toString();
        this.housesFile = projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(HOUSES_FILENAME).toString();
        this.permissionsFile = projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(PERMISSIONS_FILENAME).toString();
        this.logsDir = projectRoot.resolve(SERVER_DATA_DIR).resolve(HOMES_DIR).toString();
        this.attestationFile = projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve(ATTESTATION_FILENAME).toString();
        this.certsDir = projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve(CERTS).toString();
        this.keysDir = projectRoot.resolve(SERVER_DATA_DIR).resolve(KEYS).toString();
    }

    //Finds the project root directory.
    private Path findProjectRoot() {
        Path current = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path projectRoot = current;

        while (current != null) {
            Path makefile = current.resolve("Makefile");
            Path srcDir = current.resolve("src");
            if (Files.exists(makefile) && Files.isDirectory(srcDir)) {
                projectRoot = current;
                break;
            }
            current = current.getParent();
        }

        return projectRoot;
    }
    public void ensurePersistenceDirectories() {
        Path serverDataRoot = projectRoot.resolve(SERVER_DATA_DIR);
        Path authDir = serverDataRoot.resolve(AUTH_DIR);
        Path metadataDir = serverDataRoot.resolve(METADATA_DIR);
        Path statesDir = serverDataRoot.resolve(STATES_DIR);
        Path homesDir = serverDataRoot.resolve(HOMES_DIR);
        Path certsDirPath = authDir.resolve(CERTS);
        Path keysDirPath = serverDataRoot.resolve(KEYS);

        try {
            Files.createDirectories(authDir);
            Files.createDirectories(certsDirPath);
            Files.createDirectories(keysDirPath);
            Files.createDirectories(metadataDir);
            Files.createDirectories(statesDir);
            Files.createDirectories(homesDir);
        } catch (IOException e) {
            System.err.println("Erro ao preparar estrutura de persistência: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void ensurePersistenceStructure() {
        ensurePersistenceDirectories();

        try {
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve(USERS_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(AUTH_DIR).resolve(ATTESTATION_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(HOUSES_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(PERMISSIONS_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(HOUSE_METADATA_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(METADATA_DIR).resolve(SECTION_COUNTERS_FILENAME));
            ensureProtectedFileExists(projectRoot.resolve(SERVER_DATA_DIR).resolve(STATES_DIR).resolve(LAST_COMMANDS_FILENAME));
        } catch (Exception e) {
            System.err.println("Erro ao preparar estrutura de persistência: " + e.getMessage());
            System.exit(-1);
        }
    }

    private void ensureProtectedFileExists(Path filePath) throws Exception {
        if (!Files.exists(filePath)) {
            Path parent = filePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            writeProtectedFile(filePath, "");
        } else {
            Path hashPath = filePath.resolveSibling(filePath.getFileName().toString() + HASH_EXTENSION);
            if (!Files.exists(hashPath) && Files.size(filePath) == 0L) {
                writeProtectedFile(filePath, "");
            } else if (!Files.exists(hashPath)
                    && filePath.getFileName().toString().equals(ATTESTATION_FILENAME)) {
                // One-time migration path: convert existing plaintext attestation file into
                // protected format with a matching hash so startup integrity checks can run.
                String content = Files.readString(filePath, StandardCharsets.UTF_8);
                writeProtectedFile(filePath, content);
            }
        }
    }



    // ============ FILE LOADING METHODS ============

    /**
     * Loads all users from the users file into a Map.
     */
    public Map<String, String> loadUsers() {
        Map<String, String> users = new HashMap<>();

        try {
            String content = readProtectedFile(Paths.get(usersFile));
            if (content.isEmpty()) return users;

            String[] lines = content.split("\\r?\\n");
            boolean firstLine = true;

            for (String line : lines) {
                if (firstLine) {
                    firstLine = false;
                    continue;
                }

                line = line.trim();
                if (line.isEmpty()) continue;

                String[] parts = line.split(DELIMITER, 3);
                if (parts.length == 3) {
                    String user = parts[0].trim();
                    String hash = parts[1].trim();
                    String salt = parts[2].trim();
                    if (!user.isEmpty()) {
                        users.put(user, hash + DELIMITER + salt);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao ler " + usersFile + ": " + e.getMessage());
            System.exit(-1);
        }

        return users;
    }


    /**
     * Loads all houses from the houses file into a Map.
     */
public Map<String, String> loadHouses() {
        Map<String, String> houses = new HashMap<>();

        try {
            String content = readProtectedFile(Paths.get(housesFile));
            if (content.isEmpty())
                return houses;

            String[] lines = content.split("\\r?\\n");
            boolean firstLine = true;

            for (String line : lines) {
                if (firstLine) {
                    firstLine = false;
                    continue;
                }

                line = line.trim();
                if (line.isEmpty())
                    continue;

                String[] parts = line.split(DELIMITER, 2);
                if (parts.length == 2) {
                    String house = parts[0].trim();
                    String owner = parts[1].trim();
                    if (!house.isEmpty() && !owner.isEmpty()) {
                        houses.put(house, owner);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("ERRO ao ler " + housesFile + ": " + e.getMessage());
        }

        return houses;
    }


    /**
     * Loads all permissions from the permissions file into a nested Map.
     * Map structure: house -> (user -> section)
     */
    public Map<String, Map<String, String>> loadPermissions() {
        Map<String, Map<String, String>> permissions = new HashMap<>();

        try {
            String content = readProtectedFile(Paths.get(permissionsFile));
            if (content.isEmpty()) return permissions;

            String[] lines = content.split("\\r?\\n");
            boolean firstLine = true;

            for (String line : lines) {
                if (firstLine) {
                    firstLine = false;
                    continue;
                }

                line = line.trim();
                if (line.isEmpty()) continue;

                String[] parts = line.split(DELIMITER, 3);
                if (parts.length == 3) {
                    String house = parts[0].trim();
                    String user = parts[1].trim();
                    String section = parts[2].trim();
                    if (!house.isEmpty() && !user.isEmpty() && !section.isEmpty()) {
                        Map<String, String> housePerms = permissions.get(house);
                        if (housePerms == null) {
                            housePerms = new HashMap<>();
                            permissions.put(house, housePerms);
                        }
                        housePerms.put(user, section);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Aviso ao ler " + permissionsFile + ": " + e.getMessage());
        }

        return permissions;
    }

    // ============ DEVICE STATE METHODS ============


    /**
     * Rebuilds device state from persistence (CSV log files).
     * Returns a Map of houses to device states.
     */
    public Map<String, Map<String, Integer>> rebuildDeviceStateFromPersistence(Map<String, String> houses) {
        Map<String, Map<String, Integer>> deviceState = new HashMap<>();
        Map<String, Integer> restoredPerHouse = new HashMap<>();
        int totalRestored = 0;

        for (String house : houses.keySet()) {
            deviceState.putIfAbsent(house, new HashMap<>());
            restoredPerHouse.putIfAbsent(house, 0);
        }

        Path logsDirPath = Paths.get(logsDir).toAbsolutePath().normalize();
        if (!Files.exists(logsDirPath) || !Files.isDirectory(logsDirPath)) {
            printRebuildSummary(restoredPerHouse, totalRestored);
            return deviceState;
        }

        final int[] totalRestoredRef = {totalRestored};

        try {
            Files.walkFileTree(logsDirPath, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path logPath, BasicFileAttributes attrs) {
                    String fileName = logPath.getFileName().toString();
                    if (!fileName.endsWith(CSV_EXTENSION)) {
                        return FileVisitResult.CONTINUE;
                    }

                    normalizeLogHeader(logPath);

                    Path relativePath = logsDirPath.relativize(logPath);
                    if (relativePath.getNameCount() < 3) {
                        return FileVisitResult.CONTINUE;
                    }

                    String house = relativePath.getName(0).toString();
                    String device = fileName.substring(0, fileName.length() - 4);
                    if (!houses.containsKey(house)) {
                        return FileVisitResult.CONTINUE;
                    }

                    int value = readLastDeviceValue(logPath, house, device);

                    Map<String, Integer> houseDevices = deviceState.get(house);
                    if (houseDevices == null) {
                        houseDevices = new HashMap<>();
                        deviceState.put(house, houseDevices);
                    }
                    Integer previous = houseDevices.put(device, value);

                    if (previous == null) {
                        restoredPerHouse.put(house, restoredPerHouse.getOrDefault(house, 0) + 1);
                        totalRestoredRef[0]++;
                    }

                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("Aviso ao reconstruir estado dos dispositivos: " + e.getMessage());
        }

        printRebuildSummary(restoredPerHouse, totalRestoredRef[0]);
        return deviceState;
    }

    // ============ LOG FILE METHODS ============

    /**
     * Normalizes the header of a CSV log file.
     * Ensures the file starts with "time; command" header.
     */
    private void normalizeLogHeader(Path logPath) {
        try {
            if (!Files.exists(logPath)) {
                return;
            }

            String content = readProtectedFile(logPath);
            if (content.isBlank()) {
                writeProtectedFile(logPath, LOG_HEADER + System.lineSeparator());
                return;
            }

            String[] lines = content.split("\\r?\\n", -1);
            String firstLine = lines.length == 0 ? null : lines[0];

            if (!LOG_HEADER.equalsIgnoreCase(firstLine)) {
                writeProtectedFile(logPath, LOG_HEADER + System.lineSeparator() + content);
            }
        } catch (Exception e) {
            System.err.println("Erro ao normalizar cabeçalho do log " + logPath + ": " + e.getMessage());
        }
    }

    /**
     * Reads the last device value from a CSV log file.
     * Parses EC commands and extracts the latest value for the specified device.
     */
    private int readLastDeviceValue(Path logPath, String expectedHouse, String expectedDevice) {
        int lastValue = 0;
        try {
            String content = readProtectedFile(logPath);
            if (content.isBlank()) {
                return lastValue;
            }

            String[] lines = content.split("\\r?\\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("time;")) { 
                    continue; 
                }

                String commandPart = extractEcCommandFromLine(line);
                if (commandPart == null || commandPart.isEmpty()) {
                    continue;
                }

                String[] cmdParts = commandPart.split("\\s+");
                if (cmdParts.length == 4 && EC_COMMAND.equalsIgnoreCase(cmdParts[0])) {
                    if (!expectedHouse.equalsIgnoreCase(cmdParts[1]) || !expectedDevice.equalsIgnoreCase(cmdParts[2])) {
                        continue;
                    }

                    try {
                        int parsed = Integer.parseInt(cmdParts[3]);
                        if (parsed >= MIN_DEVICE_VALUE && parsed <= MAX_DEVICE_VALUE) {
                            lastValue = parsed;
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Aviso ao ler log de dispositivo " + logPath + ": " + e.getMessage());
        }
        return lastValue;
    }

    /**
     * Helper method to extract command from CSV line.
     */
    private String extractEcCommandFromLine(String line) {
        String[] csvParts = line.split(";", 2);
        if (csvParts.length == 2) {
            String first = csvParts[0].trim();
            String second = csvParts[1].trim();

            if (second.toUpperCase().startsWith("EC ")) {
                return second;
            }
            if (first.toUpperCase().startsWith("EC ")) {
                return first;
            }
            return null;
        }

        String raw = line.trim();
        String upperRaw = raw.toUpperCase();
        if (upperRaw.startsWith("EC ")) {
            return raw;
        }
        return null;
    }

    /**
     * Appends a new user to the users file.
     * Thread-safe operation.
     */
    public synchronized void appendUser(String user, String passHash, String saltHex) {
        try {
            Path path = Paths.get(usersFile);
            String content = readProtectedFile(path);
            
            // If the file is completely empty, make sure to add a header first
            if (content.trim().isEmpty()) {
                content = USERS_HEADER;
            }
            
            content += System.lineSeparator() + user + DELIMITER + passHash + DELIMITER + saltHex;
            
            // Re-encrypt and save the entire file
            writeProtectedFile(path, content);
            
        } catch (Exception e) {
            System.err.println("Erro ao escrever em " + usersFile + ": " + e.getMessage());
        }
    }

    private boolean isValidUserIdForPath(String user) {
        if (user == null || user.isBlank()) {
            return false;
        }
        return user.matches("[A-Za-z0-9._-]+");
    }

    public Path getUserCertificatePath(String user) {
        if (!isValidUserIdForPath(user)) {
            throw new IllegalArgumentException("User id inválido para caminho de certificado.");
        }
        try {
            Path base = Paths.get(certsDir).toAbsolutePath().normalize();
            Path target = base.resolve(user + ".cer").normalize();
            if (!target.startsWith(base)) {
                throw new IllegalArgumentException("User id inválido para caminho de certificado.");
            }
            return target;
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException("User id inválido para caminho de certificado.", e);
        }
    }

    public boolean hasUserCertificate(String user) {
        try {
            return Files.isRegularFile(getUserCertificatePath(user));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public synchronized boolean saveUserCertificate(String user, byte[] certBytes) {
        if (certBytes == null || certBytes.length == 0) {
            return false;
        }
        try {
            Path certPath = getUserCertificatePath(user);
            Path parent = certPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            Files.write(certPath, certBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            String hash = generateHashFile(certPath);
            Files.writeString(certPath.resolveSibling(certPath.getFileName().toString() + HASH_EXTENSION),
                    hash + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao guardar certificado de utilizador: " + e.getMessage());
            return false;
        }
    }

    public synchronized byte[] readUserCertificateBytes(String user) {
        try {
            Path certPath = getUserCertificatePath(user);
            if (!Files.isRegularFile(certPath)) {
                return null;
            }
            verifyBinaryIntegrity(certPath);
            return Files.readAllBytes(certPath);
        } catch (Exception e) {
            return null;
        }
    }


    private String sanitizeToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token inválido para caminho de chave.");
        }
        if (!token.matches("[A-Za-z0-9._-]+")) {
            throw new IllegalArgumentException("Token inválido para caminho de chave.");
        }
        return token;
    }

    private Path getWrappedSectionKeyPath(String house, String section, String owner, String recipient) {
        String safeHouse = sanitizeToken(house);
        String safeSection = sanitizeToken(section);
        String safeOwner = sanitizeToken(owner);
        String safeRecipient = sanitizeToken(recipient);

        Path base = Paths.get(keysDir).toAbsolutePath().normalize();
        Path target = base
                .resolve(safeHouse)
                .resolve(safeSection)
                .resolve("key." + safeHouse + "." + safeSection + "." + safeOwner + "." + safeRecipient + ".bin")
                .normalize();
        if (!target.startsWith(base)) {
            throw new IllegalArgumentException("Caminho inválido para chave de secção.");
        }
        return target;
    }

    public synchronized boolean saveWrappedSectionKey(String house, String section, String owner, String recipient, byte[] wrappedKey) {
        if (wrappedKey == null || wrappedKey.length == 0) {
            return false;
        }
        try {
            Path keyPath = getWrappedSectionKeyPath(house, section, owner, recipient);
            Path parent = keyPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(keyPath, wrappedKey, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            String hash = generateHashFile(keyPath);
            Files.writeString(keyPath.resolveSibling(keyPath.getFileName().toString() + HASH_EXTENSION),
                    hash + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao guardar chave de secção cifrada: " + e.getMessage());
            return false;
        }
    }

    public synchronized byte[] loadWrappedSectionKey(String house, String section, String owner, String recipient) {
        try {
            Path keyPath = getWrappedSectionKeyPath(house, section, owner, recipient);
            if (!Files.isRegularFile(keyPath)) {
                return null;
            }
            verifyBinaryIntegrity(keyPath);
            return Files.readAllBytes(keyPath);
        } catch (Exception e) {
            return null;
        }
    }

    private Path getEncryptedLastCommandsPath() {
        return projectRoot
                .resolve(SERVER_DATA_DIR)
                .resolve(STATES_DIR)
                .resolve(LAST_COMMANDS_FILENAME)
                .toAbsolutePath()
                .normalize();
    }

    public synchronized boolean saveEncryptedLastCommand(String house, String device, String ivB64, String ciphertextB64) {
        if (house == null || house.isBlank() || device == null || device.isBlank()) {
            return false;
        }
        if (ivB64 == null || ivB64.isBlank() || ciphertextB64 == null || ciphertextB64.isBlank()) {
            return false;
        }

        try {
            Path target = getEncryptedLastCommandsPath();
            Path parent = target.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            String content = readProtectedFile(target);
            List<String> lines = content.isBlank()
                    ? new ArrayList<>()
                    : new ArrayList<>(Arrays.asList(content.split("\\r?\\n")));

            if (lines.isEmpty() || lines.get(0).trim().isEmpty()) {
                lines.clear();
                lines.add("Home:Device:IV:Ciphertext");
            }

            String key = house + ":" + device + ":";
            String replacement = house + ":" + device + ":" + ivB64 + ":" + ciphertextB64;
            boolean updated = false;

            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.startsWith(key)) {
                    lines.set(i, replacement);
                    updated = true;
                    break;
                }
            }

            if (!updated) {
                lines.add(replacement);
            }

            writeProtectedFile(target, String.join(System.lineSeparator(), lines));
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao persistir estado cifrado EC2: " + e.getMessage());
            return false;
        }
    }

    public synchronized Map<String, EncryptedLastCommand> loadEncryptedLastCommandsByHouse(String house) {
        Map<String, EncryptedLastCommand> result = new LinkedHashMap<>();
        if (house == null || house.isBlank()) {
            return result;
        }

        try {
            Path target = getEncryptedLastCommandsPath();
            String content = readProtectedFile(target);
            if (content.isBlank()) {
                return result;
            }

            String[] lines = content.split("\\r?\\n");
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i].trim();
                if (line.isEmpty()) {
                    continue;
                }

                String[] parts = line.split(":", 4);
                if (parts.length != 4) {
                    continue;
                }

                String lineHouse = parts[0].trim();
                String device = parts[1].trim();
                String ivB64 = parts[2].trim();
                String ciphertextB64 = parts[3].trim();
                if (!lineHouse.equals(house) || device.isEmpty() || ivB64.isEmpty() || ciphertextB64.isEmpty()) {
                    continue;
                }

                result.put(device, new EncryptedLastCommand(lineHouse, device, ivB64, ciphertextB64));
            }
        } catch (Exception e) {
            System.err.println("Erro ao carregar estado cifrado EC2: " + e.getMessage());
        }

        return result;
    }


    // ============ UTILITY METHODS ============

    /**
     * Retrieves the expected attestation data from the attestation file.
     */
    public String getAttestationData() {
        try {
            String content = readProtectedFile(Paths.get(attestationFile).toAbsolutePath().normalize());
            if (content.isBlank()) {
                return null;
            }
            for (String rawLine : content.split("\\r?\\n")) {
                String line = rawLine.trim();
                if (!line.isEmpty()) {
                    return line;
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao ler " + attestationFile + ": " + e.getMessage());
        }
        return null;
    }

    public Path getReferenceClientJarPath() {
        String configuredPath = getAttestationData();
        if (configuredPath == null || configuredPath.isBlank()) {
            configuredPath = DEFAULT_REFERENCE_CLIENT_JAR;
        }

        Path candidate = Paths.get(configuredPath);
        if (!candidate.isAbsolute()) {
            candidate = projectRoot.resolve(candidate);
        }
        return candidate.toAbsolutePath().normalize();
    }

    /**
     * Prints a summary of the device state rebuild process.
     */
    private void printRebuildSummary(Map<String, Integer> restoredPerHouse, int totalRestored) {
        List<String> sortedHouses = new ArrayList<>(restoredPerHouse.keySet());
        Collections.sort(sortedHouses);

        int housesWithRestoredDevices = 0;
        for (String house : sortedHouses) {
            int restored = restoredPerHouse.getOrDefault(house, 0);
            if (restored > 0) {
                housesWithRestoredDevices++;
            }
            System.out.println("[startup][rebuild] house=" + house + " restoredDevices=" + restored);
        }
        System.out.println("[startup][rebuild] totalRestoredDevices=" + totalRestored);
        System.out.println("[startup][rebuild] housesLoaded=" + restoredPerHouse.size() + " housesWithRestoredDevices=" + housesWithRestoredDevices);
    }

    // ============ FILE PATH GETTERS ============

    public String getUsersFile() {
        return usersFile;
    }

    public String getHousesFile() {
        return housesFile;
    }

    public String getPermissionsFile() {
        return permissionsFile;
    }

    public String getLogsDir() {
        return logsDir;
    }

    public String getAttestationFile() {
        return attestationFile;
    }
}
