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
        ensurePersistenceStructure();
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

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 150_000, 128);
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            this.masterKey = new SecretKeySpec(keyBytes, "AES");
            
        } catch (Exception e) {
            System.err.println("Erro ao inicializar o motor criptográfico: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void writeProtectedFile(Path path, String content) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
        
        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(path))) {
            dos.write(MAGIC_HEADER);
            dos.writeByte(1); // Version
            dos.writeByte(iv.length);
            dos.write(iv);
            dos.write(ciphertext);
        }
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

    // Generates the SHA-256 hash for a single file and returns it in hexadecimal format.
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

    //Generates .hash files for all regular files under server_data.
    //Skips files that are already hash files.
    public int generateHashesForServerData() {
        Path serverDataRoot = projectRoot.resolve(SERVER_DATA_DIR).toAbsolutePath().normalize();
        if (!Files.exists(serverDataRoot) || !Files.isDirectory(serverDataRoot)) {
            return 0;
        }

        final int[] generated = {0};

        try {
            Files.walkFileTree(serverDataRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path filePath, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile()) {
                        return FileVisitResult.CONTINUE;
                    }

                    String fileName = filePath.getFileName().toString();
                    if (fileName.endsWith(HASH_EXTENSION)) {
                        return FileVisitResult.CONTINUE;
                    }

                    try {
                        String hash = generateHashFile(filePath);
                        Path hashPath = filePath.resolveSibling(fileName + HASH_EXTENSION);
                        Files.writeString(hashPath, hash + System.lineSeparator());
                        generated[0]++;
                    } catch (Exception e) {
                        System.err.println("Erro ao gerar hash para " + filePath + ": " + e.getMessage());
                    }

                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("Erro ao percorrer ficheiros para gerar hashes: " + e.getMessage());
        }

        return generated[0];
    }
    // TODO check if necessary
    //Verify integrity **after** decryption. Crucial:** If verification fails at any point, print `NOK-INTEGRITY` and terminate immediately.
    public static void verifyIntegrity(String path) throws Exception{
        String newHash = ServerFileManager.generateHashFile(path);
        
        try(BufferedReader reader = new BufferedReader(new FileReader(path + ".hash"))){
            String hashSaved = reader.readLine();
            if(hashSaved != null){
                hashSaved = hashSaved.trim();
            }
            if(!newHash.equals(hashSaved)){
                System.out.println("NOK-INTEGRITY");
                System.exit(1);
            }else{
                System.out.println("OK");
            }
        }catch(IOException e){
            System.out.println("NOK-INTEGRITY");
            System.exit(1);        
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


    public void ensurePersistenceStructure() {
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

            ensureFileExists(authDir.resolve(USERS_FILENAME));
            ensureFileExists(authDir.resolve(ATTESTATION_FILENAME));
            ensureFileExists(metadataDir.resolve(HOUSES_FILENAME));
            ensureFileExists(metadataDir.resolve(PERMISSIONS_FILENAME));
            ensureFileExists(metadataDir.resolve(HOUSE_METADATA_FILENAME));
            ensureFileExists(metadataDir.resolve(SECTION_COUNTERS_FILENAME));
            ensureFileExists(statesDir.resolve(LAST_COMMANDS_FILENAME));
        } catch (IOException e) {
            System.err.println("Erro ao preparar estrutura de persistência: " + e.getMessage());
            System.exit(-1);
        }
    }

    private void ensureFileExists(Path filePath) throws IOException {
        if (!Files.exists(filePath)) {
            Files.createFile(filePath);
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

            String firstLine;
            try (BufferedReader reader = Files.newBufferedReader(logPath)) {
                firstLine = reader.readLine();
            }

            if (firstLine == null) {
                Files.writeString(logPath, LOG_HEADER + System.lineSeparator());
                return;
            }

            if (!LOG_HEADER.equalsIgnoreCase(firstLine)) {
                String content = Files.readString(logPath);
                Files.writeString(logPath, LOG_HEADER + System.lineSeparator() + content);
            }
        } catch (IOException e) {
            System.err.println("Erro ao normalizar cabeçalho do log " + logPath + ": " + e.getMessage());
        }
    }

    /**
     * Reads the last device value from a CSV log file.
     * Parses EC commands and extracts the latest value for the specified device.
     */
    private int readLastDeviceValue(Path logPath, String expectedHouse, String expectedDevice) {
        int lastValue = 0;
        try (BufferedReader reader = Files.newBufferedReader(logPath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("time;")) { 
                    continue; 
                }

                String commandPart = extractEcCommandFromLine(line);
                if (commandPart == null || commandPart.isEmpty()) {
                    continue;
                }

                String[] cmdParts = commandPart.split("\\s+");
                if (cmdParts.length >= 4 && EC_COMMAND.equalsIgnoreCase(cmdParts[0])) {
                    if (!expectedHouse.equalsIgnoreCase(cmdParts[1]) || !expectedDevice.equalsIgnoreCase(cmdParts[2])) {
                        continue;
                    }

                    try {
                        int parsed = Integer.parseInt(cmdParts[3]);
                        if (parsed >= MIN_DEVICE_VALUE && parsed <= MAX_DEVICE_VALUE) {
                            lastValue = parsed;
                        }
                    } catch (NumberFormatException ignored) {
                        System.err.println("Valor inválido no log: " + cmdParts[3]);
                    }
                }
            }
        } catch (IOException e) {
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
            return Files.readAllBytes(keyPath);
        } catch (Exception e) {
            return null;
        }
    }

    public synchronized boolean saveEncryptedLastCommand(String house, String device, String ivB64, String ciphertextB64) {
        if (house == null || house.isBlank() || device == null || device.isBlank()) {
            return false;
        }
        if (ivB64 == null || ivB64.isBlank() || ciphertextB64 == null || ciphertextB64.isBlank()) {
            return false;
        }

        try {
            Path target = Paths.get(lastCommandsEc2File).toAbsolutePath().normalize();
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
            Path target = Paths.get(lastCommandsEc2File).toAbsolutePath().normalize();
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

    public synchronized EncryptedLastCommand loadEncryptedLastCommand(String house, String device) {
        if (device == null || device.isBlank()) {
            return null;
        }
        Map<String, EncryptedLastCommand> byHouse = loadEncryptedLastCommandsByHouse(house);
        return byHouse.get(device);
    }

    // ============ UTILITY METHODS ============

    /**
     * Retrieves the expected attestation data from the attestation file.
     */
    public String getAttestationData() {
        String expectedAttestation = null;
        try (BufferedReader reader = new BufferedReader(new FileReader(attestationFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    expectedAttestation = line;
                    break;
                }
            }
        } catch (IOException e) {
            System.err.println("Erro ao ler " + attestationFile + ": " + e.getMessage());
        }
        return expectedAttestation;
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
