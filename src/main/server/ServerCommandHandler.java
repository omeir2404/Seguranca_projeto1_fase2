// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ServerCommandHandler {
    
    private Map<String, String> users;
    private Map<String, String> houses;
    private Map<String, Map<String, String>> permissions;
    private Map<String, Map<String, Integer>> deviceState;

    private static String HOUSES_FILE = "server_data/metadata/homes_registry.txt";
	private static String PERMISSIONS_FILE = "server_data/metadata/permissions.txt";
    private static String HOUSE_METADATA_FILE = "server_data/metadata/house_metadata.txt";
    private static String COUNTERS_FILE = "server_data/metadata/section_counters.txt";
    private static String DEVICE_SECTIONS_FILE = "server_data/metadata/device_sections.txt";
    private static String LAST_COMMANDS_FILE = "server_data/states/last_commands.txt";
    private static String HOUSE_AUDIT_LOG = "server_data/metadata/houses.log";
    private static String LOG_DIR = "server_data/homes";
    private static final String LOGS_HEADER = "time; command";
    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final Set<String> ALLOWED_SECTIONS = Set.of("M", "G", "L", "P", "B", "E");
    private ServerNetwork serverNetwork;

    private ServerFileManager fileManager;

    public ServerCommandHandler(Map<String, String> users, Map<String, String> houses, Map<String, Map<String, String>> permissions, Map<String, Map<String, Integer>> deviceState, ServerNetwork serverNetwork, ServerFileManager fileManager) {        Path current = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
		Path projectRoot = current;
        this.users = users;
        this.houses = houses;
        this.permissions = permissions;
        this.deviceState = deviceState;
        Path serverDataRoot = projectRoot.resolve("server_data");
        PERMISSIONS_FILE = serverDataRoot.resolve("metadata").resolve("permissions.txt").toString();
    	HOUSES_FILE = serverDataRoot.resolve("metadata").resolve("homes_registry.txt").toString();
        HOUSE_METADATA_FILE = serverDataRoot.resolve("metadata").resolve("house_metadata.txt").toString();
        COUNTERS_FILE = serverDataRoot.resolve("metadata").resolve("section_counters.txt").toString();
        DEVICE_SECTIONS_FILE = serverDataRoot.resolve("metadata").resolve("device_sections.txt").toString();
        LAST_COMMANDS_FILE = serverDataRoot.resolve("states").resolve("last_commands.txt").toString();
        HOUSE_AUDIT_LOG = serverDataRoot.resolve("metadata").resolve("houses.log").toString();
        LOG_DIR = serverDataRoot.resolve("homes").toString();
        this.serverNetwork = serverNetwork;

        this.fileManager = fileManager;
    }

    private List<String> readLines(String filePath) {
        try {
            ensureParentDir(filePath);
            String content = fileManager.readProtectedFile(Paths.get(filePath).toAbsolutePath().normalize());
            if (content.isEmpty()) return new ArrayList<>();
            return new ArrayList<>(Arrays.asList(content.split("\\r?\\n")));
        } catch (Exception e) {
            System.err.println("Erro ao ler ficheiro encriptado: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private void writeLines(String filePath, List<String> lines) {
        try {
            ensureParentDir(filePath);
            String content = String.join(System.lineSeparator(), lines);
            fileManager.writeProtectedFile(Paths.get(filePath).toAbsolutePath().normalize(), content);
        } catch (Exception e) {
            System.err.println("Erro ao escrever ficheiro encriptado: " + e.getMessage());
        }
    }

    private Path getDeviceLogPath(String house, String device) {
        String section = getStoredDeviceSection(house, device);
        if (section == null || section.isBlank()) {
            section = deviceSection(device);
        }
        if (section == null) {
            section = "UNKNOWN";
        }
        return Paths.get(LOG_DIR, house, section, device + ".csv");
    }

    private synchronized void persistDeviceSection(String house, String device, String sectionName) {
        try {
            ensureFileHeader(DEVICE_SECTIONS_FILE, "House:Device:Section");
            Path mappingPath = Paths.get(DEVICE_SECTIONS_FILE).toAbsolutePath().normalize();
            List<String> lines = Files.exists(mappingPath)
                    ? readLines(DEVICE_SECTIONS_FILE)
                    : new ArrayList<>();

            if (lines.isEmpty()) {
                lines.add("House:Device:Section");
            }

            String key = house + ":" + device + ":";
            String replacement = house + ":" + device + ":" + sectionName;
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

            writeLines(DEVICE_SECTIONS_FILE, lines);
        } catch (IOException e) {
            System.err.println("Erro ao persistir secao do dispositivo: " + e.getMessage());
        }
    }

    private synchronized String getStoredDeviceSection(String house, String device) {
        try {
            Path mappingPath = Paths.get(DEVICE_SECTIONS_FILE).toAbsolutePath().normalize();
            if (!Files.exists(mappingPath)) {
                return null;
            }

            List<String> lines = readLines(DEVICE_SECTIONS_FILE);
            String key = house + ":" + device + ":";

            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (!line.startsWith(key)) {
                    continue;
                }
                String[] parts = line.split(":", 3);
                if (parts.length == 3) {
                    String section = parts[2].trim();
                    if (!section.isEmpty()) {
                        return section;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao ler secao do dispositivo: " + e.getMessage());
        }
        return null;
    }

    private synchronized void persistLastCommandValue(String house, String device, int value) {
        try {
            ensureFileHeader(LAST_COMMANDS_FILE, "Home:Device:Value");
            Path statePath = Paths.get(LAST_COMMANDS_FILE).toAbsolutePath().normalize();
            List<String> lines = readLines(LAST_COMMANDS_FILE);

            if (lines.isEmpty()) {
                lines.add("Home:Device:Value");
            }

            String key = house + ":" + device + ":";
            String replacement = house + ":" + device + ":" + value;
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

            writeLines(LAST_COMMANDS_FILE, lines);
        } catch (IOException e) {
            System.err.println("Erro ao persistir último estado do dispositivo: " + e.getMessage());
        }
    }


    private void updateDeviceLogs(String command, String house, String device){
        try {
            Path logPath = getDeviceLogPath(house, device);
            ensureParentDir(logPath.toString());
            ensureLogHeaderAtTop(logPath, LOGS_HEADER);
            appendLine(logPath.toString(), LocalDateTime.now().format(TS_FORMAT) + ";" + command);

        } catch (Exception e){
            e.printStackTrace();
        }

    }

    private void ensureParentDir(String filePath) throws IOException {
        Path path = Paths.get(filePath).toAbsolutePath().normalize();
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }
    private void ensureFileHeader(String filePath, String header) throws IOException {
        List<String> lines = readLines(filePath);
        if (lines.isEmpty() || lines.get(0).trim().isEmpty()) {
            lines.clear();
            lines.add(header);
            writeLines(filePath, lines);
        }
    }

    private void ensureLogHeaderAtTop(Path logPath, String header) throws IOException {
        List<String> lines = readLines(logPath.toString());
        if (lines.isEmpty()) {
            lines.add(header);
            writeLines(logPath.toString(), lines);
        } else if (!header.equalsIgnoreCase(lines.get(0).trim())) {
            lines.add(0, header);
            writeLines(logPath.toString(), lines);
        }
    }

    private void appendLine(String filePath, String line) throws IOException {
        List<String> lines = readLines(filePath);
        lines.add(line);
        writeLines(filePath, lines);
    }

    private synchronized boolean persistPermissionsSnapshot() {
        try {
            ensureParentDir(PERMISSIONS_FILE);
            Path target = Paths.get(PERMISSIONS_FILE).toAbsolutePath().normalize();
            Path temp = target.resolveSibling(target.getFileName().toString() + ".tmp");

            StringBuilder content = new StringBuilder("House:User:Section");

            List<String> sortedHouses = new ArrayList<>(permissions.keySet());
            Collections.sort(sortedHouses);

            for (String house : sortedHouses) {
                Map<String, String> housePermissions = permissions.get(house);
                if (housePermissions == null || housePermissions.isEmpty()) {
                    continue;
                }

                List<String> sortedUsers = new ArrayList<>(housePermissions.keySet());
                Collections.sort(sortedUsers);

                for (String user : sortedUsers) {
                    String normalized = normalizePermissionValue(housePermissions.get(user));
                    if (normalized == null) {
                        continue;
                    }
                    content.append(System.lineSeparator())
                            .append(house)
                            .append(":")
                            .append(user)
                            .append(":")
                            .append(normalized);
                }
            }

            ensureParentDir(PERMISSIONS_FILE);
            fileManager.writeProtectedFile(Paths.get(PERMISSIONS_FILE).toAbsolutePath().normalize(), content.toString());
            return true;
        } catch (Exception e) {
            System.err.println("Erro ao persistir permissões: " + e.getMessage());
            return false;
        }
    }

    private Map<String, Integer> initialSectionCounters() {
        Map<String, Integer> counters = new LinkedHashMap<>();
        counters.put("M", 1);
        counters.put("G", 1);
        counters.put("L", 1);
        counters.put("P", 1);
        counters.put("B", 1);
        counters.put("E", 1);
        return counters;
    }

    private String countersToString(Map<String, Integer> counters) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : counters.entrySet()) {
            if (!sb.isEmpty()) {
                sb.append(",");
            }
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }

    private Map<String, Integer> parseCounters(String countersStr) {
        Map<String, Integer> counters = initialSectionCounters();
        if (countersStr == null || countersStr.isBlank()) {
            return counters;
        }

        String[] tokens = countersStr.split(",");
        for (String token : tokens) {
            String[] pair = token.split("=", 2);
            if (pair.length != 2) {
                continue;
            }

            String section = normalizeSectionName(pair[0]);
            if (section == null || section.equalsIgnoreCase("all")) {
                continue;
            }

            try {
                int nextId = Integer.parseInt(pair[1].trim());
                if (nextId < 1) {
                    nextId = 1;
                }
                counters.put(section, nextId);
            } catch (NumberFormatException ignored) {
            }
        }
        return counters;
    }

    private synchronized String allocateNextDeviceName(String house, String sectionLetter) {
        try {
            ensureFileHeader(COUNTERS_FILE, "House:Section=NextCounter");
            Path countersPath = Paths.get(COUNTERS_FILE).toAbsolutePath().normalize();
            List<String> lines = readLines(COUNTERS_FILE);
            if (lines.isEmpty()) {
                lines.add("House:Section=NextCounter");
            }

            int houseLineIndex = -1;
            Map<String, Integer> counters = initialSectionCounters();

            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && house.equals(parts[0].trim())) {
                    houseLineIndex = i;
                    counters = parseCounters(parts[1]);
                    break;
                }
            }

            int nextId = counters.getOrDefault(sectionLetter, 1);
            if (nextId < 1) {
                nextId = 1;
            }
            String deviceName = sectionLetter + nextId;
            counters.put(sectionLetter, nextId + 1);

            String updatedLine = house + ":" + countersToString(counters);
            if (houseLineIndex >= 0) {
                lines.set(houseLineIndex, updatedLine);
            } else {
                lines.add(updatedLine);
            }

            writeLines(COUNTERS_FILE, lines);
            return deviceName;
        } catch (Exception e) {
            System.err.println("Erro ao atualizar section counters: " + e.getMessage());
            return null;
        }
    }

    private synchronized boolean addHouseToFile(String house, String owner) {
        String now = LocalDateTime.now().format(TS_FORMAT);
        Map<String, Integer> counters = initialSectionCounters();

        String houseRecord = house + ":" + owner;
        String metadataRecord = house + ":createdAt=" + now;
        String permissionRecord = house + ":" + owner + ":all";
        String counterRecord = house + ":" + countersToString(counters);
        String auditRecord = now + " CREATE " + house + " owner=" + owner;

        try {
            ensureFileHeader(HOUSES_FILE, "House:Owner");
            ensureFileHeader(PERMISSIONS_FILE, "House:User:Section");
            ensureFileHeader(HOUSE_METADATA_FILE, "House:Metadata");
            ensureFileHeader(COUNTERS_FILE, "House:Section=NextCounter");

            appendLine(HOUSES_FILE, houseRecord);
            appendLine(PERMISSIONS_FILE, permissionRecord);
            appendLine(HOUSE_METADATA_FILE, metadataRecord);
            appendLine(COUNTERS_FILE, counterRecord);
            appendLine(HOUSE_AUDIT_LOG, auditRecord);
            return true;
        } catch (IOException e) {
            System.err.println("Erro ao persistir CREATE da casa " + house + ": " + e.getMessage());
            return false;
        }
    }

    private String normalizePermissionValue(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.startsWith("(") && trimmed.endsWith(")") && trimmed.length() >= 2) {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.equalsIgnoreCase("all")) {
            return "all";
        }

        Set<String> sections = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        String[] parts = trimmed.split(",");
        for (String part : parts) {
            String token = normalizeSectionName(part);
            if (token == null || token.equalsIgnoreCase("all")) {
                continue;
            }
            String key = token.toUpperCase();
            if (seen.add(key)) {
                sections.add(key);
            }
        }

        if (sections.isEmpty()) {
            return null;
        }
        return String.join(",", sections);
    }

    private boolean hasHouseAccess(String house, String user) {
        if (houses.containsKey(house) && user.equals(houses.get(house))) {
            return true;
        }
        Map<String, String> housePermissions = permissions.get(house);
        return housePermissions != null && housePermissions.containsKey(user);
    }

    private boolean isAllowedSection(String granted, String requestedSection) {
        String normalizedGranted = normalizePermissionValue(granted);
        String normalizedRequested = normalizePermissionValue(requestedSection);
        if (normalizedGranted == null || normalizedRequested == null) {
            return false;
        }
        if (normalizedGranted.equalsIgnoreCase("all")) {
            return true;
        }
        if (normalizedRequested.equalsIgnoreCase("all")) {
            return false;
        }

        Set<String> allowed = new LinkedHashSet<>();
        for (String token : normalizedGranted.split(",")) {
            if (!token.isBlank()) {
                allowed.add(token.trim().toUpperCase());
            }
        }
        for (String token : normalizedRequested.split(",")) {
            if (!allowed.contains(token.trim().toUpperCase())) {
                return false;
            }
        }
        return true;
    }

    private String deviceSection(String deviceName) {
        if (deviceName == null || deviceName.isEmpty()) {
            return null;
        }
        return String.valueOf(Character.toUpperCase(deviceName.charAt(0)));
    }

    private String normalizeSectionName(String section) {
        if (section == null) {
            return null;
        }
        String trimmed = section.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        if (trimmed.equalsIgnoreCase("all")) {
            return "all";
        }

        if (trimmed.length() != 1) {
            return null;
        }

        String upper = trimmed.toUpperCase(Locale.ROOT);
        if (ALLOWED_SECTIONS.contains(upper)) {
            return upper;
        }

        return null;
    }

    private Set<String> getExistingSections(String house) {
        Set<String> sections = new LinkedHashSet<>();
        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || devices.isEmpty()) {
            return sections;
        }

        for (String device : devices.keySet()) {
            String section = getStoredDeviceSection(house, device);
            if (section == null || section.isBlank()) {
                section = deviceSection(device);
            }
            String normalized = normalizeSectionName(section);
            if (normalized != null) {
                sections.add(normalized);
            }
        }
        return sections;
    }

    private boolean sectionExistsInHouse(String house, String section) {
        String normalizedSection = normalizeSectionName(section);
        if (normalizedSection == null) {
            return false;
        }
        if ("all".equalsIgnoreCase(normalizedSection)) {
            return true;
        }

        for (String existing : getExistingSections(house)) {
            if (existing.equalsIgnoreCase(normalizedSection)) {
                return true;
            }
        }
        return false;
    }

    private boolean requestedSectionsExistInHouse(String house, String requestedSections) {
        String normalizedRequested = normalizePermissionValue(requestedSections);
        if (normalizedRequested == null) {
            return false;
        }
        if (normalizedRequested.equalsIgnoreCase("all")) {
            return true;
        }

        Set<String> existingSections = getExistingSections(house);
        for (String section : normalizedRequested.split(",")) {
            if (!existingSections.contains(section)) {
                return false;
            }
        }
        return true;
    }


    //Método CREATE
    private String createHouse(String user, String house) {
        if (houses.containsKey(house)) {
            return "NOK";
        }
        houses.put(house, user);
        if (!addHouseToFile(house, user)) {
            houses.remove(house);
            return "NOK";
        }

        Map<String, String> housePermissions = permissions.get(house);
        if (housePermissions == null) {
            housePermissions = new HashMap<>();
            permissions.put(house, housePermissions);
        }
        housePermissions.put(user, "all");
        if (!persistPermissionsSnapshot()) {
            System.err.println("Aviso: Ficheiro de permissões pode estar desatualizado após CREATE.");
        }

        if (!deviceState.containsKey(house)) {
            deviceState.put(house, new HashMap<>());
        }

        return "OK";
    }

    
    //Método ADD
    private String addHouse(String user, String userAdd, String house, String section) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!users.containsKey(userAdd)) {
            return "NOUSER";
        }
        if (!houses.get(house).equals(user)) {
            return "NOPERM";
        }
        if (!requestedSectionsExistInHouse(house, section)) {
            return "NOK";
        }

        Map<String, String> housePermissions = permissions.get(house);
        if (housePermissions == null) {
            housePermissions = new HashMap<>();
            permissions.put(house, housePermissions);
        }

        String normalized = normalizePermissionValue(section);
        if (normalized != null) {
            housePermissions.put(userAdd, normalized);
        }
        if (!persistPermissionsSnapshot()) {
            System.err.println("Aviso: Ficheiro de permissões pode estar desatualizado após ADD.");
        }
        
        return "OK";
    }


    //Método RD (Registar)
    private String registerDevice(String user, String house, String section) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!houses.get(house).equals(user)) {
            return "NOPERM";
        }

        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }

        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null) {
            devices = new HashMap<>();
            deviceState.put(house, devices);
        }

        String deviceName = allocateNextDeviceName(house, sectionName);
        if (deviceName == null) {
            return "NOK";
        }
        devices.put(deviceName, 0);
        persistDeviceSection(house, deviceName, sectionName);
        persistLastCommandValue(house, deviceName, 0);
  
        updateDeviceLogs("RD " + house + " " + sectionName, house, deviceName);
        return "OK";
    }

    // Método EC (Enviar valor)
    public String sendInt(String user, String house, String device, String valueStr){
        if (device != null) {
            device = device.toUpperCase();
        }
        int value;
        try {
            value = Integer.parseInt(valueStr);
        } catch (NumberFormatException e) {
            return "NOK";
        }
        if (value < 0 || value > 600) {
            return "NOK";
        }
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || !devices.containsKey(device)) {
            return "NOD";
        }
        if (!hasDeviceAccess(house, user, device)) {
            return "NOPERM";
        }
        devices.put(device, value);
        persistLastCommandValue(house, device, value);

        updateDeviceLogs("EC " + house + " " + device + " " + value, house, device);
        return "OK";
    }   


    //Método RT (Obtém ficheiro de texto)
    public String RT(String house, String user) {
        if (!houses.containsKey(house)){
            return "NOHM";
        }
        if (!hasHouseAccess(house, user)){
            return "NOPERM"; 
        } 
        Map<String, Integer> devices = deviceState.get(house);
        if (!hasAnyAccessibleDevice(devices, house, user)){
            return "NODATA";
        }

        return "OK";
    }

    public void RT_sendFile(String house, String user) {
        if (!houses.containsKey(house) || deviceState.get(house) == null){
            return;
        }

        List<String> allowedDevices = new LinkedList<>();

        for (String deviceName : deviceState.get(house).keySet()) {
            if (hasDeviceAccess(house, user, deviceName)) {
                allowedDevices.add(deviceName);
            }
        }

        Collections.sort(allowedDevices);
        File lineSeparatorFile = new File(Paths.get(LOG_DIR, "lineSeparator.txt").toString());
        try {
            ensureParentDir(lineSeparatorFile.getPath());
            if (!lineSeparatorFile.exists()) {
                Files.writeString(lineSeparatorFile.toPath(), System.lineSeparator(), StandardCharsets.UTF_8, StandardOpenOption.CREATE);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<InputStream> files = new LinkedList<>();
        final long[] totalSize = {0};
        Map<String, Integer> houseDevices = deviceState.get(house);
        for (String deviceName : allowedDevices) {
            try {
                Integer currentValue = houseDevices.get(deviceName);
                if (currentValue == null) {
                    continue;
                }

                String line = "EC " + house + " " + deviceName + " " + currentValue;
                byte[] lineBytes = line.getBytes(StandardCharsets.UTF_8);

                files.add(new ByteArrayInputStream(lineBytes));
                files.add(new FileInputStream(lineSeparatorFile));
                totalSize[0] += lineBytes.length + lineSeparatorFile.length();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }

        try (SequenceInputStream statusStream = new SequenceInputStream(Collections.enumeration(files))) {
            serverNetwork.send("OK");
            serverNetwork.sendFile(statusStream, totalSize[0]);

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    // Método RH (Obter histórico)
    public String historic(String house, String user, String device){
        if (device != null) {
            device = device.toUpperCase();
        }
        if(!houses.containsKey(house)){
            return "NOHM";
        }
        if (!hasDeviceAccess(house, user, device)) {
            return "NOPERM";
        }
        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || !devices.containsKey(device)) {
            return "NOD";
        }
        File logFile = getDeviceLogPath(house, device).toFile();
        if (!logFile.exists()) {
            System.out.println("Nenhum log encontrado para o dispositivo: " + device + " na casa: " + house);
            return "NODATA";
        }
        
        return "OK";
    }

 
public void RH_sendFile(String house, String device) {
        if (device != null) {
            device = device.toUpperCase();
        }

        serverNetwork.send("OK");
        Path logPath = getDeviceLogPath(house, device);
        File logFile = logPath.toFile();
        
        if (logFile.exists()) {
            try {
                // Read and decrypt the file
                String decryptedContent = fileManager.readProtectedFile(logPath);
                byte[] bytes = decryptedContent.getBytes(StandardCharsets.UTF_8);
                
                // Wrap in streams so ServerNetwork.sendFile(SequenceInputStream) accepts it
                InputStream is = new ByteArrayInputStream(bytes);
                SequenceInputStream sis = new SequenceInputStream(Collections.enumeration(Arrays.asList(is)));
                
                serverNetwork.sendFile(sis, bytes.length);
            } catch (Exception e) {
                System.err.println("Erro a desencriptar log para envio: " + e.getMessage());
            }
        } else {
            System.out.println("Nenhum log encontrado para o dispositivo: " + device + " na casa: " + house);
        }
    }


// ################FUNÇÕES AUXILIARES################

    private boolean checkPermissions(String house, String user, String section) {
        if (!houses.containsKey(house)) {
            System.out.println("A casa não existe.");
            return false;
        }
        if (user.equals(houses.get(house))) {
            return true;
        }
        Map<String, String> housePermissions = permissions.get(house);
        if (housePermissions == null || !housePermissions.containsKey(user)) {
            System.out.println("As permissões da casa são null ou o utilizador não tem permissão.");
            return false;
        }
        return isAllowedSection(housePermissions.get(user), section);
    }

    private boolean hasDeviceAccess(String house, String user, String deviceName) {
        String section = getStoredDeviceSection(house, deviceName);
        if (section == null || section.isBlank()) {
            section = deviceSection(deviceName);
        }
        return checkPermissions(house, user, section);
    }

    private boolean hasAnyAccessibleDevice(Map<String, Integer> devices, String house, String user) {
        if (devices == null || devices.isEmpty()) {
            return false;
        }
        for (String deviceName : devices.keySet()) {
            if (hasDeviceAccess(house, user, deviceName)) {
                return true;
            }
        }
        return false;
    }

    private String getCertCommand(String targetUser) {
        if (targetUser == null || targetUser.isBlank()) {
            return "NOK";
        }
        if (!users.containsKey(targetUser)) {
            return "NOUSER";
        }
        byte[] certBytes = fileManager.readUserCertificateBytes(targetUser);
        if (certBytes == null || certBytes.length == 0) {
            return "NOCERT";
        }
        return "OK " + Base64.getEncoder().encodeToString(certBytes);
    }

    private String putWrappedKeyCommand(String requester, String house, String section, String recipient, String wrappedKeyB64) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!requester.equals(houses.get(house))) {
            return "NOPERM";
        }
        if (!users.containsKey(recipient)) {
            return "NOUSER";
        }

        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }

        try {
            byte[] wrappedBytes = Base64.getDecoder().decode(wrappedKeyB64);
            if (wrappedBytes.length == 0) {
                return "NOK";
            }
            boolean stored = fileManager.saveWrappedSectionKey(house, sectionName, requester, recipient, wrappedBytes);
            return stored ? "OK" : "NOK";
        } catch (IllegalArgumentException e) {
            return "NOK";
        }
    }

    private String getWrappedKeyCommand(String requester, String house, String section, String owner) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }
        if (!users.containsKey(owner)) {
            return "NOUSER";
        }
        if (!checkPermissions(house, requester, sectionName)) {
            return "NOPERM";
        }

        byte[] wrappedBytes = fileManager.loadWrappedSectionKey(house, sectionName, owner, requester);
        if (wrappedBytes == null || wrappedBytes.length == 0) {
            return "NOKEY";
        }
        return "OK " + Base64.getEncoder().encodeToString(wrappedBytes);
    }

    private String ec2RequestCommand(String requester, String house, String device) {
        String normalizedDevice = device == null ? null : device.toUpperCase(Locale.ROOT);
        if (!houses.containsKey(house)) {
            return "NOHM";
        }

        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || !devices.containsKey(normalizedDevice)) {
            return "NOD";
        }

        String section = getStoredDeviceSection(house, normalizedDevice);
        if (section == null || section.isBlank()) {
            section = deviceSection(normalizedDevice);
        }
        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }

        if (!checkPermissions(house, requester, sectionName)) {
            return "NOPERM";
        }

        String owner = houses.get(house);
        if (owner == null || owner.isBlank()) {
            return "NOK";
        }

        byte[] wrappedKey = fileManager.loadWrappedSectionKey(house, sectionName, owner, requester);
        if (wrappedKey == null || wrappedKey.length == 0) {
            return "NOKEY";
        }

        return "OK " + sectionName + " " + owner + " " + Base64.getEncoder().encodeToString(wrappedKey);
    }

    private String ec2SendCommand(String requester, String house, String device, String ivB64, String ciphertextB64) {
        String normalizedDevice = device == null ? null : device.toUpperCase(Locale.ROOT);
        if (!houses.containsKey(house)) {
            return "NOHM";
        }

        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || !devices.containsKey(normalizedDevice)) {
            return "NOD";
        }

        String section = getStoredDeviceSection(house, normalizedDevice);
        if (section == null || section.isBlank()) {
            section = deviceSection(normalizedDevice);
        }
        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }

        if (!checkPermissions(house, requester, sectionName)) {
            return "NOPERM";
        }

        try {
            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
            if (iv.length == 0 || ciphertext.length == 0) {
                return "NOK";
            }
        } catch (IllegalArgumentException e) {
            return "NOK";
        }

        if (!fileManager.saveEncryptedLastCommand(house, normalizedDevice, ivB64, ciphertextB64)) {
            return "NOK";
        }

        updateDeviceLogs("EC2 " + house + " " + normalizedDevice + " " + ivB64 + " " + ciphertextB64, house, normalizedDevice);
        return "OK";
    }

    private static final class Rt2Entry {
        final String device;
        final String section;
        final String ivB64;
        final String ciphertextB64;

        Rt2Entry(String device, String section, String ivB64, String ciphertextB64) {
            this.device = device;
            this.section = section;
            this.ivB64 = ivB64;
            this.ciphertextB64 = ciphertextB64;
        }
    }

    private static final class Rh2Entry {
        final String timestamp;
        final String ivB64;
        final String ciphertextB64;

        Rh2Entry(String timestamp, String ivB64, String ciphertextB64) {
            this.timestamp = timestamp;
            this.ivB64 = ivB64;
            this.ciphertextB64 = ciphertextB64;
        }
    }

    private List<Rt2Entry> collectRt2Entries(String house, String user) {
        List<Rt2Entry> entries = new ArrayList<>();
        Map<String, ServerFileManager.EncryptedLastCommand> encrypted = fileManager.loadEncryptedLastCommandsByHouse(house);
        if (encrypted.isEmpty()) {
            return entries;
        }

        List<String> devices = new ArrayList<>(encrypted.keySet());
        Collections.sort(devices);
        for (String device : devices) {
            if (!hasDeviceAccess(house, user, device)) {
                continue;
            }

            String section = getStoredDeviceSection(house, device);
            if (section == null || section.isBlank()) {
                section = deviceSection(device);
            }
            String sectionName = normalizeSectionName(section);
            if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
                continue;
            }

            ServerFileManager.EncryptedLastCommand value = encrypted.get(device);
            if (value == null) {
                continue;
            }
            entries.add(new Rt2Entry(device, sectionName, value.ivB64, value.ciphertextB64));
        }

        return entries;
    }

    public String RT2(String house, String user) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!hasHouseAccess(house, user)) {
            return "NOPERM";
        }

        List<Rt2Entry> entries = collectRt2Entries(house, user);
        if (entries.isEmpty()) {
            return "NODATA";
        }

        String owner = houses.get(house);
        Set<String> requiredSections = new LinkedHashSet<>();
        for (Rt2Entry entry : entries) {
            requiredSections.add(entry.section);
        }
        for (String section : requiredSections) {
            byte[] wrapped = fileManager.loadWrappedSectionKey(house, section, owner, user);
            if (wrapped == null || wrapped.length == 0) {
                return "NOKEY";
            }
        }

        return "OK";
    }

    public void RT2_sendFile(String house, String user) {
        List<Rt2Entry> entries = collectRt2Entries(house, user);
        String owner = houses.get(house);
        Map<String, String> wrappedPerSection = new LinkedHashMap<>();
        for (Rt2Entry entry : entries) {
            wrappedPerSection.computeIfAbsent(entry.section, section -> {
                byte[] wrapped = fileManager.loadWrappedSectionKey(house, section, owner, user);
                if (wrapped == null || wrapped.length == 0) {
                    return null;
                }
                return Base64.getEncoder().encodeToString(wrapped);
            });
        }

        StringBuilder payload = new StringBuilder();
        payload.append("RT2").append(System.lineSeparator());
        for (Map.Entry<String, String> keyEntry : wrappedPerSection.entrySet()) {
            if (keyEntry.getValue() == null) {
                continue;
            }
            payload.append("KEY ")
                    .append(keyEntry.getKey())
                    .append(" ")
                    .append(keyEntry.getValue())
                    .append(System.lineSeparator());
        }
        for (Rt2Entry entry : entries) {
            payload.append("DATA ")
                    .append(entry.device)
                    .append(" ")
                    .append(entry.section)
                    .append(" ")
                    .append(entry.ivB64)
                    .append(" ")
                    .append(entry.ciphertextB64)
                    .append(System.lineSeparator());
        }

        byte[] bytes = payload.toString().getBytes(StandardCharsets.UTF_8);
        try (InputStream is = new ByteArrayInputStream(bytes);
             SequenceInputStream sis = new SequenceInputStream(Collections.enumeration(Collections.singletonList(is)))) {
            serverNetwork.send("OK");
            serverNetwork.sendFile(sis, bytes.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private List<Rh2Entry> collectRh2Entries(String house, String device) {
        List<Rh2Entry> entries = new ArrayList<>();
        Path logPath = getDeviceLogPath(house, device);
        try {
            String content = fileManager.readProtectedFile(logPath);
            if (content.isBlank()) {
                return entries;
            }

            String[] lines = content.split("\\r?\\n");
            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("time;")) {
                    continue;
                }

                String[] csv = line.split(";", 2);
                if (csv.length != 2) {
                    continue;
                }

                String timestamp = csv[0].trim();
                String command = csv[1].trim();
                String[] parts = command.split("\\s+");
                if (parts.length != 5 || !"EC2".equalsIgnoreCase(parts[0])) {
                    continue;
                }
                if (!house.equals(parts[1]) || !device.equalsIgnoreCase(parts[2])) {
                    continue;
                }

                entries.add(new Rh2Entry(timestamp, parts[3], parts[4]));
            }
        } catch (Exception e) {
            return entries;
        }

        return entries;
    }

    public String RH2(String house, String user, String device) {
        String normalizedDevice = device == null ? null : device.toUpperCase(Locale.ROOT);
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!hasDeviceAccess(house, user, normalizedDevice)) {
            return "NOPERM";
        }
        Map<String, Integer> devices = deviceState.get(house);
        if (devices == null || !devices.containsKey(normalizedDevice)) {
            return "NOD";
        }

        List<Rh2Entry> entries = collectRh2Entries(house, normalizedDevice);
        if (entries.isEmpty()) {
            return "NODATA";
        }

        String section = getStoredDeviceSection(house, normalizedDevice);
        if (section == null || section.isBlank()) {
            section = deviceSection(normalizedDevice);
        }
        String sectionName = normalizeSectionName(section);
        if (sectionName == null || sectionName.equalsIgnoreCase("all")) {
            return "NOK";
        }

        String owner = houses.get(house);
        byte[] wrapped = fileManager.loadWrappedSectionKey(house, sectionName, owner, user);
        if (wrapped == null || wrapped.length == 0) {
            return "NOKEY";
        }

        return "OK";
    }

    public void RH2_sendFile(String house, String user, String device) {
        String normalizedDevice = device == null ? null : device.toUpperCase(Locale.ROOT);
        String section = getStoredDeviceSection(house, normalizedDevice);
        if (section == null || section.isBlank()) {
            section = deviceSection(normalizedDevice);
        }
        String sectionName = normalizeSectionName(section);
        String owner = houses.get(house);
        byte[] wrapped = fileManager.loadWrappedSectionKey(house, sectionName, owner, user);
        String wrappedB64 = wrapped == null ? "" : Base64.getEncoder().encodeToString(wrapped);

        List<Rh2Entry> entries = collectRh2Entries(house, normalizedDevice);

        StringBuilder payload = new StringBuilder();
        payload.append("RH2 ").append(house).append(" ").append(normalizedDevice).append(System.lineSeparator());
        payload.append("KEY ").append(sectionName).append(" ").append(wrappedB64).append(System.lineSeparator());
        for (Rh2Entry entry : entries) {
            payload.append("H ")
                    .append(entry.timestamp)
                    .append(" ")
                    .append(entry.ivB64)
                    .append(" ")
                    .append(entry.ciphertextB64)
                    .append(System.lineSeparator());
        }

        byte[] bytes = payload.toString().getBytes(StandardCharsets.UTF_8);
        try (InputStream is = new ByteArrayInputStream(bytes);
             SequenceInputStream sis = new SequenceInputStream(Collections.enumeration(Collections.singletonList(is)))) {
            serverNetwork.send("OK");
            serverNetwork.sendFile(sis, bytes.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

//////////////////////////FUNÇÕES AUXILIARES/////////////////////////////////////////


    public String handleCommand(String cmd, String user) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return "ERRO: Não colocou o comando!";
        }

        String[] parts = cmd.trim().split("\\s+");
        System.out.println(Arrays.toString(parts));
        System.out.println(parts.length);
        String comando = parts[0].toUpperCase();
    
        switch (comando) {
            case "GETCERT":
                if (parts.length != 2) {
                    return "ERRO: O correto e: GETCERT <user>";
                }
                return getCertCommand(parts[1]);

            case "PUTWKEY":
                if (parts.length != 5) {
                    return "ERRO: O correto e: PUTWKEY <hm> <s> <user> <wrappedKeyB64>";
                }
                return putWrappedKeyCommand(user, parts[1], parts[2], parts[3], parts[4]);

            case "GETWKEY":
                if (parts.length != 4) {
                    return "ERRO: O correto e: GETWKEY <hm> <s> <owner>";
                }
                return getWrappedKeyCommand(user, parts[1], parts[2], parts[3]);

            case "LS":
                if (parts.length > 2) {
                    return "Erro: O correto é: LS ou LS <hm>";
                }
                if (parts.length == 1) {
                    return lsCommand(user, null);
                }
                return lsCommand(user, parts[1]);

            case "CREATE":
                if (parts.length != 2) {
                    return "ERRO: O correto é: CREATE <hm>";
                }
                return createHouse(user, parts[1]);

            case "ADD":
                if (parts.length < 4) {
                    return "ERRO: O correto é:  ADD <user1> <hm> <s1,s2,...>";
                }
                String sectionsArg = String.join("", Arrays.copyOfRange(parts, 3, parts.length));
                return addHouse(user, parts[1], parts[2], sectionsArg);

            case "RD":
                if (parts.length != 3) {
                    return "ERRO: O correto é:  RD <hm> <s>";
                }
                return registerDevice(user, parts[1], parts[2]);

            case "EC":
                if (parts.length != 4) {
                    return "ERRO: O correto é: EC <hm> <d> <int>";
                }
                return sendInt(user, parts[1], parts[2], parts[3]);

            case "EC2-REQ":
                if (parts.length != 3) {
                    return "ERRO: O correto e: EC2-REQ <hm> <d>";
                }
                return ec2RequestCommand(user, parts[1], parts[2]);

            case "EC2-SEND":
                if (parts.length != 5) {
                    return "ERRO: O correto e: EC2-SEND <hm> <d> <ivB64> <ciphertextB64>";
                }
                return ec2SendCommand(user, parts[1], parts[2], parts[3], parts[4]);

            case "RH":
                if (parts.length != 3) {
                    return "ERRO: O correto é: RH <hm> <d>";
                }
                return historic(parts[1], user, parts[2]);

            case "RT2":
                if (parts.length != 2) {
                    return "ERRO: O correto e: RT2 <hm>";
                }
                return RT2(parts[1], user);

            case "RH2":
                if (parts.length != 3) {
                    return "ERRO: O correto e: RH2 <hm> <d>";
                }
                return RH2(parts[1], user, parts[2]);

            case "RT":
                if (parts.length != 2) {
                    return "ERRO: O correto é: RT <hm>";
                }
                return RT(parts[1], user);

            default:
                return "ERRO: Comando desconhecido: " + comando;
        }
    }

    //Lists the houses that the user has access to, and if a house is specified, lists the devices in that house that the user has access to, with their current state.
    private String lsCommand(String user, String house) {
        if (house != null) {
            if (!houses.containsKey(house)) {
                return "NOHM";
            }
            if (!hasHouseAccess(house, user)) {
                return "NOPERM";
            }
            Map<String, Integer> devices = deviceState.get(house);
            if (!hasAnyAccessibleDevice(devices, house, user)) {
                return "NODATA";
            }
            StringBuilder result = new StringBuilder();
            for (String deviceName : devices.keySet()) {
                if (hasDeviceAccess(house, user, deviceName)) {
                    result.append(deviceName).append(" ").append(devices.get(deviceName)).append("\n");
                }
            }
            return result.toString().trim();
        } else {
            StringBuilder result = new StringBuilder();
            for (String houseName : houses.keySet()) {
                if (hasHouseAccess(houseName, user)) {
                    result.append(houseName).append("\n");
                }
            }
            if (result.isEmpty()) {
                return "NODATA";
            }
            return result.toString().trim();
        }
    }


}