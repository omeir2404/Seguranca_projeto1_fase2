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
    // =============================================================
    // Estado partilhado do servidor
    // =============================================================
    // users: lista de utilizadores registados e respetivo estado interno.
    private Map<String, String> users;
    // houses: mapa casa -> owner.
    private Map<String, String> houses;
    // permissions: mapa casa -> (utilizador -> secao(s) permitidas).
    private Map<String, Map<String, String>> permissions;
    // deviceState: estado atual de cada dispositivo por casa.
    private Map<String, Map<String, Integer>> deviceState;

    // Ficheiros persistentes encriptados/protegidos com metadados do sistema.
    private static String HOUSES_FILE = "server_data/metadata/homes_registry.txt";
	private static String PERMISSIONS_FILE = "server_data/metadata/permissions.txt";
    private static String HOUSE_METADATA_FILE = "server_data/metadata/house_metadata.txt";
    private static String COUNTERS_FILE = "server_data/metadata/section_counters.txt";
    private static String DEVICE_SECTIONS_FILE = "server_data/metadata/device_sections.txt";
    private static String HOUSE_AUDIT_LOG = "server_data/metadata/houses.log";
    private static String LOG_DIR = "server_data/homes";
    private static final String LOGS_HEADER = "time; command";
    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final Set<String> ALLOWED_SECTIONS = Set.of("M", "G", "L", "P", "B", "E");
        // Canal de rede do servidor para enviar respostas e ficheiros ao cliente.
    private ServerNetwork serverNetwork;

        // Abstração de acesso a ficheiros protegidos, cifrados e assinados.
    private ServerFileManager fileManager;

        /**
         * Construtor.
         *
         * Recebe as estruturas em memória do servidor e inicializa os caminhos
         * para os ficheiros de persistência com base na diretoria de execução.
         */
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
        HOUSE_AUDIT_LOG = serverDataRoot.resolve("metadata").resolve("houses.log").toString();
        LOG_DIR = serverDataRoot.resolve("homes").toString();
        this.serverNetwork = serverNetwork;

        this.fileManager = fileManager;
    }

    /**
     * Lê um ficheiro protegido e devolve as linhas em memória.
     *
     * Este método centraliza o acesso a ficheiros encriptados para não repetir
     * a lógica de criação de diretórios e tratamento de erro.
     */
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

    /**
     * Escreve um conjunto de linhas num ficheiro protegido.
     *
     * O conteúdo é reconstruído como texto antes de ser guardado pelo
     * ServerFileManager.
     */
    private void writeLines(String filePath, List<String> lines) {
        try {
            ensureParentDir(filePath);
            String content = String.join(System.lineSeparator(), lines);
            fileManager.writeProtectedFile(Paths.get(filePath).toAbsolutePath().normalize(), content);
        } catch (Exception e) {
            System.err.println("Erro ao escrever ficheiro encriptado: " + e.getMessage());
        }
    }

    /**
     * Calcula onde deve ficar o CSV do histórico de um dispositivo.
     *
     * A secção é obtida primeiro do mapeamento persistido; se não existir,
     * usa-se a secção inferida do nome do dispositivo.
     */
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

    /**
     * Persiste o mapeamento casa:dispositivo:secao.
     *
     * Isto permite recuperar mais tarde a secção real de um dispositivo,
     * em vez de depender apenas da primeira letra do nome.
     */
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

    /**
     * Lê do ficheiro o mapeamento persistido da secção de um dispositivo.
     */
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

    /**
     * Atualiza o log CSV do dispositivo com o novo comando recebido.
     *
     * O objetivo é manter histórico cronológico de ações por dispositivo.
     */
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

    /**
     * Garante que o diretório pai do ficheiro existe.
     */
    private void ensureParentDir(String filePath) throws IOException {
        Path path = Paths.get(filePath).toAbsolutePath().normalize();
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }

    /**
     * Garante que um ficheiro começa com o cabeçalho esperado.
     */
    private void ensureFileHeader(String filePath, String header) throws IOException {
        List<String> lines = readLines(filePath);
        if (lines.isEmpty() || lines.get(0).trim().isEmpty()) {
            lines.clear();
            lines.add(header);
            writeLines(filePath, lines);
        }
    }

    /**
     * Garante que o cabeçalho do log fica na primeira linha.
     */
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

    /**
     * Acrescenta uma linha a um ficheiro baseado em texto.
     */
    private void appendLine(String filePath, String line) throws IOException {
        List<String> lines = readLines(filePath);
        lines.add(line);
        writeLines(filePath, lines);
    }

    /**
     * Persiste o snapshot completo do mapa de permissões no ficheiro protegido.
     */
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

    /**
     * Inicializa os contadores de dispositivos por secção.
     *
     * Cada nova casa começa com A1/B1/... conforme a secção correspondente.
     */
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

    /**
     * Serializa os contadores numa string do tipo M=1,G=1,...
     */
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

    /**
     * Interpreta a string persistida dos contadores e reconstrói o mapa.
     */
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

    /**
     * Reserva o próximo nome livre para um dispositivo de uma secção.
     *
     * Exemplo: M1, M2, M3... ou P1, P2, ...
     */
    private synchronized String allocateNextDeviceName(String house, String sectionLetter) {
        try {
            ensureFileHeader(COUNTERS_FILE, "House:Section=NextCounter");
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

    /**
     * Regista uma nova casa nos ficheiros de persistência e cria as bases
     * de permissões, metadata, audit log e contadores.
     */
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

    /**
     * Normaliza permissões: remove parênteses, espaços e duplicados.
     */
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

    /**
     * Verifica se o utilizador tem acesso à casa.
     *
     * O owner tem sempre acesso. Outros utilizadores precisam de estar
     * explicitamente listados nas permissões da casa.
     */
    private boolean hasHouseAccess(String house, String user) {
        if (houses.containsKey(house) && user.equals(houses.get(house))) {
            return true;
        }
        Map<String, String> housePermissions = permissions.get(house);
        return housePermissions != null && housePermissions.containsKey(user);
    }

    /**
     * Confirma se uma permissão concedida cobre a secção pedida.
     */
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

    /**
     * Inferência simples da secção pelo nome do dispositivo.
     */
    private String deviceSection(String deviceName) {
        if (deviceName == null || deviceName.isEmpty()) {
            return null;
        }
        return String.valueOf(Character.toUpperCase(deviceName.charAt(0)));
    }

    /**
     * Normaliza a secção para maiúscula e valida se é uma secção permitida.
     */
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

    /**
     * Devolve as secções já usadas por dispositivos da casa.
     */
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

            /**
             * Confirma se todas as secções pedidas existem realmente na casa.
             */
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


    /**
     * CREATE:
     * cria a casa, atribui owner, regista permissões base e inicializa estado.
     */
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

    /**
     * ADD:
     * adiciona um utilizador a uma casa numa ou mais secções.
     */
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


            /**
             * RD:
             * regista um novo dispositivo numa secção da casa e atualiza os contadores.
             */
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
  
        updateDeviceLogs("RD " + house + " " + sectionName, house, deviceName);
        return "OK";
    }


// ################ FUNÇÕES AUXILIARES ################

    /**
     * Verifica permissões de acesso à casa/secção.
     */
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

    /**
     * Confirma se o utilizador pode aceder ao dispositivo com base na secção.
     */
    private boolean hasDeviceAccess(String house, String user, String deviceName) {
        String section = getStoredDeviceSection(house, deviceName);
        if (section == null || section.isBlank()) {
            section = deviceSection(deviceName);
        }
        return checkPermissions(house, user, section);
    }

    /**
     * Verifica se existe pelo menos um dispositivo acessível na casa.
     */
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

    /**
     * GETCERT:
     * devolve o certificado X.509 de um utilizador em Base64.
     */
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

    /**
     * PUTWKEY:
     * guarda no servidor uma chave wrapped associada a uma casa/secção/recipiente.
     */
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

    /**
     * GETWKEY:
     * devolve a chave wrapped da secção para permitir ao cliente fazer unwrap local.
     */
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

    /**
     * EC inicial:
     * valida permissões e devolve a chave wrapped que o cliente precisa para cifrar o valor.
     */
    private String ecRequestCommand(String requester, String house, String device) {
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

    /**
     * EC final:
     * recebe IV+ciphertext já cifrados pelo cliente e guarda o último comando.
     */
    private String ecSendCommand(String requester, String house, String device, String ivB64, String ciphertextB64) {
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

        updateDeviceLogs("EC " + house + " " + normalizedDevice + " " + ivB64 + " " + ciphertextB64, house, normalizedDevice);
        return "OK";
    }

    /**
     * Estrutura auxiliar para cada linha do RT.
     */
    private static final class RtEntry {
        final String device;
        final String section;
        final String ivB64;
        final String ciphertextB64;

        RtEntry(String device, String section, String ivB64, String ciphertextB64) {
            this.device = device;
            this.section = section;
            this.ivB64 = ivB64;
            this.ciphertextB64 = ciphertextB64;
        }
    }

    /**
     * Estrutura auxiliar para cada linha do RH.
     */
    private static final class RhEntry {
        final String timestamp;
        final String ivB64;
        final String ciphertextB64;

        RhEntry(String timestamp, String ivB64, String ciphertextB64) {
            this.timestamp = timestamp;
            this.ivB64 = ivB64;
            this.ciphertextB64 = ciphertextB64;
        }
    }

    /**
     * Recolhe entradas RT acessíveis ao utilizador.
     */
    private List<RtEntry> collectRtEntries(String house, String user) {
        List<RtEntry> entries = new ArrayList<>();
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
            entries.add(new RtEntry(device, sectionName, value.ivB64, value.ciphertextB64));
        }

        return entries;
    }

    /**
     * RT:
     * valida o pedido, confirma existência de chaves e devolve OK antes do envio do ficheiro.
     */
    public String RT(String house, String user) {
        if (!houses.containsKey(house)) {
            return "NOHM";
        }
        if (!hasHouseAccess(house, user)) {
            return "NOPERM";
        }

        List<RtEntry> entries = collectRtEntries(house, user);
        if (entries.isEmpty()) {
            return "NODATA";
        }

        String owner = houses.get(house);
        Set<String> requiredSections = new LinkedHashSet<>();
        for (RtEntry entry : entries) {
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

    /**
     * Constrói e envia o ficheiro RT encriptado ao cliente.
     */
    public void RT_sendFile(String house, String user) {
        List<RtEntry> entries = collectRtEntries(house, user);
        String owner = houses.get(house);
        Map<String, String> wrappedPerSection = new LinkedHashMap<>();
        for (RtEntry entry : entries) {
            wrappedPerSection.computeIfAbsent(entry.section, section -> {
                byte[] wrapped = fileManager.loadWrappedSectionKey(house, section, owner, user);
                if (wrapped == null || wrapped.length == 0) {
                    return null;
                }
                return Base64.getEncoder().encodeToString(wrapped);
            });
        }

        StringBuilder payload = new StringBuilder();
        payload.append("RT").append(System.lineSeparator());
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
        for (RtEntry entry : entries) {
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

    /**
     * Recolhe entradas RH do histórico de um dispositivo.
     */
    private List<RhEntry> collectRhEntries(String house, String device) {
        List<RhEntry> entries = new ArrayList<>();
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
                if (parts.length != 5 || !"EC".equalsIgnoreCase(parts[0])) {
                    continue;
                }
                if (!house.equals(parts[1]) || !device.equalsIgnoreCase(parts[2])) {
                    continue;
                }

                entries.add(new RhEntry(timestamp, parts[3], parts[4]));
            }
        } catch (Exception e) {
            return entries;
        }

        return entries;
    }

    /**
     * RH:
     * valida acesso ao histórico e garante que existe chave wrapped disponível.
     */
    public String RH(String house, String user, String device) {
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

        List<RhEntry> entries = collectRhEntries(house, normalizedDevice);
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

    /**
     * Envia o ficheiro RH encriptado ao cliente.
     */
    public void RH_sendFile(String house, String user, String device) {
        String normalizedDevice = device == null ? null : device.toUpperCase(Locale.ROOT);
        String section = getStoredDeviceSection(house, normalizedDevice);
        if (section == null || section.isBlank()) {
            section = deviceSection(normalizedDevice);
        }
        String sectionName = normalizeSectionName(section);
        String owner = houses.get(house);
        byte[] wrapped = fileManager.loadWrappedSectionKey(house, sectionName, owner, user);
        String wrappedB64 = wrapped == null ? "" : Base64.getEncoder().encodeToString(wrapped);

        List<RhEntry> entries = collectRhEntries(house, normalizedDevice);

        StringBuilder payload = new StringBuilder();
        payload.append("RH2 ").append(house).append(" ").append(normalizedDevice).append(System.lineSeparator());
        payload.append("KEY ").append(sectionName).append(" ").append(wrappedB64).append(System.lineSeparator());
        for (RhEntry entry : entries) {
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

////////////////////////// FUNÇÕES AUXILIARES //////////////////////////

    /**
     * Despachador principal de comandos recebidos do cliente.
     *
     * Interpreta o texto, valida aridade e encaminha para o método correto.
     */
    public String handleCommand(String cmd, String user) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return "ERRO: Não colocou o comando!";
        }

        String[] parts = cmd.trim().split("\\s+");
        // Debug auxiliar para inspecionar o parsing em desenvolvimento.
        System.out.println(Arrays.toString(parts));
        System.out.println(parts.length);
        String comando = parts[0].toUpperCase();

        // Cada case valida o formato e delega para a lógica específica.
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
                if (parts.length == 3) {
                    return ecRequestCommand(user, parts[1], parts[2]);
                }
                if (parts.length == 5) {
                    return ecSendCommand(user, parts[1], parts[2], parts[3], parts[4]);
                }
                if (parts.length >= 4) {
                    return "NOK-PLAINTEXT-DISABLED";
                }
                return "ERRO: O correto e: EC <hm> <d> [<ivB64> <ciphertextB64>]";

            case "RH":
                if (parts.length != 3) {
                    return "ERRO: O correto é: RH <hm> <d>";
                }
                return RH(parts[1], user, parts[2]);

            case "RT":
                if (parts.length != 2) {
                    return "ERRO: O correto é: RT <hm>";
                }
                return RT(parts[1], user);

            default:
                return "ERRO: Comando desconhecido: " + comando;
        }
    }

    /**
     * LS:
     * sem argumento lista casas acessíveis; com casa lista os dispositivos
     * acessíveis dessa casa.
     */
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
                    result.append(deviceName).append("\n");
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
