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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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

    // ============ INITIALIZATION METHODS ============

    private static void initializeFileManager() {
        fileManager = new ServerFileManager();
    }

	private static void verifyPersistenceStructure() {
		fileManager.ensurePersistenceStructure();
	}

    private static int validateInput(String[] args) {
        if (args.length > 1) {
            System.out.println("Input Inválido: SpertaServer [port]");
            System.exit(-1);
        }
        if (args.length == 0) {
            return 0;
        }
        try {
            int port = Integer.parseInt(args[0]);
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

    public static void initialize_server_vars() {
        users = fileManager.loadUsers();
        houses = fileManager.loadHouses();
        permissions = fileManager.loadPermissions();
        deviceState = fileManager.rebuildDeviceStateFromPersistence(houses);
		activeUsers = ConcurrentHashMap.newKeySet();
    }

    // ============ MAIN ENTRY POINT ============

    public static void main(String[] args) {
        int port = validateInput(args);
        initializeFileManager();
		verifyPersistenceStructure();
        initialize_server_vars();

        if (port == 0) {
            port = DEFAULT_PORT;
        }

        SpertaServer server = new SpertaServer();
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                System.out.println("\nCTRL+C detetado. A fechar o servidor...");
                server.closeServer();
            }
        }));
        server.startServer(port);
    }

    // ============ SERVER MANAGEMENT METHODS ============

    public void startServer(int port) {
        System.out.println("À espera de clientes...");

        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }

        while(running){
            try{
				Socket clientSocket = serverSocket.accept();
                System.out.println("Nova conexão de: " + clientSocket.getInetAddress().getHostAddress());
				ClientHandler clientHandler = new ClientHandler(clientSocket);
				clientHandler.start();
            }catch(IOException e){
                if(running){
                    System.err.println("Erro na conexão: " + e.getMessage());
                }
            }
                
        }
  
    }

    public void closeServer() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                System.out.println("O Servidor fechou!");
            }
        } catch (IOException e) {
            System.err.println("Erro ao fechar o servidor: " + e.getMessage());
        }
    }

    // ============ CLIENT HANDLER (INNER CLASS) ============

    class ClientHandler extends Thread {
    	private Socket socket;
		private ServerCommandHandler commandHandler;
		private ServerNetwork network;
		
    	ClientHandler(Socket sock) {
			this.socket = sock;
			try{
				this.network = new ServerNetwork(sock);
				this.commandHandler = new ServerCommandHandler(users, houses, permissions, deviceState, network);
				System.out.println("Thread do servidor criada para cliente.");
			} catch (Exception e){
				System.out.println("Erro ao criar thread do servidor");
				e.printStackTrace();
			}
    	}

		private int clientInFile(String user, String pass) {
			int correct = -1;
			if (user == null || pass == null) {
				return -1;
			}

			String storedPass = users.get(user);
			if (storedPass == null) {
				users.put(user, pass);
				fileManager.appendUser(user, pass);
				return 1;
			}
			if (storedPass.equals(pass)) {
				correct = 0;
			}

			return correct;
		}

		private boolean attestClient() throws IOException {
			String attestationMessage = (String) network.receive();
			String expectedAttestation = fileManager.getAttestationData();

			boolean valid = false;
			if (expectedAttestation != null && attestationMessage != null && attestationMessage.startsWith("ATTEST ")) {
				String received = attestationMessage.substring("ATTEST ".length()).trim();
				valid = expectedAttestation.equals(received);
			}

			if (valid) {
				network.send("ATTEST OK");
				return true;
			}

			network.send("ATTEST FAILED");
			return false;
		}

		// ============ COMMAND EXECUTION METHODS ============

		private String authenticateClient() throws IOException {
			String user = (String) network.receive();
			String passwd = (String) network.receive();
			System.out.println("Utilizador: " + user + "; Password: " + passwd);

			int authenticated = clientInFile(user, passwd);
			if (user != null && !user.isEmpty() && authenticated >= 0) {
				if (!activeUsers.add(user)) {
					network.send("USER-ALREADY-CONNECTED");
					return null;
				}
				if (authenticated == 1) {
					network.send("OK-NEW-USER");
				} else {
					network.send("OK-USER");
				}
				return user;
			}

			network.send("WRONG-PWD");

			passwd = (String) network.receive();
			System.out.println("Password recebida: " + passwd);
			authenticated = clientInFile(user, passwd);
			if (authenticated >= 0) {
				if (!activeUsers.add(user)) {
					network.send("USER-ALREADY-CONNECTED");
					return null;
				}
				network.send("OK-USER");
				return user;
			}

			return null;
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
						commandHandler.RH_sendFile(house, device);
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