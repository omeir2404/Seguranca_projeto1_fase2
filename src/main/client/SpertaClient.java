// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

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


    public static void main(String[] args) {
        if (args.length != 3){
            System.err.println("Uso: SpertaClient <serverAddress> <user-id> <password>");
            System.exit(-1);
        }
        
        ServerAddress server = validateServerAddress(args[0]);
        String userId = args[1];
        String password = args[2];
        
        if (userId.isEmpty() || password.isEmpty()) {
            System.err.println("User-id e password não podem estar vazios.");
            System.exit(-1);
        }

        SpertaClient client = new SpertaClient();
        network = new ClientNetwork();
        network.initClientNetwork(server.host, server.port);
        client.run(userId, password);
    }


    private boolean isAuthenticatedResponse(String authResponse) {
        if(authResponse == null)
            return false;
        return "OK-USER".equals(authResponse) || "OK-NEW-USER".equals(authResponse);
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

        if (isAuthenticatedResponse(authResponse)) {
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
            }
        }
    }

    private boolean attestation() throws IOException{
        long size;
        try (InputStream is = SpertaClient.class.getResourceAsStream("SpertaClient.class")) {
            if (is == null) throw new IOException("Não foi possível carregar o recurso SpertaClient.class para atestação.");
            size = is.readAllBytes().length;
        }
        String attestMsg = "ATTEST SpertaClient:" + size;
        network.send(attestMsg);

        String response = (String) network.receive();
        if ("ATTEST OK".equals(response)) {
            System.out.println("ATTESTATION OK");
            return true;
        } else {
            System.out.println("ATTESTATION FAILED");
            return false;
        }
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
}