// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.server;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ServerNetwork {

    ObjectOutputStream out;
    ObjectInputStream in;

    public ServerNetwork(Socket socket) throws IOException {
        this.out = new ObjectOutputStream(socket.getOutputStream());
        this.in  = new ObjectInputStream(socket.getInputStream());
    }

    // send
    public void send(Object obj) {
        try {
            out.writeObject(obj);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // send a file
    public void sendFile(Path filePath) {
        try (InputStream fis = Files.newInputStream(filePath)) {
            out.writeLong(Files.size(filePath));
            out.flush();

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendFile(SequenceInputStream s, long totalSize) {
        try {
            out.writeLong(totalSize);
            out.flush();

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = s.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // receive
    public Object receive() {
        try {
            return in.readObject();
        } catch (EOFException e) {
            return null;
        } catch (SocketException e) {
            return null;
        } catch (Exception e) {
            System.err.println("Erro a receber dados do cliente: " + e.getMessage());
            return null;
        }
    }

    // close
    public void close() {
        try {
            out.close();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
