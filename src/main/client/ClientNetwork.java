// ##############################################################
//           Autores:                Numero Aluno:              # 
//        - Omeir Haroon               61810                    # 
//        - Isa David                  61871                    # 
//        - Diogo Roque                61857                    # 
// ##############################################################

package main.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
public class ClientNetwork {

    Socket clientSocket;
    ObjectOutputStream out;
    ObjectInputStream in;

    // send
    public void send(Object obj) {
        try {
            out.writeObject(obj);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // receive
    public Object receive() {
        try {
            return in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String receiveFile() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try(baos) {
            long received = receiveFileToOutputStream(baos);
            if (received < 0) {
                return null;
            }
            return baos.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public long receiveFile(Path outputPath) {
        try {
            Path parent = outputPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            try (var fos = Files.newOutputStream(outputPath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE)) {
                return receiveFileToOutputStream(fos);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;
        }
    }

    private long receiveFileToOutputStream(OutputStream outputStream) throws IOException {
        long fileSize = in.readLong();
        System.out.printf("A receber arquivo de tamanho %d bytes...%n", fileSize);

        byte[] buffer = new byte[8192];
        long remaining = fileSize;

        while (remaining > 0) {
            int toRead = (int) Math.min(buffer.length, remaining);
            int bytesRead = in.read(buffer, 0, toRead);

            if (bytesRead == -1) {
                throw new IOException("A ligação foi terminada antes da conclusão da transferência do ficheiro.");
            }
            outputStream.write(buffer, 0, bytesRead);
            remaining -= bytesRead;
        }

        outputStream.flush();
        return fileSize;
    }


    // init socket and streams
    public boolean initClientNetwork(String host, int port, String truststorePath, String truststorePass) {
        try {
            // Set the system properties so TLS knows where to find the server's certificate
            System.setProperty("javax.net.ssl.trustStore", truststorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", truststorePass);

            // Create the SSLSocket
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);

            // Validate that the certificate matches the requested hostname.
            SSLParameters sslParameters = sslSocket.getSSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            sslSocket.setSSLParameters(sslParameters);
            clientSocket = sslSocket;

            // Explicitly start the handshake (optional, but good for error catching)
            sslSocket.startHandshake();

            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());

            return true;
        } catch (Exception e) {
            System.err.println("Erro na ligação TLS: " + e.getMessage());
            return false;
        }
    }

    // close resources
    public boolean closeClientNetwork(){
        try{
            if (out != null) {
                out.close();
            }
            if (in != null) {
                in.close();
            }
            if (clientSocket != null) {
                clientSocket.close();
            }
            return true;
        } catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }


}
