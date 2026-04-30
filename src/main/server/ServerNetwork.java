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

/**
 * Camada de rede do servidor.
 *
 * Esta classe encapsula a comunicação com um cliente através de um socket já
 * existente. O objetivo é fornecer operações simples:
 * - enviar objetos Java serializados
 * - enviar ficheiros em bruto por blocos
 * - receber objetos Java do cliente
 * - fechar corretamente os streams
 */
public class ServerNetwork {

    // Stream para enviar objetos Java serializados ao cliente.
    ObjectOutputStream out;

    // Stream para receber objetos Java serializados do cliente.
    ObjectInputStream in;

    /**
     * Cria a camada de rede a partir de um socket já ligado.
     *
     * A ordem é importante: primeiro o ObjectOutputStream e depois o
     * ObjectInputStream para evitar bloqueios na negociação inicial dos streams.
     */
    public ServerNetwork(Socket socket) throws IOException {
        // O ObjectOutputStream escreve objetos no stream do socket.
        this.out = new ObjectOutputStream(socket.getOutputStream());

        // O ObjectInputStream lê objetos enviados pelo cliente.
        this.in  = new ObjectInputStream(socket.getInputStream());
    }

    /**
     * Envia um objeto Java para o cliente.
     *
     * É usado para respostas simples como "OK", "NOK", listas ou códigos de
     * erro. O objeto é serializado automaticamente pelo Java.
     */
    public void send(Object obj) {
        try {
            // Serializa o objeto e escreve-o no canal do socket.
            out.writeObject(obj);

            // Garante que os bytes saem imediatamente e não ficam em buffer.
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Envia um ficheiro localizado em disco para o cliente.
     *
     * Protocolo usado:
     * 1) envia o tamanho total do ficheiro em bytes
     * 2) envia o conteúdo por blocos de 8192 bytes
     *
     * O cliente lê primeiro o tamanho e depois sabe exatamente quantos bytes
     * tem de receber.
     */
    public void sendFile(Path filePath) {
        try (InputStream fis = Files.newInputStream(filePath)) {
            // O cliente precisa saber quantos bytes virão a seguir.
            out.writeLong(Files.size(filePath));
            out.flush();

            // Buffer fixo para transferir o ficheiro em pedaços.
            byte[] buffer = new byte[8192];
            int bytesRead;

            // Lê do ficheiro e escreve no socket até chegar ao fim.
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }

            // Garante que todo o conteúdo foi efetivamente enviado.
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Envia um ficheiro a partir de um SequenceInputStream.
     *
     * Esta variante é útil quando o conteúdo já foi construído em memória,
     * por exemplo ao montar um payload RT/RH antes de o transmitir.
     * O protocolo é o mesmo: tamanho primeiro, bytes depois.
     */
    public void sendFile(SequenceInputStream s, long totalSize) {
        try {
            // Primeiro comunica o tamanho total do payload.
            out.writeLong(totalSize);
            out.flush();

            // Depois transfere o conteúdo por blocos.
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = s.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }

            // Força o envio do que ainda esteja em buffer.
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Recebe um objeto Java enviado pelo cliente.
     *
     * Tipicamente é usado para comandos, passwords, hashes de atestação ou
     * outras mensagens serializadas. Se o cliente fechar a ligação, devolve
     * null em vez de lançar a exceção para cima.
     */
    public Object receive() {
        try {
            return in.readObject();
        } catch (EOFException e) {
            // O cliente terminou a transmissão de forma limpa.
            return null;
        } catch (SocketException e) {
            // A ligação de rede foi interrompida.
            return null;
        } catch (Exception e) {
            System.err.println("Erro a receber dados do cliente: " + e.getMessage());
            return null;
        }
    }

    /**
     * Fecha os streams de forma limpa.
     *
     * Isto ajuda a libertar recursos no lado do servidor e evita sockets
     * pendurados depois do cliente sair.
     */
    public void close() {
        try {
            // Fecha primeiro o output e depois o input.
            out.close();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
