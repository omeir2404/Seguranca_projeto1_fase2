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

// ===================================================================
//                          ClientNetwork
// ===================================================================
// OBJETIVO: Fazer a comunicação entre Cliente e Servidor via TLS/SSL
// - Envia OBJETOS Java (comandos serializados)
// - Envia FICHEIROS (histórico, CSV, etc)
// - Recebe RESPOSTAS do servidor
// - Tudo de forma ENCRIPTADA (confidencial) e AUTENTICADA
// ===================================================================

public class ClientNetwork {

    // ===================================================================
    //                       VARIÁVEIS DE INSTÂNCIA
    // ===================================================================
    
    // Socket encriptado com TLS/SSL que mantém a ligação com servidor
    // TLS garante que a comunicação é:
    // - CONFIDENCIAL (ninguém vê o conteúdo)
    // - ÍNTEGRA (mensagens não são alteradas)
    // - AUTENTICADA (servidor é quem diz ser)
    Socket clientSocket;
    
    // Stream para ENVIAR objetos Java serializados ao servidor
    // Exemplo: envia um comando "EC casa1 lampada 100" como objeto
    // Java automaticamente converte objeto → bytes (serialização)
    ObjectOutputStream out;
    
    // Stream para RECEBER objetos Java serializados do servidor
    // Exemplo: recebe resposta "OK" ou mensagens de erro
    // Java automaticamente converte bytes → objeto (desserialização)
    ObjectInputStream in;

    // ===================================================================
    //                       MÉTODOS DE ENVIO (SEND)
    // ===================================================================

    /**
     * Envia um objeto Java qualquer ao servidor
     * O objeto é automaticamente convertido para bytes (serialização)
     * e transmitido de forma segura pela ligação TLS
     * 
     * FLUXO:
     * 1. Objeto Java (ex: "EC casa1 lampada 25")
     * 2. ObjectOutputStream serializa → bytes
     * 3. TLS encripta os bytes
     * 4. Transmite pela rede ao servidor
     * 5. Servidor recebe, desencripta, desserializa → objeto original
     * 
     * @param obj Qualquer objeto Java a enviar
     *            (String, HashMap, ArrayList, etc)
     */
    public void send(Object obj) {
        try {
            // writeObject() serializa o objeto em bytes
            // e escreve no socket TLS
            out.writeObject(obj);
            
            // flush() garante que os dados saem IMEDIATAMENTE pela rede
            // Sem flush(), dados podem ficar em buffer na memória
            // e não chegam logo ao servidor
            out.flush();
        } catch (Exception e) {
            // Se erro (ex: conexão interrompida), mostra o stack trace
            e.printStackTrace();
        }
    }

    /**
     * Envia um FICHEIRO ao servidor
     * Usa um protocolo simples:
     * - PRIMEIRO: tamanho do ficheiro (em bytes) como long
     * - DEPOIS: conteúdo do ficheiro (array de bytes)
     * 
     * Isto permite ao servidor saber exatamente quantos bytes ler
     * 
     * FLUXO EXEMPLO - Enviando ficheiro de 1000 bytes:
     * 1. Envia: long 1000
     * 2. Envia: 1000 bytes de conteúdo
     * 3. Servidor lê long, sabe que vem 1000 bytes
     * 4. Servidor lê 1000 bytes, sabe que terminou
     * 
     * @param baos ByteArrayOutputStream contendo o ficheiro
     *             (está tudo em memória antes de enviar)
     */
    public void sendFile(ByteArrayOutputStream baos) {
        try {
            // PASSO 1: Enviar o TAMANHO
            // writeLong() envia um número inteiro de 64 bits (long)
            // Isto permite ao servidor saber quantos bytes vão vir
            out.writeLong(baos.size());
            out.flush();
            
            // PASSO 2: Enviar o CONTEÚDO
            // baos.toByteArray() converte o stream em array de bytes
            // write() escreve os bytes no socket TLS
            out.write(baos.toByteArray());
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ===================================================================
    //                   MÉTODOS DE RECEBIMENTO (RECEIVE)
    // ===================================================================

    /**
     * Recebe UM OBJETO Java do servidor
     * O objeto é desserializado automaticamente (bytes → objeto Java)
     * 
     * EXEMPLO - Receber resposta do servidor:
     * 1. Servidor envia: resposta = "OK"
     * 2. ObjectInputStream desserializa → "OK" como String
     * 3. Este método retorna "OK"
     * 4. SpertaClient usa a resposta
     * 
     * @return O objeto recebido (ex: String, HashMap, etc)
     *         Retorna null se houver erro na recepção
     */
    public Object receive() {
        try {
            // readObject() desserializa bytes recebidos → objeto Java
            // Bloqueia até haver dados disponíveis
            return in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Recebe um FICHEIRO do servidor e guarda em MEMÓRIA (RAM)
     * Retorna o conteúdo como String
     * 
     * BOM PARA:
     * - Ficheiros pequenos (até alguns MB)
     * - Ficheiros de texto (CSV, TXT, etc)
     * - Quando precisa do conteúdo logo em memória
     * 
     * MÁ IDEIA PARA:
     * - Ficheiros muito grandes (> 100MB)
     * - Ficheiros binários enormes
     * 
     * FLUXO:
     * 1. Cria um ByteArrayOutputStream (buffer em memória)
     * 2. Chama receiveFileToOutputStream para ler dados
     * 3. Converte bytes → String em UTF-8
     * 4. Retorna a String
     * 
     * @return String com o conteúdo do ficheiro, ou null se erro
     */
    public String receiveFile() {
        // ByteArrayOutputStream é um stream que acumula bytes em RAM
        // Não escreve em disco, guarda tudo em memória
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try(baos) {  // Try-with-resources: fecha automaticamente ao sair
            // Chama método auxiliar que faz todo o trabalho pesado
            long received = receiveFileToOutputStream(baos);
            
            // Se retornar -1, significa que houve erro
            if (received < 0) {
                return null;
            }
            
            // Converte o conteúdo do buffer para String
            // StandardCharsets.UTF_8 é o encoding padrão para texto
            // UTF-8 suporta português, emojis, etc
            return baos.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Recebe um FICHEIRO do servidor e guarda em DISCO (ficheiro local)
     * 
     * BOM PARA:
     * - Ficheiros grandes
     * - Históricos CSV de dispositivos
     * - Quando não quer carregar tudo em memória
     * 
     * FLUXO:
     * 1. Obtém diretório do ficheiro, cria se não existir
     * 2. Abre ficheiro em modo escrita
     * 3. Lê dados do servidor em chunks (pedaços)
     * 4. Escreve cada chunk no ficheiro
     * 5. Fecha ficheiro
     * 
     * @param outputPath Caminho completo onde guardar (ex: "casa1/P1.csv")
     * @return Número de bytes recebidos, ou -1 se houver erro
     */
    public long receiveFile(Path outputPath) {
        try {
            // Obtém o diretório pai
            // Ex: de "server_data/homes/casa1/P/P1.csv" → "server_data/homes/casa1/P"
            Path parent = outputPath.getParent();
            
            // Cria o diretório se não existir
            // createDirectories() cria recursivamente (cria pai, avó, etc se precisar)
            if (parent != null) {
                Files.createDirectories(parent);
            }

            // Try-with-resources: cria FileOutputStream e fecha automaticamente
            // StandardOpenOption.CREATE → cria ficheiro se não existe
            // StandardOpenOption.TRUNCATE_EXISTING → apaga conteúdo se já existe
            // StandardOpenOption.WRITE → modo escrita
            try (var fos = Files.newOutputStream(outputPath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE)) {
                // Chama método auxiliar para fazer a recepção
                return receiveFileToOutputStream(fos);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return -1L;  // -1 indica erro
        }
    }

    /**
     * Método PRIVADO auxiliar que faz o trabalho real de receber ficheiros
     * Lê dados do servidor em CHUNKS (pedaços) e escreve num stream
     * 
     * ALGORITMO:
     * 1. Lê tamanho total do ficheiro (servidor envia isto primeiro)
     * 2. Cria um buffer de 8KB para ler dados em pedaços
     * 3. Loop:
     *    - Lê até 8KB do servidor
     *    - Escreve no stream (disco ou memória)
     *    - Repete até ter recebido TUDO
     * 4. Flush e retorna tamanho total
     * 
     * POR QUE EM CHUNKS?
     * - Se ficheiro tem 100MB e tentasse ler tudo de uma vez,
     *   ocuparia 100MB de RAM
     * - Lendo em chunks de 8KB, usa apenas 8KB de RAM
     * - Muito mais eficiente para ficheiros grandes
     * 
     * @param outputStream Stream onde escrever
     *                    (pode ser FileOutputStream para disco
     *                     ou ByteArrayOutputStream para RAM)
     * @return Número total de bytes recebidos
     * @throws IOException Se houver problema de I/O (erro de rede, disco, etc)
     */
    private long receiveFileToOutputStream(OutputStream outputStream) throws IOException {
        // PASSO 1: Lê o TAMANHO TOTAL do ficheiro
        // O servidor SEMPRE envia isto primeiro
        // Isto permite ao cliente saber QUANDO TERMINOU
        long fileSize = in.readLong();
        System.out.printf("A receber arquivo de tamanho %d bytes...%n", fileSize);

        // PASSO 2: Cria BUFFER (array de bytes) para ler em pedaços
        // 8192 bytes = 8 KB
        // Este é um bom tamanho (não demasiado grande, não demasiado pequeno)
        byte[] buffer = new byte[8192];
        
        // PASSO 3: Variável que controla o PROGRESSO
        // Começa com o tamanho total
        // Vai diminuindo conforme recebemos dados
        // Quando chegar a 0, recebemos TUDO
        long remaining = fileSize;

        // PASSO 4: LOOP PRINCIPAL - lê até receber tudo
        while (remaining > 0) {
            // Calcula quantos bytes ler NESTA ITERAÇÃO
            // Math.min garante que não tentamos ler mais do que falta
            // 
            // EXEMPLO:
            // - Se faltam 10000 bytes e buffer tem 8192
            // → toRead = 8192 (lê um buffer cheio)
            // - Se faltam 5000 bytes e buffer tem 8192
            // → toRead = 5000 (lê só o que falta)
            int toRead = (int) Math.min(buffer.length, remaining);
            
            // Lê dados do servidor (ObjectInputStream)
            // Tenta ler "toRead" bytes
            // Coloca os bytes no "buffer" a partir da posição 0
            // Retorna quantos bytes foram efetivamente lidos
            int bytesRead = in.read(buffer, 0, toRead);

            // VERIFICAÇÃO: Se retorna -1, significa fim de stream
            // Isto é um PROBLEMA! Significa que servidor desconectou
            // ANTES de enviar todos os bytes
            if (bytesRead == -1) {
                throw new IOException("A ligação foi terminada antes da conclusão da transferência do ficheiro.");
            }
            
            // Escreve os bytes que lemos no stream de OUTPUT
            // (disco se é FileOutputStream, RAM se é ByteArrayOutputStream)
            outputStream.write(buffer, 0, bytesRead);
            
            // ATUALIZA PROGRESSO
            // Diminui "remaining" pelos bytes que recebemos
            remaining -= bytesRead;
        }

        // PASSO 5: Força a escrita (flush)
        // Garante que se for FileOutputStream, tudo foi escrito em disco
        outputStream.flush();
        
        // Retorna o tamanho total do ficheiro recebido
        return fileSize;
    }

    // ===================================================================
    //           INICIALIZAÇÃO E FECHAMENTO DE CONEXÃO
    // ===================================================================

    /**
     * CONECTA ao servidor usando TLS/SSL (ligação segura)
     * 
     * OPERAÇÕES:
     * 1. Configura propriedades do sistema (onde estão certificados confiáveis)
     * 2. Cria um SSLSocket (socket com encriptação TLS)
     * 3. Valida que o certificado pertence realmente ao servidor
     * 4. Inicia o TLS handshake (troca de certificados e chaves)
     * 5. Abre ObjectStreams para comunicação
     * 
     * SEGURANÇA IMPLEMENTADA:
     * - TLS 1.2/1.3 (encriptação)
     * - Validação de hostname (protege contra ataques MITM)
     * - Certificados X.509
     * 
     * @param host Endereço IP ou hostname do servidor
     *             (ex: "localhost" ou "192.168.1.10")
     * @param port Porto onde servidor escuta
     *             (ex: 22345 é o padrão do projeto)
     * @param truststorePath Caminho para ficheiro .jks com certificados confiáveis
     *                      (ex: "clienttruststore.jks")
     * @param truststorePass Password para abrir o truststore
     *                      (ex: "truststorepass")
     * @return true se conexão bem-sucedida, false se erro
     */
    public boolean initClientNetwork(String host, int port, String truststorePath, String truststorePass) {
        try {
            // PASSO 1: CONFIGURAR PROPRIEDADES DO SISTEMA
            // Estas propriedades dizem ao Java:
            // - Onde encontrar os certificados do servidor que confio
            // - Qual é a password para abrir esse ficheiro
            // Java usará isto AUTOMATICAMENTE quando criar SSLSocket
            System.setProperty("javax.net.ssl.trustStore", truststorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", truststorePass);

            // PASSO 2: OBTER A "FACTORY" (fábrica) DE SSL SOCKETS
            // SSLSocketFactory é uma classe que cria sockets encriptados
            // getDefault() retorna a factory com as propriedades que acabamos de configurar
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            
            // PASSO 3: CRIAR O SOCKET TLS
            // factory.createSocket(host, port) cria um socket que:
            // - Se conecta a "host:port"
            // - Usa TLS para encriptação
            // - Está pronto para fazer handshake
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);

            // PASSO 4: VALIDAÇÃO DE HOSTNAME (proteção contra MITM)
            // SSLParameters permite configurar parâmetros SSL/TLS
            // setEndpointIdentificationAlgorithm("HTTPS") garante que:
            // - O certificado que o servidor enviou é REALMENTE do host "host"
            // - Protege contra ataques "man-in-the-middle"
            // 
            // EXEMPLO DE PROTEÇÃO:
            // - Tentamos conectar a "192.168.1.10"
            // - Certificado diz que é de "outro.com"
            // - Validação falha! Alguém está a tentar enganar-nos
            SSLParameters sslParameters = sslSocket.getSSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            sslSocket.setSSLParameters(sslParameters);
            clientSocket = sslSocket;

            // PASSO 5: INICIAR TLS HANDSHAKE EXPLICITAMENTE
            // (Tecnicamente é opcional porque streams também iniciam)
            // Mas é bom fazer explicitamente para:
            // - Apanhar erros logo (certificado inválido, etc)
            // - Garantir que conexão está pronta antes de usar
            // 
            // DURANTE O HANDSHAKE:
            // - Cliente e servidor trocam certificados
            // - Validam certificados mutuamente (só servidor neste caso)
            // - Negoceiam algoritmo de encriptação (ex: AES)
            // - Criam chaves de sessão
            // - Estabelecem ligação segura
            sslSocket.startHandshake();

            // PASSO 6: ABRIR STREAMS DE COMUNICAÇÃO
            // Estes streams funcionam SOBRE a ligação TLS
            // Tudo que escrevemos é AUTOMATICAMENTE encriptado pelo TLS
            // Tudo que lemos é AUTOMATICAMENTE desencriptado pelo TLS
            
            // ObjectOutputStream permite:
            // - Serializar objetos Java
            // - Enviar através do socket TLS
            // - Servidor recebe, desencripta, desserializa
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            
            // ObjectInputStream permite:
            // - Receber dados do socket TLS
            // - TLS desencripta automaticamente
            // - Desserializar objetos Java
            in = new ObjectInputStream(clientSocket.getInputStream());

            // SUCESSO! Conexão estabelecida
            return true;
        } catch (Exception e) {
            // Se algo correr mal (ex: servidor offline, certificado inválido,
            // firewall bloqueando, etc), mostra erro e retorna false
            System.err.println("Erro na ligação TLS: " + e.getMessage());
            return false;
        }
    }

    /**
     * DESCONECTA do servidor e liberta TODOS os recursos
     * 
     * IMPORTANTE CHAMAR ISTO:
     * - Quando cliente faz EXIT/QUIT
     * - Se houver erro e precisa fechar
     * - Antes de sair do programa
     * 
     * SE NÃO CHAMAR:
     * - Socket fica aberto desnecessariamente
     * - Servidor mantém thread aberta para este cliente
     * - Com muitos clientes, consome recursos
     * 
     * OPERAÇÕES:
     * 1. Fecha ObjectOutputStream (envia EOF ao servidor)
     * 2. Fecha ObjectInputStream
     * 3. Fecha socket TLS (termina ligação TCP)
     * 
     * @return true se fechamento bem-sucedido, false se erro
     */
    public boolean closeClientNetwork(){
        try {
            // PASSO 1: Fechar ObjectOutputStream
            // close() envia um "end-of-file" ao servidor
            // Servidor sabe que cliente vai terminar
            if (out != null) {
                out.close();
            }
            
            // PASSO 2: Fechar ObjectInputStream
            if (in != null) {
                in.close();
            }
            
            // PASSO 3: Fechar socket TLS
            // close() encerra a ligação TCP
            // Liberta porta no cliente
            // Servidor pode eliminar thread deste cliente
            if (clientSocket != null) {
                clientSocket.close();
            }
            
            // SUCESSO!
            return true;
        } catch (Exception e) {
            // Se algo correr mal durante fechamento (ex: conexão já estava morta)
            e.printStackTrace();
            return false;
        }
    }

}
