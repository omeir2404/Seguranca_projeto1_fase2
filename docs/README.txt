================================================================================
  Sperta - Projeto 1, Fase 2
  Seguranca e Confiabilidade 2025/2026
================================================================================

Grupo 4
  - Omeir Haroon   61810
  - Isa David      61871
  - Diogo Roque    61857

--------------------------------------------------------------------------------
OBJETIVO DA FASE 2
--------------------------------------------------------------------------------

Esta fase adiciona seguranca ao sistema Sperta (casas inteligentes):

  1. TLS/SSL (autenticacao unilateral do servidor) em todas as comunicacoes
  2. Protecao de passwords com SHA-256 + salt (formato: user:hash:salt)
  3. Atestacao remota do cliente com nonce + SHA-256(nonce || SpertaClient.jar)
  4. Cifra dos ficheiros do servidor com PBE (PBKDF2 + AES-128-GCM)
  5. Verificacao de integridade de todos os ficheiros (SHA-256, ficheiros .hash)
  6. Confidencialidade fim-a-fim nos comandos EC/RT/RH (AES-128-GCM por seccao)

--------------------------------------------------------------------------------
REQUISITOS
--------------------------------------------------------------------------------

  - Java JDK 17 ou superior  (testado com OpenJDK 21)
  - make
  - keytool (incluido no JDK)
  - Portos utilizados: 2223 (Makefile) | 22345 (default do codigo)

--------------------------------------------------------------------------------
SINTAXE DE EXECUCAO
--------------------------------------------------------------------------------

Servidor:
  SpertaServer [port] <password-cifra> <keystore> <password-keystore>

  Exemplo:
    java -jar dist/SpertaServer.jar 2223 cipherpass serverkeystore.jks keystorepass

Cliente:
  SpertaClient <serverAddress> <truststore> <password-truststore>
               <keystore> <password-keystore> <user-id> <password>

  Exemplo:
    java -jar dist/SpertaClient.jar 127.0.0.1:2223 clienttruststore.jks truststorepass \
         clientkeystore.jks clientkeypass Nexus ehBueFixe

  serverAddress aceita formato <IP/hostname>[:Port].
  Se o port for omitido, o cliente liga-se ao porto 22345.

--------------------------------------------------------------------------------
COMPILAR O PROJETO (a partir do codigo-fonte)
--------------------------------------------------------------------------------

  make certs        # Gera certificados TLS e guarda o IP em server_ip.txt
  make createJARs   # Compila o codigo e cria dist/SpertaServer.jar e dist/SpertaClient.jar

Os JARs pre-compilados ja estao disponiveis em dist/. Se nao for necessario
recompilar, pode saltar o passo "make createJARs".

AVISO: Recompilar o SpertaClient.jar gera um novo binario com hash diferente.
O servidor usa SHA-256(nonce || SpertaClient.jar) para atestacao remota.
Se o JAR do cliente usado for diferente do JAR em dist/ no servidor, a
atestacao falha (NOK-ATTEST). Por isso, cliente e servidor devem sempre
usar os JARs gerados na mesma compilacao.

--------------------------------------------------------------------------------
EXECUCAO (MAQUINA UNICA - cenario mais comum)
--------------------------------------------------------------------------------

Terminal 1 (Servidor):
  make certs
  make serverJAR

Terminal 2 (Cliente - Nexus):
  make client

Terminal 3 (Cliente - Eclipse):
  make client2

Terminal 4 (Cliente com password errada para testar):
  make wrongclient

--------------------------------------------------------------------------------
EXECUCAO EM DUAS MAQUINAS (lab / avaliacao)
--------------------------------------------------------------------------------

MAQUINA 1 (Servidor):

  1. Gerar certificados com o IP correto da maquina:
       make certs TLS_SERVER_IP=<IP_DA_MAQUINA_SERVIDOR>

     Se o IP for detetado automaticamente mas errado (ex: Docker, VMs):
       hostname -I       # ver IPs disponiveis
       make certs TLS_SERVER_IP=<IP_CORRETO>

  2. Compilar e iniciar o servidor:
       make serverJAR

     O terminal imprimira o comando exato para o cliente.

MAQUINA 2 (Cliente):

  IMPORTANTE: NAO execute "make client" na Maquina 2.
  Isso recompilaria o JAR, gerando um hash diferente e causando NOK-ATTEST.

  Em vez disso, copie da Maquina 1 os ficheiros:
    dist/SpertaClient.jar
    clienttruststore.jks
    clientkeystore.jks
    server_ip.txt   (opcional, contem o IP guardado automaticamente)

  Depois execute diretamente:
    java -jar dist/SpertaClient.jar <IP_SERVIDOR>:2223 \
         clienttruststore.jks truststorepass \
         clientkeystore.jks clientkeypass \
         <user-id> <password>

  Usando o IP guardado em server_ip.txt:
    java -jar dist/SpertaClient.jar $(cat server_ip.txt):2223 \
         clienttruststore.jks truststorepass \
         clientkeystore.jks clientkeypass Nexus ehBueFixe

  Utilizadores pre-configurados no Makefile:
    Nexus     / ehBueFixe   (make client)
    Eclipse   / tbmEhFixe     (make client2)

--------------------------------------------------------------------------------
EXECUCAO MANUAL (sem Makefile, ex: nos labs da faculdade)
--------------------------------------------------------------------------------

Passo 1 - Gerar certificados (apenas uma vez por sessao):
  keytool -genkeypair -alias sperta-server -keyalg RSA -keysize 2048 \
    -validity 3650 -keystore serverkeystore.jks -storepass keystorepass \
    -keypass keystorepass \
    -dname "CN=$(hostname), OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT" \
    -ext SAN=dns:$(hostname),ip:$(hostname -I | awk '{print $1}')

  keytool -exportcert -alias sperta-server -keystore serverkeystore.jks \
    -storepass keystorepass -rfc -file server-cert.pem

  keytool -importcert -alias sperta-server -file server-cert.pem \
    -keystore clienttruststore.jks -storepass truststorepass -noprompt

  keytool -genkeypair -alias sperta-client -keyalg RSA -keysize 2048 \
    -validity 3650 -keystore clientkeystore.jks -storepass clientkeypass \
    -keypass clientkeypass \
    -dname "CN=client-default, OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT"

Passo 2 - Iniciar o servidor:
  java -jar dist/SpertaServer.jar 2223 cipherpass serverkeystore.jks keystorepass

Passo 3 - Conectar o cliente (noutro terminal):
  java -jar dist/SpertaClient.jar 127.0.0.1:2223 \
       clienttruststore.jks truststorepass \
       clientkeystore.jks clientkeypass \
       Nexus ehBueFixe

  Para outro utilizador:
  java -jar dist/SpertaClient.jar 127.0.0.1:2223 \
       clienttruststore.jks truststorepass \
       clientkeystore.jks clientkeypass \
       Eclipse tbmEhFixe

Nota: nos labs da FCUL, se o "make" nao estiver disponivel, use os comandos
manuais acima. O Java e o keytool devem estar no PATH por defeito.
Para verificar: java -version  e  keytool -help

--------------------------------------------------------------------------------
COMANDOS SUPORTADOS
--------------------------------------------------------------------------------

  CREATE <hm>             Criar casa <hm> (utilizador fica Owner)
  ADD <user> <hm> <s>     Adicionar utilizador a casa <hm>, seccao <s>
                          <s> pode ser M, G, L, P, B, E, ou "all"
  RD <hm> <s>             Registar dispositivo na seccao <s> da casa <hm>
  EC <hm> <d> <int>       Enviar estado/temporizacao [0..600] ao dispositivo <d>
                          (valor cifrado fim-a-fim com a chave da seccao)
  RT <hm>                 Receber estado atual dos dispositivos (decifrado localmente)
  RH <hm> <d>             Receber historico CSV do dispositivo <d> (decifrado localmente)
  LS [<hm>]               Listar casas acessiveis (ou dispositivos de <hm>)
  EXIT / QUIT             Desligar

Respostas do servidor:
  OK         Operacao bem-sucedida
  NOK        Erro generico
  NOHM       Casa nao existe
  NOPERM     Sem permissoes
  NOUSER     Utilizador nao existe
  NOD        Dispositivo nao existe
  NODATA     Sem dados disponiveis

--------------------------------------------------------------------------------
FLUXO DE AUTENTICACAO E ATESTACAO
--------------------------------------------------------------------------------

  1. Cliente liga ao servidor via TLS (servidor autenticado pelo certificado)
  2. Servidor envia nonce aleatorio (8 bytes)
  3. Cliente calcula SHA-256(nonce || SpertaClient.jar) e envia ao servidor
  4. Servidor verifica comparando com SHA-256(nonce || dist/SpertaClient.jar)
     - OK-ATTEST  : atestacao bem-sucedida, prossegue para autenticacao
     - NOK-ATTEST : cliente invalido, ligacao encerrada
  5. Cliente envia user-id e password
     - OK-NEW-USER : novo utilizador registado, cliente envia certificado X.509
     - OK-USER     : utilizador existente autenticado
     - WRONG-PWD   : password incorreta (1 retry permitido)
     - USER-ALREADY-CONNECTED : sessao duplicada rejeitada

--------------------------------------------------------------------------------
ESTRUTURA DE PERSISTENCIA (servidor)
--------------------------------------------------------------------------------

  server_data/
    auth/
      users.txt            utilizadores (cifrado + hash)
      attestation.txt      caminho para o JAR de referencia do cliente (cifrado)
      pbe.salt             sal para derivacao da chave PBE
      certs/               certificados X.509 dos utilizadores (.cer)
    metadata/
      homes_registry.txt   casas e owners (cifrado + hash)
      permissions.txt      permissoes por casa/utilizador (cifrado + hash)
      house_metadata.txt   metadados das casas (cifrado + hash)
      section_counters.txt contadores de IDs por seccao (cifrado + hash)
      device_sections.txt  mapeamento dispositivo -> seccao (cifrado + hash)
      houses.log           log de auditoria (cifrado + hash)
    states/
      last_commands.txt    ultimo comando EC por dispositivo (cifrado + hash)
    homes/
      <casa>/<seccao>/     historico CSV por dispositivo (cifrado + hash)
    keys/
      <casa>/<seccao>/     chaves de seccao cifradas por utilizador (.bin + hash)

  client_data/ (gerado no lado do cliente)
    <user-id>/
      status_<hm>.txt      resultado decifrado do RT
      history_<d>_<hm>.csv resultado decifrado do RH

Todos os ficheiros protegidos sao cifrados com AES-128-GCM usando uma chave
derivada por PBKDF2(password-cifra, salt) e tem um ficheiro .hash associado
com o SHA-256 do conteudo em texto simples.

--------------------------------------------------------------------------------
LIMITA??ES CONHECIDAS
--------------------------------------------------------------------------------

  - O formato de hash/salt de passwords esta em hexadecimal (nao Base64 como
    no exemplo do enunciado). O funcionamento esta correto.
  - O comando LS e extra ao enunciado e mantido por conveniencia.
  - Para testes em duas maquinas, o SpertaClient.jar do cliente deve ser o
    mesmo (mesmo binario) que esta em dist/ no servidor para a atestacao passar.
  - O servidor so aceita utilizadores que ja tenham feito login pelo menos uma
    vez antes de serem adicionados a uma casa com ADD (necessario para o
    certificado existir no servidor para partilha de chaves).

================================================================================
