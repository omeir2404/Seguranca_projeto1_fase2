 ##############################################################
 #         Autores:                Numero Aluno:              # 
 #       - Omeir Haroon               61810                   # 
 #       - Isa David                  61871                   # 
 #       - Diogo Roque                61857                   # 
 ##############################################################

JAVAC = javac
JAVA = java
SRC_DIR = src
BIN_DIR = bin
DIST_DIR = dist
SERVER_CLASS = main.server.SpertaServer
KEYTOOL = keytool
SERVER_KEYSTORE = serverkeystore.jks
SERVER_CERT = server-cert.pem
CLIENT_TRUSTSTORE = clienttruststore.jks
CLIENT_KEYSTORE = clientkeystore.jks
SERVER_KEYSTORE_PASS = keystorepass
CLIENT_TRUSTSTORE_PASS = truststorepass
CLIENT_KEYSTORE_PASS = clientkeypass
SERVER_CERT_ALIAS = sperta-server
CLIENT_CERT_ALIAS = sperta-client
TLS_SERVER_HOSTNAME ?= localhost
TLS_SERVER_IP ?= 127.0.0.1
SERVER_CERT_DNAME = CN=$(TLS_SERVER_HOSTNAME), OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT
SERVER_CERT_SAN = dns:$(TLS_SERVER_HOSTNAME),ip:$(TLS_SERVER_IP)
SERVER_PORT ?= 2223
SERVER_HOST ?= $(TLS_SERVER_HOSTNAME)
SERVER_ARGS = $(SERVER_PORT) cipherpass serverkeystore.jks keystorepass
CLIENT_CLASS = main.client.SpertaClient
CLIENT_ARGS = $(SERVER_HOST):$(SERVER_PORT) clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus ehBueFixe
CLIENT_ARGS2 = $(SERVER_HOST):$(SERVER_PORT) clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Eclipse ATuaMae
CLIENT_WRONG_ARGS = $(SERVER_HOST):$(SERVER_PORT) clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus Eclipsew
CLIENT_ARGS_NO_PORT = $(SERVER_HOST) clienttruststore.jks truststorepass clientkeystore.jks clientkeypass Nexus ehBueFixe


compile:
	@mkdir -p $(BIN_DIR)/main/server $(BIN_DIR)/main/client
	@$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/main/server/*.java $(SRC_DIR)/main/client/*.java
	@mkdir -p server_data/auth
	@printf 'dist/SpertaClient.jar\n' > server_data/auth/attestation.txt


compile_client:
	@$(JAVAC) -d $(BIN_DIR)  $(SRC_DIR)/main/client/*.java
	@mkdir -p server_data/auth
	@printf 'dist/SpertaClient.jar\n' > server_data/auth/attestation.txt


compile_server:
	@$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/main/server/*.java 

certs:
	@rm -f $(SERVER_KEYSTORE) $(SERVER_CERT) $(CLIENT_TRUSTSTORE) $(CLIENT_KEYSTORE)
	@$(KEYTOOL) -genkeypair -alias $(SERVER_CERT_ALIAS) -keyalg RSA -keysize 2048 -validity 3650 -keystore $(SERVER_KEYSTORE) -storepass $(SERVER_KEYSTORE_PASS) -keypass $(SERVER_KEYSTORE_PASS) -dname "$(SERVER_CERT_DNAME)" -ext SAN=$(SERVER_CERT_SAN)
	@$(KEYTOOL) -exportcert -alias $(SERVER_CERT_ALIAS) -keystore $(SERVER_KEYSTORE) -storepass $(SERVER_KEYSTORE_PASS) -rfc -file $(SERVER_CERT)
	@$(KEYTOOL) -importcert -alias $(SERVER_CERT_ALIAS) -file $(SERVER_CERT) -keystore $(CLIENT_TRUSTSTORE) -storepass $(CLIENT_TRUSTSTORE_PASS) -noprompt
	@$(KEYTOOL) -genkeypair -alias $(CLIENT_CERT_ALIAS) -keyalg RSA -keysize 2048 -validity 3650 -keystore $(CLIENT_KEYSTORE) -storepass $(CLIENT_KEYSTORE_PASS) -keypass $(CLIENT_KEYSTORE_PASS) -dname "CN=client-default, OU=SC, O=FCUL, L=Lisbon, ST=Lisbon, C=PT"
	@echo "TLS materials updated for hostname $(TLS_SERVER_HOSTNAME) and IP $(TLS_SERVER_IP): $(SERVER_KEYSTORE), $(SERVER_CERT), $(CLIENT_TRUSTSTORE), $(CLIENT_KEYSTORE)"

certs_lab: certs
	@echo "Lab TLS setup ready."
	@echo "Server certificate SAN: DNS=$(TLS_SERVER_HOSTNAME), IP=$(TLS_SERVER_IP)"
	@echo "Use clients with SERVER_HOST=$(SERVER_HOST) SERVER_PORT=$(SERVER_PORT)"

server: compile
	$(JAVA) -cp $(BIN_DIR) $(SERVER_CLASS) $(SERVER_ARGS)

client: createClientJar
	@$(JAVA) -jar $(DIST_DIR)/SpertaClient.jar $(CLIENT_ARGS)

client2: createClientJar
	@$(JAVA) -jar $(DIST_DIR)/SpertaClient.jar $(CLIENT_ARGS2)

wrongclient: createClientJar
	@$(JAVA) -jar $(DIST_DIR)/SpertaClient.jar $(CLIENT_WRONG_ARGS)

server_no_port: compile
	$(JAVA) -cp $(BIN_DIR) $(SERVER_CLASS) 

client_no_port: createClientJar
	@$(JAVA) -jar $(DIST_DIR)/SpertaClient.jar $(CLIENT_ARGS_NO_PORT)


re: clean compile

createServerJAR: compile
	@mkdir -p $(DIST_DIR)
	jar --create --file $(DIST_DIR)/SpertaServer.jar --main-class main.server.SpertaServer -C $(BIN_DIR) .

createClientJar: compile
	@mkdir -p $(DIST_DIR)
	jar --create --file $(DIST_DIR)/SpertaClient.jar --main-class main.client.SpertaClient -C $(BIN_DIR) .

createJARs: createServerJAR createClientJar


serverJAR: createServerJAR
	java -jar $(DIST_DIR)/SpertaServer.jar 22345 cipherpass serverkeystore.jks keystorepass

clientJAR: createClientJar
	@echo "Uso: java -jar $(DIST_DIR)/SpertaClient.jar <IP/hostname>[:Port] <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>"


clean:
	@rm -rf $(BIN_DIR)
	@rm -rf *.class

cleanFULL: clean
	@rm -rf client_data
	@rm -rf server_data
	@rm -f $(SERVER_KEYSTORE) $(SERVER_CERT) $(CLIENT_TRUSTSTORE) $(CLIENT_KEYSTORE)
