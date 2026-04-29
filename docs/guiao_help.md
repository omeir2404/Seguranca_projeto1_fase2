
### Guia de Demonstração, passo a passo

Este ficheiro foi ajustado para a forma como o vosso código está realmente implementado. A ordem abaixo segue o que os avaliadores costumam pedir: primeiro a preparação do ambiente, depois a prova no código, e por fim os testes funcionais.

---

## 1. Preparação do ambiente

### Máquina 1
1. Confirmar que o servidor arranca sem recompilar o cliente na máquina 2.
2. Iniciar o `SpertaServer` com o comando gerado pelo `Makefile`.
3. Manter o terminal do servidor aberto durante toda a demonstração.

### Máquina 2
1. Abrir pelo menos dois terminais.
2. Iniciar um `SpertaClient` por terminal com utilizadores diferentes.
3. Para a parte de partilha de certificados e permissões, preparar também um terceiro cliente.

### Antes de começar
1. Mostrar os keystores e truststores com `keytool -list -v`.
2. Confirmar que a `truststore` do cliente inicial não contém ainda o certificado do `user3`.
3. Confirmar que os ficheiros do servidor estão protegidos e não em texto claro.

---

## 2. O que o avaliador pode pedir para ver no código

### 2.1 Passwords dos utilizadores

O formato correto no ficheiro de utilizadores é:

`<user-id>:<hash(password + salt)>:<salt>`

No vosso código isto está implementado em `src/main/server/SpertaServer.java` e o ficheiro é lido/escrito por `src/main/server/ServerFileManager.java`.

O que deves mostrar:
1. A função que gera o salt e o hash.
2. A função que compara a password introduzida com a credencial guardada.
3. O ficheiro `server_data/auth/users.txt` depois de desencriptado pelo servidor, não aberto diretamente no editor.

Ponto importante para explicar:
1. O ficheiro no disco está cifrado.
2. O conteúdo legível aparece apenas depois de `readProtectedFile()`.
3. O servidor guarda `hash:salt` por utilizador e não a password em claro.

### 2.2 Atestação remota

A atestação ocorre antes da autenticação do utilizador.

Fluxo a explicar:
1. O servidor envia um nonce.
2. O cliente concatena o nonce com o `SpertaClient.jar`.
3. O cliente calcula `SHA-256(nonce || SpertaClient.jar)`.
4. O servidor calcula o mesmo valor sobre a cópia de referência.
5. Se coincidir, a ligação continua; se não coincidir, o servidor rejeita a sessão.

O que mostrar no código:
1. O ponto onde o nonce é enviado.
2. O ponto onde o cliente calcula o hash.
3. O ponto onde o servidor compara a referência com a resposta do cliente.

### 2.3 Cifra dos ficheiros do servidor

Os ficheiros do servidor são protegidos com PBE e AES-128-GCM.

O que mostrar no código:
1. A geração da chave mestre a partir da password e do `pbe.salt`.
2. A escrita de ficheiros protegidos com `writeProtectedFile()`.
3. A leitura/desencriptação com `readProtectedFile()`.

O que confirmar na demonstração:
1. `users.txt`, `homes_registry.txt`, `permissions.txt`, `house_metadata.txt`, `section_counters.txt`, `device_sections.txt`, `attestation.txt` e `last_commands.txt` estão cifrados no disco.
2. Cada ficheiro protegido tem o respetivo `.hash` com SHA-256 do conteúdo em texto claro.

### 2.4 Integridade dos ficheiros

O servidor guarda o hash do conteúdo após cada alteração e verifica esse hash quando lê o ficheiro.

O que mostrar no código:
1. A escrita do `.hash` após `writeProtectedFile()`.
2. A verificação do hash na leitura.
3. O comportamento quando a integridade falha: aviso e término do servidor.

### 2.5 Concorrência

O avaliador pode perguntar como o servidor lida com múltiplos clientes.

O que dizer e mostrar:
1. O servidor trabalha com múltiplas threads para clientes em simultâneo.
2. As secções críticas que alteram ficheiros partilhados usam sincronização.
3. O ficheiro de utilizadores e os registos de dispositivos/comandos não devem ser corrompidos quando há acessos concorrentes.

### 2.6 Certificados

O servidor funciona como servidor de certificados públicos.

O que mostrar:
1. O diretório `server_data/auth/certs/` contém os certificados dos utilizadores já autenticados.
2. Antes de um novo utilizador autenticar, o servidor só tem os certificados dos utilizadores anteriores.
3. Após o novo login, o certificado desse utilizador passa a existir no servidor.

---

## 3. Sequência recomendada da demonstração funcional

### Parte A - Arranque e autenticação
1. Iniciar o servidor na Máquina 1.
2. Abrir dois clientes na Máquina 2, com dois utilizadores diferentes.
3. Demonstrar que ambos autenticam com sucesso.
4. Se necessário, mostrar uma tentativa de password errada para provar `WRONG-PWD`.

### Parte B - Verificar passwords e ficheiros protegidos
1. Abrir o ficheiro de utilizadores apenas através do servidor ou do código.
2. Mostrar que o conteúdo está no formato `user:hash:salt`.
3. Mostrar que o ficheiro físico está cifrado.

### Parte C - Certificados
1. Mostrar inicialmente os certificados existentes no servidor.
2. Autenticar o terceiro utilizador.
3. Confirmar que o certificado desse utilizador foi adicionado ao servidor.
4. No cliente do `user1`, confirmar que a `truststore` só recebe o certificado do `user3` depois do `ADD user3 c1 M`.

### Parte D - CREATE / ADD / RD / EC / RT / RH
Segue esta ordem porque é a mais fácil de defender no código.

1. `CREATE c2`
	- O owner gera as chaves de secção.
	- O servidor guarda seis chaves cifradas, uma por secção.
2. `ADD user2 c2 P`
	- O owner partilha a chave da secção com `user2`.
	- O servidor cria a cópia cifrada da chave para esse utilizador.
3. `ADD user3 c2 P`
	- Igual ao ponto anterior, para um segundo utilizador.
4. `RD c2 P`
	- Registar um dispositivo na secção `P`.
5. `EC c2 P1 5`
	- O valor `5` é cifrado com a chave de secção antes de ser enviado.
6. `RH c2 P1`
	- O histórico do dispositivo deve ser mostrado em texto claro após a descodificação.
7. `RT c2`
	- Só devem aparecer dispositivos das secções para as quais o utilizador tem permissões.

### Parte E - Casos de erro esperados
1. `RH c2 M1` com utilizador sem permissão deve devolver `NOPERM`.
2. Corrupção manual de um ficheiro protegido deve fazer o servidor parar com aviso de integridade.
3. Substituição do `SpertaClient.jar` por outro binário deve falhar na atestação remota.

---

## 4. Script curto para responder a perguntas do avaliador

Se te pedirem uma explicação rápida, responde nesta ordem:

1. TLS: “As ligações são feitas via SSL/TLS com autenticação do servidor.”
2. Passwords: “O servidor não guarda passwords em claro; guarda `user:hash:salt`.”
3. Atestação: “Antes da autenticação, o servidor valida o `SpertaClient.jar` com nonce + SHA-256.”
4. Cifra: “Os ficheiros persistentes do servidor estão cifrados com PBE/AES-128-GCM.”
5. Integridade: “Cada ficheiro protegido tem um `.hash` verificado em leitura.”
6. Confidencialidade fim-a-fim: “Os comandos `EC`, `RT` e `RH` usam chaves de secção e o servidor não consegue ler o conteúdo em claro.”

---

## 5. Observações importantes para não falhar a demo

1. Não recompilar o `SpertaClient.jar` na Máquina 2 se a atestação depender do binário de referência do servidor.
2. Usar o mesmo JAR que o servidor espera para o teste de atestação.
3. Abrir sempre vários terminais separados, um por cliente.
4. Mostrar o conteúdo dos keystores e truststores com `keytool`, não apenas dizer que existem.
5. Se te pedirem para provar que o ficheiro `users.txt` tem o formato correto, mostrar o conteúdo desencriptado pelo código, não o ficheiro bruto no disco.

---

## 6. Resumo do que deves ter pronto

Antes da apresentação, confirma que consegues mostrar rapidamente:

1. O arranque do servidor.
2. Dois ou três clientes autenticados.
3. `CREATE`, `ADD`, `RD`, `EC`, `RT`, `RH` em ação.
4. `user:hash:salt` no código e no conteúdo desencriptado.
5. Ficheiros cifrados e `.hash` atualizados.
6. Atestação remota a aceitar um cliente válido e a rejeitar um inválido.
7. Certificados a aparecer e a ser propagados para a `truststore`.

Se quiseres, no passo seguinte posso também transformar este guia num checklist de apresentação ainda mais curto, em formato de uma página, para usares durante a demo.