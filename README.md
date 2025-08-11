# Defesa-cibernetica-kernel
🛡️ Defesa Cibernética: Ferramentas do Kernel para Blue Teams
Em um ambiente de segurança, as equipes de Blue Team (defesa) precisam de visibilidade profunda para detectar, analisar e responder a ameaças. O kernel é o nível mais crítico para essa visibilidade. Este post explora ferramentas e técnicas que Blue Teams usam diariamente para monitorar a atividade do sistema, identificar anomalias e combater ameaças persistentes.
1. Monitoramento de Chamadas de Sistema com auditd
O Linux Auditing System (auditd) é a principal ferramenta para um Blue Team entender o que está acontecendo no nível mais baixo. Ele registra eventos de segurança, como a execução de programas e o acesso a arquivos, permitindo que os analistas rastreiem a atividade maliciosa.
 * Exemplo de Regra de Auditoria: Esta regra monitora qualquer tentativa de modificar um arquivo de configuração crítico do SSH.
   # Adicione esta regra ao arquivo /etc/audit/rules.d/audit.rules
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes

 * Comando para Visualizar os Logs de Auditoria: Use o ausearch para filtrar os logs e procurar eventos específicos da regra que você criou.
   sudo ausearch -k ssh_config_changes -ts today

   Este comando mostra todas as tentativas de escrita (w) ou alteração de atributos (a) no arquivo sshd_config no dia de hoje.
2. Detecção de Alterações de Integridade com aide
A detecção de rootkits e outros malwares persistentes que alteram arquivos do sistema é uma tarefa central do Blue Team. Ferramentas como o AIDE (Advanced Intrusion Detection Environment) criam um banco de dados de hashes (impressões digitais) de arquivos críticos e alertam se algum deles for alterado.
 * Comando para Inicializar a Base de Dados: Execute isso após a instalação do sistema, quando ele estiver em um estado "limpo".
   sudo aide --init

   Depois, renomeie o arquivo aide.db.new.gz para aide.db.gz.
 * Comando para Verificar a Integridade: Execute este comando regularmente (via cron) para verificar se algum arquivo foi alterado.
   sudo aide --check

   A saída mostrará exatamente quais arquivos foram alterados, adicionados ou removidos.
3. Análise de Comportamento em Tempo Real com Falco
Em vez de apenas auditar, o Blue Team precisa de detecção em tempo real. O Falco é um motor de detecção de ameaças de código aberto que se conecta diretamente ao kernel para monitorar a atividade do sistema. Ele usa regras para identificar comportamentos suspeitos, como um processo de shell sendo executado dentro de um contêiner.
 * Exemplo de Regra do Falco: Esta regra simples dispara um alarme se um arquivo binário for executado dentro de um diretório de um contêiner.
   - rule: Run shell in container
  desc: a shell was spawned in a container
  condition: container.id != "host" and proc.name in ("bash", "sh", "zsh")
  output: A shell was spawned in a container (user=%user.name container=%container.name)
  priority: ERROR

 * Comando para Iniciar o Falco:
   sudo falco -c /etc/falco/falco.yaml

   O Falco começará a monitorar o sistema em tempo real, enviando alertas para a saída padrão ou para um log.
4. Monitoramento da Rede no Nível do Kernel com tcpdump
Ataques de rede podem ser detectados ao nível mais baixo do kernel. O tcpdump é uma ferramenta de linha de comando essencial para capturar e analisar pacotes de rede que passam pelo kernel.
 * Comando para Monitorar o Tráfego Suspeito: Este comando captura todo o tráfego que não é SSH (porta 22) na interface eth0, que pode indicar tráfego incomum.
   sudo tcpdump -i eth0 not port 22

   A saída mostrará os pacotes de rede em tempo real, permitindo que você identifique atividades anômalas.
