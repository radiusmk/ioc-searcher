#!/usr/bin/env python3
"""
IOC Searcher - Ferramenta para buscar Indicators of Compromise em arquivos vazados
de ataques de ransomware.
"""

import os
import sys
import argparse
import json
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Set, Tuple
import re
import time

try:
    from colorama import init, AnsiToWin32
    import colorama
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

from ioc_detectors import IOCDetector
from file_processor import FileProcessor


class IOCSearcher:
    """Classe principal para realizar buscas de IOCs em arquivos."""
    
    def __init__(self, target_directory: str):
        self.target_directory = Path(target_directory)
        if not self.target_directory.exists():
            raise ValueError(f"Diretório não encontrado: {target_directory}")
        
        self.detector = IOCDetector()
        self.processor = FileProcessor()
        self.results = defaultdict(lambda: defaultdict(set))
        
    def search(self) -> Dict:
        """Realiza a busca de IOCs em todos os arquivos do diretório."""
        print(f"[*] Iniciando busca de IOCs em: {self.target_directory}")
        print(f"[*] Processando arquivos...")

        file_count = 0
        processed_count = 0
        total_matches = 0

        # Extensões de arquivos de texto e logs comuns (lista expandida)
        text_extensions = {
            '.txt', '.log', '.conf', '.config', '.cfg', '.ini',
            '.json', '.xml', '.yaml', '.yml', '.sh', '.bat', '.cmd',
            '.ps1', '.py', '.js', '.html', '.sql', '.csv', '.md',
            '.history', '.bash_history', '.zsh_history', '.out', '.err',
            '.dat', '.data', '.dump', '.trace', '.debug', '.info',
            '.warn', '.error', '.access', '.audit', '.syslog', '.auth',
            '.secure', '.messages', '.evt', '.evtx', '.eventlog',
            '.reg', '.inf', '.properties', '.env', '.htaccess', '.htpasswd'
        }

        # Nomes de arquivos de log comuns
        log_patterns = [
            'messages', 'audit', 'syslog', 'auth.log', 'secure',
            'access.log', 'error.log', 'evtx', 'eventlog', 'history'
        ]

        # Extensões binárias conhecidas que devem ser ignoradas
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.com', '.scr',
            '.msi', '.deb', '.rpm', '.pkg', '.dmg', '.iso', '.img',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
            '.db', '.sqlite', '.mdb', '.accdb', '.dbf'
        }

        # Coleta apenas arquivos que têm alta probabilidade de serem de texto
        total_files = 0
        all_files = []

        for root, dirs, files in os.walk(self.target_directory):
            for file in files:
                file_path = Path(root) / file
                file_lower = file.lower()
                file_suffix = file_path.suffix.lower()

                # Ignora arquivos binários conhecidos
                if file_suffix in binary_extensions:
                    continue

                should_process = False

                # Verifica extensão de texto conhecida
                if file_suffix in text_extensions:
                    should_process = True

                # Verifica se é um arquivo de log conhecido (mesmo sem extensão)
                if any(pattern in file_lower for pattern in log_patterns):
                    should_process = True

                # Para arquivos sem extensão, apenas processa se for muito pequeno (< 100 bytes)
                # e contenha "history" no nome (como arquivos de histórico de comandos)
                if not file_suffix and len(file) < 100 and 'history' in file_lower:
                    should_process = True

                # Para outros arquivos sem extensão conhecida, verifica se é realmente texto
                if not file_suffix and not should_process:
                    # Tenta verificar se é texto lendo uma pequena amostra
                    if self.processor.is_text_file(file_path):
                        should_process = True

                # Só adiciona se deve processar
                if should_process:
                    all_files.append(file_path)
                    total_files += 1

        print(f"[*] Total de arquivos a processar: {total_files}")

        # Inicializa colorama para melhor compatibilidade com Windows
        if COLORAMA_AVAILABLE:
            init(wrap=False)
            # Redireciona stdout para suportar ANSI no Windows
            if hasattr(sys.stdout, 'reconfigure'):
                try:
                    sys.stdout.reconfigure(encoding='utf-8')
                except:
                    pass

        # Processa os arquivos
        last_displayed_file = None

        for file_path in all_files:
            processed_count += 1

            # Exibe apenas o arquivo sendo processado na mesma linha
            try:
                relative_path = file_path.relative_to(self.target_directory)
            except ValueError:
                # Se não conseguir fazer relative, usa o caminho completo
                relative_path = str(file_path)

            # Mostra progresso e arquivo atual na mesma linha
            status_msg = f"{processed_count} de {total_files}: {relative_path}"

            # Atualiza a exibição na mesma linha usando colorama para compatibilidade Windows
            if COLORAMA_AVAILABLE:
                # Usa sequências ANSI com colorama para Windows
                if last_displayed_file is not None:
                    # Move cursor para cima e limpa a linha
                    print(colorama.ansi.clear_line(), end='')
                    print(colorama.Cursor.UP(1), end='')
                print(status_msg, end='\r')
            else:
                # Fallback sem colorama - mostra em linhas separadas
                print(status_msg)

            last_displayed_file = status_msg

            try:
                matches = self._process_file(file_path)
                if matches:
                    file_count += 1
                    total_matches += sum(len(v) for v in matches.values())
                    self._update_results(str(file_path), matches)
            except Exception as e:
                # Limpa a linha atual e mostra o erro em nova linha
                sys.stdout.write(f"\r{' ' * len(status_msg)}\r")
                sys.stdout.flush()
                print(f"[!] Erro ao processar {file_path}: {e}")

        # Limpa a linha final de status
        if COLORAMA_AVAILABLE:
            print(colorama.ansi.clear_line(), end='')
        else:
            # Fallback - apenas adiciona uma linha em branco
            print()

        print(f"[*] Processamento concluído!")
        print(f"[*] Arquivos processados: {file_count} (de {processed_count} analisados)")
        print(f"[*] Total de IOCs encontrados: {total_matches}\n")

        return dict(self.results)
    
    def _process_file(self, file_path: Path) -> Dict[str, Set]:
        """Processa um arquivo e retorna os IOCs encontrados."""
        try:
            content = self.processor.read_file(file_path)
            if not content:
                return {}
            
            matches = self.detector.detect_all(content)
            return matches
        except Exception as e:
            # Arquivo pode ser binário ou corrompido
            return {}
    
    def _update_results(self, file_path: str, matches: Dict[str, Set]):
        """Atualiza os resultados com os IOCs encontrados."""
        for ioc_type, ioc_set in matches.items():
            for ioc in ioc_set:
                self.results[ioc_type][ioc].add(file_path)
    
    def print_results(self):
        """Imprime os resultados de forma formatada."""
        print("=" * 80)
        print("RESULTADOS DA BUSCA DE IOCs")
        print("=" * 80)
        
        for ioc_type in ['ips', 'domains', 'commands', 'passwords', 'software', 'urls']:
            if ioc_type in self.results and self.results[ioc_type]:
                print(f"\n[{ioc_type.upper()}]")
                print("-" * 80)
                
                for ioc, files in sorted(self.results[ioc_type].items()):
                    print(f"\n  {ioc}")
                    print(f"  Arquivos ({len(files)}):")
                    for file in sorted(files):
                        print(f"    - {file}")
        
        print("\n" + "=" * 80)
    
    def export_json(self, output_file: str):
        """Exporta os resultados para um arquivo JSON."""
        export_data = {}
        for ioc_type, iocs in self.results.items():
            export_data[ioc_type] = {
                ioc: list(files) for ioc, files in iocs.items()
            }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Resultados exportados para: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Busca Indicators of Compromise (IOCs) em arquivos vazados de ransomware',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python ioc_searcher.py ./ransomware_files
  python ioc_searcher.py ./ransomware_files --output results.json
  python ioc_searcher.py ./ransomware_files --json-only
        """
    )
    
    parser.add_argument(
        'directory',
        help='Diretório contendo os arquivos para análise'
    )
    
    parser.add_argument(
        '--output', '-o',
        default=None,
        help='Arquivo JSON para exportar os resultados'
    )
    
    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Apenas exporta para JSON, sem imprimir resultados no console'
    )
    
    args = parser.parse_args()
    
    try:
        searcher = IOCSearcher(args.directory)
        results = searcher.search()
        
        if not args.json_only:
            searcher.print_results()
        
        if args.output:
            searcher.export_json(args.output)
        elif args.json_only:
            # Se --json-only mas sem --output, usa nome padrão
            searcher.export_json('ioc_results.json')
        
    except ValueError as e:
        print(f"[!] Erro: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro inesperado: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

