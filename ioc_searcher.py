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
import signal
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    from colorama import init, AnsiToWin32
    import colorama
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

from ioc_detectors import IOCDetector
from file_processor import FileProcessor

# Flag global para controlar interrupção
shutdown_event = threading.Event()

def signal_handler(signum, frame):
    """Handler para sinais de interrupção."""
    global shutdown_event
    print("\n[!] Recebido sinal de interrupção. Encerrando graciosamente...", flush=True)
    shutdown_event.set()

# Configura o handler de sinal
signal.signal(signal.SIGINT, signal_handler)

def check_shutdown():
    """Verifica se foi solicitado shutdown e lança KeyboardInterrupt se necessário."""
    if shutdown_event.is_set():
        raise KeyboardInterrupt("Shutdown solicitado")


class IOCSearcher:
    """Classe principal para realizar buscas de IOCs em arquivos."""

    def __init__(self, target_directory: str, max_workers: int = 4):
        self.target_directory = Path(target_directory)
        if not self.target_directory.exists():
            raise ValueError(f"Diretório não encontrado: {target_directory}")

        self.detector = IOCDetector()
        self.processor = FileProcessor()
        self.results = defaultdict(lambda: defaultdict(set))
        self.results_lock = threading.Lock()  # Lock para acesso thread-safe aos resultados
        self.max_workers = max_workers

        # Passa a função de verificação de shutdown para o processor
        self.processor.set_shutdown_checker(check_shutdown)
        
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

        # Processa os arquivos usando múltiplas threads
        processed_count = 0
        file_count = 0
        total_matches = 0
        thread_id_counter = 0

        # Estruturas thread-safe
        progress_lock = threading.Lock()
        thread_status_lock = threading.Lock()
        output_lock = threading.Lock()

        def get_thread_id():
            """Atribui um ID único para cada thread."""
            with thread_status_lock:
                nonlocal thread_id_counter
                thread_id_counter += 1
                return thread_id_counter

        def show_progress():
            """Mostra o progresso atual."""
            with thread_status_lock:
                progress_msg = f"[*] Progresso: {processed_count}/{total_files} arquivos processados"
                with output_lock:
                    print(progress_msg, flush=True)

        def process_file_threaded(file_path):
            """Processa um arquivo em uma thread separada."""
            nonlocal processed_count, file_count, total_matches

            thread_id = get_thread_id()

            # Verifica se foi solicitado encerramento antes de começar
            if shutdown_event.is_set():
                with thread_status_lock:
                    processed_count += 1
                return False

            # Mostra que a thread começou o processamento
            relative_path = str(file_path).replace(str(self.target_directory), '').lstrip(os.sep)
            with output_lock:
                print(f"[Thread {thread_id}] Iniciando processamento: {relative_path}", flush=True)

            try:
                # Verifica novamente se foi solicitado encerramento
                if shutdown_event.is_set():
                    with thread_status_lock:
                        processed_count += 1
                    with output_lock:
                        print(f"[Thread {thread_id}] Iniciando processamento: {relative_path} (Interrompido).", flush=True)
                    show_progress()
                    return False

                matches = self._process_file(file_path)

                # Verifica uma última vez após processamento
                if shutdown_event.is_set():
                    with thread_status_lock:
                        processed_count += 1
                    with output_lock:
                        print(f"[Thread {thread_id}] Iniciando processamento: {relative_path} (Interrompido).", flush=True)
                    show_progress()
                    return False

                success = bool(matches)

                # Atualiza contadores de forma thread-safe
                with thread_status_lock:
                    if success:
                        file_count += 1
                        total_matches += sum(len(v) for v in matches.values())
                    processed_count += 1

                if success:
                    # Atualiza resultados de forma thread-safe
                    with self.results_lock:
                        self._update_results(str(file_path), matches)

                # Mostra que a thread terminou o processamento
                if success:
                    with output_lock:
                        print(f"[Thread {thread_id}] Iniciando processamento: {relative_path} (Concluído).", flush=True)
                show_progress()
                return success

            except Exception as e:
                # Atualiza status e mostra erro
                with thread_status_lock:
                    processed_count += 1
                with output_lock:
                    print(f"[Thread {thread_id}] Iniciando processamento: {relative_path} (Erro).", flush=True)
                    print(f"[!] Erro na Thread {thread_id} ao processar {relative_path}: {e}", flush=True)
                show_progress()
                return False

        # Executa processamento multi-thread
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submete todos os arquivos para processamento
            future_to_file = {executor.submit(process_file_threaded, file_path): file_path
                            for file_path in all_files}

            # Aguarda conclusão de todas as tarefas com verificação de interrupção
            try:
                # Processa tarefas com verificação periódica de interrupção
                remaining_futures = set(future_to_file.keys())
                while remaining_futures and not shutdown_event.is_set():
                    # Usa timeout para permitir verificação de interrupção
                    try:
                        completed, remaining_futures = concurrent.futures.wait(
                            remaining_futures, timeout=0.1,
                            return_when=concurrent.futures.FIRST_COMPLETED
                        )

                        # Processa tarefas concluídas
                        for future in completed:
                            try:
                                future.result()  # Levanta exceções se houver
                            except Exception as e:
                                # Erro já foi tratado na função process_file_threaded
                                pass

                            # Atualiza progresso após cada tarefa concluída
                            show_progress()

                    except concurrent.futures.TimeoutError:
                        # Timeout normal, continua verificando
                        continue

                # Se foi interrompido, cancela tarefas restantes
                if shutdown_event.is_set():
                    print("\n[!] Interrupção solicitada. Cancelando tarefas restantes...", flush=True)
                    for future in remaining_futures:
                        future.cancel()

            except KeyboardInterrupt:
                print("\n[!] KeyboardInterrupt detectado. Encerrando...", flush=True)
                shutdown_event.set()
                # Cancela tarefas pendentes
                for future in future_to_file:
                    if not future.done():
                        future.cancel()

        # Mostra progresso final
        with progress_lock:
            if COLORAMA_AVAILABLE:
                print(colorama.ansi.clear_line(), end='')
            print(f"[*] Processamento concluído: {processed_count}/{total_files} arquivos")

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
  python ioc_searcher.py /caminho/para/analisar
  python ioc_searcher.py /dados/ransomware --output relatorio.json --threads 8
  python ioc_searcher.py /logs/suspeitos --json-only --threads 2
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

    parser.add_argument(
        '--threads', '-t',
        type=int,
        default=4,
        help='Número de threads para processamento paralelo (padrão: 4)'
    )
    
    args = parser.parse_args()
    
    try:
        searcher = IOCSearcher(args.directory, max_workers=args.threads)
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
        print("\n[!] Interrompido pelo usuário (Ctrl+C)", file=sys.stderr)
        print("[*] Saindo graciosamente...", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro inesperado: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

