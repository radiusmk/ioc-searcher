#!/usr/bin/env python3
"""
IOC Viewer - Ferramenta para visualizar e filtrar resultados de IOCs gerados pelo IOC Searcher
"""

import json
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
import re

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False


class IOCViewer:
    """Classe para visualizar e filtrar resultados de IOCs."""

    def __init__(self, json_file: str, memory_efficient: bool = False):
        self.json_file = Path(json_file)
        if not self.json_file.exists():
            raise FileNotFoundError(f"Arquivo JSON não encontrado: {json_file}")

        self.memory_efficient = memory_efficient

        # Mostra informações sobre o arquivo
        file_size_mb = self._get_file_size_mb()
        print(f"[*] Arquivo: {self.json_file.name} ({file_size_mb:.1f} MB)")

        self.data = self._load_json()
        self.ioc_types = list(self.data.keys())

        total_iocs = sum(len(iocs) for iocs in self.data.values())
        print(f"[*] Carregado: {total_iocs} IOCs em {len(self.ioc_types)} tipos")

    def _get_file_size_mb(self) -> float:
        """Retorna o tamanho do arquivo em MB."""
        return self.json_file.stat().st_size / (1024 * 1024)

    def _load_json_streaming(self) -> Dict[str, Dict[str, List[str]]]:
        """Carrega arquivo JSON grande usando streaming."""
        if not IJSON_AVAILABLE:
            raise ImportError("Biblioteca 'ijson' necessária para arquivos grandes. Instale com: pip install ijson")

        print(f"[*] Carregando arquivo grande ({self._get_file_size_mb():.1f} MB) em modo streaming...")

        results = defaultdict(lambda: defaultdict(list))

        try:
            with open(self.json_file, 'rb') as f:
                # Parse usando ijson para streaming
                for ioc_type, ioc, file_path in ijson.parse(f):
                    if ioc_type.endswith('.item'):
                        # Extrai o tipo de IOC do caminho
                        type_match = re.match(r'(\w+)\.(.+)\.item', ioc_type)
                        if type_match:
                            actual_type = type_match.group(1)
                            ioc_value = type_match.group(2)
                            results[actual_type][ioc_value].append(file_path)

            return dict(results)

        except Exception as e:
            raise Exception(f"Erro no carregamento streaming: {e}")

    def _load_json_chunked(self) -> Dict[str, Dict[str, List[str]]]:
        """Carrega arquivo JSON grande em pedaços para economia de memória."""
        print(f"[*] Carregando arquivo grande ({self._get_file_size_mb():.1f} MB) em modo chunked...")

        # Tamanho do chunk (10MB)
        chunk_size = 10 * 1024 * 1024

        json_content = ""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    json_content += chunk

                    # Verifica se temos um JSON completo
                    try:
                        return json.loads(json_content)
                    except json.JSONDecodeError:
                        continue

        except MemoryError:
            raise MemoryError("Arquivo muito grande mesmo para modo chunked. Considere usar um arquivo menor ou mais memória RAM.")
        except Exception as e:
            raise Exception(f"Erro no carregamento chunked: {e}")

    def _load_json(self) -> Dict[str, Dict[str, List[str]]]:
        """Carrega os dados do arquivo JSON com tratamento para arquivos grandes."""
        file_size_mb = self._get_file_size_mb()

        # Se modo econômico forçado, pula para métodos alternativos
        if self.memory_efficient and file_size_mb >= 50:
            print("[*] Modo econômico de memória ativado")

        # Arquivos pequenos (< 100MB): carregamento normal
        if file_size_mb < 100 and not self.memory_efficient:
            try:
                with open(self.json_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (MemoryError, json.JSONDecodeError) as e:
                print(f"[!] Carregamento normal falhou ({e}), tentando métodos alternativos...")

        # Arquivos médios (100MB - 500MB) ou modo econômico: modo chunked
        if file_size_mb < 500 or self.memory_efficient:
            try:
                return self._load_json_chunked()
            except Exception as e:
                if file_size_mb >= 500 or self.memory_efficient:
                    print(f"[!] Modo chunked falhou ({e}), tentando streaming...")
                else:
                    raise e

        # Arquivos grandes (> 500MB): modo streaming
        try:
            return self._load_json_streaming()
        except ImportError:
            raise ImportError(
                f"Arquivo muito grande ({file_size_mb:.1f} MB) requer biblioteca 'ijson'. "
                "Instale com: pip install ijson"
            )
        except Exception as e:
            raise Exception(f"Erro ao carregar arquivo grande: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Retorna estatísticas gerais dos resultados."""
        stats = {
            'total_iocs': 0,
            'total_files': set(),
            'by_type': {},
            'by_file': defaultdict(int)
        }

        for ioc_type, iocs in self.data.items():
            type_count = 0
            type_files = set()

            for ioc, files in iocs.items():
                type_count += 1
                stats['total_iocs'] += 1
                type_files.update(files)
                stats['total_files'].update(files)

                for file in files:
                    stats['by_file'][file] += 1

            stats['by_type'][ioc_type] = {
                'count': type_count,
                'files': len(type_files)
            }

        stats['total_files'] = len(stats['total_files'])
        return stats

    def filter_by_type(self, ioc_types: List[str]) -> Dict[str, Dict[str, List[str]]]:
        """Filtra resultados por tipos de IOC específicos."""
        if not ioc_types:
            return self.data

        filtered = {}
        for ioc_type in ioc_types:
            if ioc_type in self.data:
                filtered[ioc_type] = self.data[ioc_type]
        return filtered

    def filter_by_path(self, path_pattern: str) -> Dict[str, Dict[str, List[str]]]:
        """Filtra resultados por padrão de caminho/arquivo."""
        if not path_pattern:
            return self.data

        filtered = defaultdict(lambda: defaultdict(list))

        for ioc_type, iocs in self.data.items():
            for ioc, files in iocs.items():
                matching_files = [f for f in files if path_pattern.lower() in f.lower()]
                if matching_files:
                    filtered[ioc_type][ioc] = matching_files

        return dict(filtered)

    def search_iocs(self, search_term: str) -> Dict[str, Dict[str, List[str]]]:
        """Busca IOCs que contenham o termo de pesquisa."""
        if not search_term:
            return self.data

        filtered = defaultdict(lambda: defaultdict(list))

        for ioc_type, iocs in self.data.items():
            for ioc, files in iocs.items():
                if search_term.lower() in ioc.lower():
                    filtered[ioc_type][ioc] = files

        return dict(filtered)

    def display_results(self, results: Dict[str, Dict[str, List[str]]], show_files: bool = True):
        """Exibe os resultados de forma amigável."""
        if not results:
            print("\n[!] Nenhum resultado encontrado com os filtros aplicados.")
            return

        print("\n" + "=" * 80)
        print("RESULTADOS DOS IOCs")
        print("=" * 80)

        total_iocs = sum(len(iocs) for iocs in results.values())

        for ioc_type, iocs in results.items():
            if not iocs:
                continue

            print(f"\n[{ioc_type.upper()}] ({len(iocs)} encontrados)")
            print("-" * 50)

            for ioc, files in sorted(iocs.items()):
                print(f"\n  {ioc}")
                if show_files:
                    print(f"  Arquivos ({len(files)}):")
                    for file in sorted(files):
                        print(f"    - {file}")

    def display_table(self, results: Dict[str, Dict[str, List[str]]], show_files: bool = False):
        """Exibe os resultados em formato de tabela."""
        try:
            if not TABULATE_AVAILABLE:
                print("\n[!] Biblioteca 'tabulate' não está instalada.")
                print("   Instale com: pip install tabulate")
                print("   Alternativamente, use a visualização normal.")
                return

            if not results:
                print("\n[!] Nenhum resultado encontrado com os filtros aplicados.")
                return

            print(f"[*] Preparando tabela com {sum(len(iocs) for iocs in results.values())} IOCs...")

            # Preparar dados para tabela
            table_data = []
            processed_count = 0

            for ioc_type, iocs in results.items():
                for ioc, files in iocs.items():
                    try:
                        if show_files:
                            # Uma linha por combinação IOC-arquivo
                            for file in sorted(files):
                                table_data.append([ioc, ioc_type.upper(), file])
                        else:
                            # Uma linha por IOC (com contagem de arquivos)
                            file_count = len(files)
                            files_str = f"{file_count} arquivo{'s' if file_count > 1 else ''}"
                            table_data.append([ioc, ioc_type.upper(), files_str])

                        processed_count += 1
                        if processed_count % 10000 == 0:
                            print(f"[*] Processados {processed_count} IOCs...")

                    except Exception as e:
                        print(f"[!] Erro processando IOC '{ioc}': {e}")
                        continue

            if not table_data:
                print("\n[!] Nenhum IOC encontrado.")
                return

            print(f"[*] Ordenando {len(table_data)} entradas...")

            # Ordenar por tipo de IOC, depois por IOC
            try:
                table_data.sort(key=lambda x: (x[1], x[0]))
            except Exception as e:
                print(f"[!] Erro na ordenação: {e}")
                print("[*] Continuando sem ordenação...")

            print("\n" + "=" * 80)
            print("TABELA DE IOCs")
            print("=" * 80)

            headers = ["IOC", "TIPO", "ARQUIVOS" if show_files else "CONTAGEM"]

            print(tabulate(table_data, headers=headers, tablefmt="grid"))

            total_iocs = len(set(row[0] for row in table_data)) if show_files else len(table_data)
            print(f"\nTotal de IOCs únicos: {total_iocs}")
            print(f"Total de entradas na tabela: {len(table_data)}")

        except MemoryError:
            print("\n[!] Erro de memória ao criar tabela.")
            print("   Arquivo muito grande para exibir em tabela completa.")
            print("   Tente usar filtros para reduzir os resultados:")
            print("   --filter-type ips,domains")
            print("   --search termo")
            print("   --filter-path caminho")
        except Exception as e:
            print(f"\n[!] Erro ao exibir tabela: {e}")
            print(f"   Tipo do erro: {type(e).__name__}")
            import traceback
            print(f"   Traceback: {traceback.format_exc()}")

    def display_statistics(self):
        """Exibe estatísticas gerais."""
        stats = self.get_statistics()

        print("\n" + "=" * 80)
        print("ESTATÍSTICAS GERAIS")
        print("=" * 80)
        print(f"Total de IOCs encontrados: {stats['total_iocs']}")
        print(f"Total de arquivos afetados: {stats['total_files']}")
        print(f"Tipos de IOC detectados: {len(self.ioc_types)}")

        print("\nDistribuição por tipo:")
        for ioc_type, type_stats in stats['by_type'].items():
            print(f"  {ioc_type}: {type_stats['count']} IOCs em {type_stats['files']} arquivos")

        if stats['by_file']:
            print("\nArquivos mais afetados:")
            sorted_files = sorted(stats['by_file'].items(), key=lambda x: x[1], reverse=True)[:10]
            for file, count in sorted_files:
                print(f"  {file}: {count} IOCs")

    def interactive_menu(self):
        """Interface interativa para navegação dos resultados."""
        while True:
            print("\n" + "=" * 80)
            print("IOC VIEWER - MENU PRINCIPAL")
            print("=" * 80)
            print("1. Ver todos os resultados")
            print("2. Filtrar por tipo de IOC")
            print("3. Filtrar por caminho/arquivo")
            print("4. Buscar IOC específico")
            print("5. Ver estatísticas")
            print("6. Ver resultados em tabela")
            print("7. Sair")

            try:
                choice = input("\nEscolha uma opção (1-7): ").strip()

                if choice == "1":
                    self.display_results(self.data)
                    input("\nPressione Enter para continuar...")

                elif choice == "2":
                    print(f"\nTipos disponíveis: {', '.join(self.ioc_types)}")
                    types_input = input("Digite os tipos separados por vírgula (ou Enter para todos): ").strip()
                    if types_input:
                        selected_types = [t.strip() for t in types_input.split(',')]
                        filtered = self.filter_by_type(selected_types)
                        self.display_results(filtered)
                    else:
                        self.display_results(self.data)
                    input("\nPressione Enter para continuar...")

                elif choice == "3":
                    path_pattern = input("Digite o padrão de caminho/arquivo: ").strip()
                    if path_pattern:
                        filtered = self.filter_by_path(path_pattern)
                        self.display_results(filtered)
                    else:
                        print("[!] Padrão vazio. Mostrando todos os resultados.")
                        self.display_results(self.data)
                    input("\nPressione Enter para continuar...")

                elif choice == "4":
                    search_term = input("Digite o termo para buscar nos IOCs: ").strip()
                    if search_term:
                        filtered = self.search_iocs(search_term)
                        self.display_results(filtered)
                    else:
                        print("[!] Termo vazio. Mostrando todos os resultados.")
                        self.display_results(self.data)
                    input("\nPressione Enter para continuar...")

                elif choice == "5":
                    self.display_statistics()
                    input("\nPressione Enter para continuar...")

                elif choice == "6":
                    print("\nEscolha o formato da tabela:")
                    print("1. IOC único por linha (com contagem de arquivos)")
                    print("2. Uma linha por IOC-arquivo (detalhado)")

                    table_choice = input("\nEscolha (1-2) ou Enter para padrão: ").strip()

                    if table_choice == "2":
                        self.display_table(self.data, show_files=True)
                    else:
                        self.display_table(self.data, show_files=False)
                    input("\nPressione Enter para continuar...")

                elif choice == "7":
                    print("\n[!] Saindo do IOC Viewer...")
                    break

                else:
                    print("[!] Opção inválida. Tente novamente.")

            except KeyboardInterrupt:
                print("\n[!] Interrupção detectada. Saindo...")
                break
            except Exception as e:
                print(f"[!] Erro: {e}")
                input("Pressione Enter para continuar...")


def main():
    parser = argparse.ArgumentParser(
        description='Visualizador e filtro de resultados de IOCs gerados pelo IOC Searcher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python ioc_viewer.py relatorio.json
  python ioc_viewer.py relatorio.json --stats
  python ioc_viewer.py relatorio.json --filter-type ips,domains
  python ioc_viewer.py relatorio.json --filter-path config.txt
  python ioc_viewer.py relatorio.json --search malicious
  python ioc_viewer.py relatorio.json --table
  python ioc_viewer.py relatorio.json --table-detailed
  python ioc_viewer.py relatorio.json --filter-type ips --table
        """
    )

    parser.add_argument(
        'json_file',
        help='Arquivo JSON gerado pelo IOC Searcher'
    )

    parser.add_argument(
        '--stats', '-s',
        action='store_true',
        help='Mostrar apenas estatísticas gerais'
    )

    parser.add_argument(
        '--filter-type',
        help='Filtrar por tipos específicos de IOC (separados por vírgula)'
    )

    parser.add_argument(
        '--filter-path',
        help='Filtrar por padrão de caminho/arquivo'
    )

    parser.add_argument(
        '--search',
        help='Buscar IOCs que contenham o termo especificado'
    )

    parser.add_argument(
        '--no-files',
        action='store_true',
        help='Não mostrar lista de arquivos nos resultados'
    )

    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Modo interativo com menu'
    )

    parser.add_argument(
        '--table', '-t',
        action='store_true',
        help='Mostrar resultados em formato de tabela'
    )

    parser.add_argument(
        '--table-detailed',
        action='store_true',
        help='Mostrar tabela detalhada (uma linha por IOC-arquivo)'
    )

    parser.add_argument(
        '--memory-efficient',
        action='store_true',
        help='Forçar modo de carregamento econômico de memória'
    )

    args = parser.parse_args()

    try:
        viewer = IOCViewer(args.json_file, memory_efficient=args.memory_efficient)

        # Modo interativo
        if args.interactive:
            viewer.interactive_menu()
            return

        # Aplicar filtros
        results = viewer.data

        if args.filter_type:
            types = [t.strip() for t in args.filter_type.split(',')]
            results = viewer.filter_by_type(types)

        if args.filter_path:
            results = viewer.filter_by_path(args.filter_path)

        if args.search:
            results = viewer.search_iocs(args.search)

        # Mostrar resultados
        if args.stats:
            viewer.display_statistics()
        elif args.table or args.table_detailed:
            viewer.display_table(results, show_files=args.table_detailed)
        else:
            viewer.display_results(results, show_files=not args.no_files)

    except Exception as e:
        print(f"[!] Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
