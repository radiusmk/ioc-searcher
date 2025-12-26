#!/usr/bin/env python3
"""
Módulo para processamento de diferentes tipos de arquivos.
"""

import os
from pathlib import Path
from typing import Optional

try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False


class FileProcessor:
    """Classe para processar e ler diferentes tipos de arquivos."""
    
    def __init__(self, max_file_size: int = 50 * 1024 * 1024):  # 50MB padrão
        self.max_file_size = max_file_size
    
    def read_file(self, file_path: Path) -> Optional[str]:
        """
        Lê um arquivo e retorna seu conteúdo como string.
        Tenta detectar a codificação automaticamente.
        """
        try:
            # Verifica tamanho do arquivo
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                # Para arquivos muito grandes, lê apenas uma amostra
                return self._read_large_file_sample(file_path)
            
            # Tenta ler com diferentes codificações
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                        # Verifica se parece ser texto (não binário)
                        if self._is_text_content(content):
                            return content
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            # Se nenhuma codificação funcionou, tenta detectar automaticamente
            return self._read_with_detection(file_path)
            
        except PermissionError:
            return None
        except Exception as e:
            return None
    
    def _read_large_file_sample(self, file_path: Path, sample_size: int = 10 * 1024 * 1024) -> Optional[str]:
        """
        Lê uma amostra de um arquivo grande (primeiros N bytes).
        """
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(sample_size)
            
            # Detecta codificação
            if HAS_CHARDET:
                detected = chardet.detect(sample)
                encoding = detected.get('encoding', 'utf-8')
            else:
                encoding = 'utf-8'
            
            if encoding:
                try:
                    content = sample.decode(encoding, errors='ignore')
                    if self._is_text_content(content):
                        return content
                except:
                    pass
            
            # Fallback para latin-1
            try:
                content = sample.decode('latin-1', errors='ignore')
                if self._is_text_content(content):
                    return content
            except:
                pass
            
            return None
            
        except Exception:
            return None
    
    def _read_with_detection(self, file_path: Path) -> Optional[str]:
        """
        Lê arquivo detectando a codificação automaticamente.
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(min(1024 * 1024, self.max_file_size))  # Lê até 1MB para detecção
            
            if HAS_CHARDET:
                detected = chardet.detect(raw_data)
                encoding = detected.get('encoding', 'utf-8')
                confidence = detected.get('confidence', 0)
                
                # Se a confiança for muito baixa, tenta utf-8
                if confidence < 0.5:
                    encoding = 'utf-8'
            else:
                encoding = 'utf-8'
            
            # Lê o arquivo completo com a codificação detectada
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read(self.max_file_size)
                if self._is_text_content(content):
                    return content
            
            return None
            
        except Exception:
            return None
    
    def _is_text_content(self, content: str) -> bool:
        """
        Verifica se o conteúdo parece ser texto (não binário).
        """
        if not content:
            return False
        
        # Verifica se há muitos caracteres não imprimíveis
        non_printable = sum(1 for c in content[:1000] if ord(c) < 32 and c not in '\n\r\t')
        if non_printable > len(content[:1000]) * 0.3:
            return False
        
        # Verifica se há muitos bytes nulos
        if '\x00' in content[:1000]:
            return False
        
        return True
    
    def is_text_file(self, file_path: Path) -> bool:
        """
        Verifica se um arquivo parece ser um arquivo de texto.
        """
        try:
            # Verifica extensão
            text_extensions = {
                '.txt', '.log', '.conf', '.config', '.cfg', '.ini',
                '.json', '.xml', '.yaml', '.yml', '.sh', '.bat', '.cmd',
                '.ps1', '.py', '.js', '.html', '.sql', '.csv', '.md',
                '.history', '.bash_history', '.zsh_history'
            }
            
            if file_path.suffix.lower() in text_extensions:
                return True
            
            # Tenta ler uma amostra
            sample = self.read_file(file_path)
            return sample is not None
            
        except Exception:
            return False

