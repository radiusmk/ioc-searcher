#!/usr/bin/env python3
"""
Módulo de detecção de Indicators of Compromise (IOCs).
"""

import re
from typing import Dict, Set, List
from collections import defaultdict


class IOCDetector:
    """Classe para detectar diferentes tipos de IOCs em texto."""
    
    def __init__(self):
        self.patterns = self._compile_patterns()
        self.suspicious_commands = self._load_suspicious_commands()
        self.ransomware_keywords = self._load_ransomware_keywords()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compila os padrões regex para detecção de IOCs."""
        patterns = {}
        
        # IPv4
        patterns['ipv4'] = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 (simplificado)
        patterns['ipv6'] = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b::1\b|'
            r'\b::ffff:\d+\.\d+\.\d+\.\d+\b'
        )
        
        # Domínios
        patterns['domain'] = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        )
        
        # URLs
        patterns['url'] = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        # Senhas comuns (padrões)
        patterns['password'] = re.compile(
            r'(?:password|passwd|pwd|senha)\s*[:=]\s*([^\s\n]{4,})',
            re.IGNORECASE
        )
        
        # Hash MD5
        patterns['md5'] = re.compile(r'\b[a-fA-F0-9]{32}\b')
        
        # Hash SHA1
        patterns['sha1'] = re.compile(r'\b[a-fA-F0-9]{40}\b')
        
        # Hash SHA256
        patterns['sha256'] = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # Email
        patterns['email'] = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        )
        
        return patterns
    
    def _load_suspicious_commands(self) -> List[str]:
        """Lista de comandos suspeitos comuns em ataques."""
        return [
            r'wget\s+',
            r'curl\s+',
            r'nc\s+.*-e',
            r'ncat\s+.*-e',
            r'bash\s+-i\s+>&',
            r'python\s+-c',
            r'perl\s+-e',
            r'powershell\s+-enc',
            r'powershell\s+-e\s+',
            r'cmd\.exe\s+/c',
            r'certutil\s+-urlcache',
            r'bitsadmin',
            r'reg\s+add',
            r'reg\s+save',
            r'schtasks\s+/create',
            r'sc\s+create',
            r'net\s+user\s+.*\s+/add',
            r'net\s+localgroup\s+administrators',
            r'vssadmin\s+delete\s+shadows',
            r'bcdedit\s+/set',
            r'wmic\s+process',
            r'wmic\s+shadowcopy\s+delete',
            r'fsutil\s+usn\s+deletejournal',
            r'wevtutil\s+cl',
            r'cipher\s+/w',
            r'format\s+',
            r'del\s+/f\s+/s\s+/q',
            r'rm\s+-rf',
            r'mkdir\s+.*\$',
            r'chmod\s+\+x',
            r'chattr\s+\+i',
            r'iptables\s+-F',
            r'systemctl\s+stop',
            r'service\s+.*\s+stop',
            r'killall\s+',
            r'pkill\s+',
            r'xargs\s+kill',
            r'find\s+.*\s+-exec\s+rm',
            r'base64\s+-d',
            r'openssl\s+enc\s+-d',
            r'gpg\s+--decrypt',
            r'cryptsetup',
            r'encfs',
        ]
    
    def _load_ransomware_keywords(self) -> List[str]:
        """Palavras-chave relacionadas a ransomware e ferramentas maliciosas."""
        return [
            'ransomware', 'lockbit', 'conti', 'revil', 'maze', 'ryuk',
            'wannacry', 'notpetya', 'gandcrab', 'sodinokibi', 'phobos',
            'cryptolocker', 'teslacrypt', 'cerber', 'locky', 'cryptowall',
            'mimikatz', 'cobalt', 'strike', 'empire', 'metasploit',
            'c2', 'command', 'control', 'beacon', 'payload', 'dropper',
            'keylogger', 'rat', 'trojan', 'backdoor', 'rootkit',
            'privilege', 'escalation', 'lateral', 'movement',
            'persistence', 'exfiltration', 'exfil', 'data', 'theft'
        ]
    
    def detect_ips(self, text: str) -> Set[str]:
        """Detecta endereços IP (IPv4 e IPv6)."""
        ips = set()
        
        # IPv4
        for match in self.patterns['ipv4'].finditer(text):
            ip = match.group(0)
            # Filtra IPs privados e locais comuns (mas mantém alguns para análise)
            if not self._is_common_local_ip(ip):
                ips.add(ip)
        
        # IPv6
        for match in self.patterns['ipv6'].finditer(text):
            ips.add(match.group(0))
        
        return ips
    
    def _is_common_local_ip(self, ip: str) -> bool:
        """Verifica se é um IP local comum (pode ser ignorado)."""
        local_patterns = [
            '127.0.0.1', '0.0.0.0', '255.255.255.255',
            '169.254.', '224.0.0.', '239.255.255.'
        ]
        return any(ip.startswith(pattern) for pattern in local_patterns)
    
    def detect_domains(self, text: str) -> Set[str]:
        """Detecta nomes de domínio."""
        domains = set()
        
        for match in self.patterns['domain'].finditer(text):
            domain = match.group(0).lower()
            # Filtra domínios comuns do sistema e falsos positivos
            if not self._is_common_domain(domain) and self._is_valid_domain(domain):
                domains.add(domain)
        
        return domains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Verifica se é um domínio válido (não é um nome de arquivo)."""
        # Remove domínios que são claramente nomes de arquivos
        file_extensions = ['.txt', '.sh', '.exe', '.bat', '.cmd', '.ps1', 
                          '.py', '.js', '.log', '.conf', '.config', '.ini',
                          '.json', '.xml', '.yaml', '.yml', '.html', '.sql']
        
        # Se termina com extensão de arquivo comum, provavelmente é um arquivo
        if any(domain.endswith(ext) for ext in file_extensions):
            return False
        
        # Domínios válidos geralmente têm pelo menos 2 partes separadas por ponto
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # Verifica se a última parte é uma TLD válida (pelo menos 2 caracteres)
        tld = parts[-1]
        if len(tld) < 2:
            return False
        
        # Filtra domínios muito curtos (provavelmente falsos positivos)
        if len(domain) < 4:
            return False
        
        return True
    
    def _is_common_domain(self, domain: str) -> bool:
        """Verifica se é um domínio comum do sistema."""
        common_domains = [
            'localhost', 'localdomain', 'example.com', 'example.org',
            'test.com', 'test.local', 'domain.local', 'corp.local',
            'microsoft.com', 'windows.com', 'google.com', 'github.com'
        ]
        return any(domain == d or domain.endswith('.' + d) for d in common_domains)
    
    def detect_urls(self, text: str) -> Set[str]:
        """Detecta URLs."""
        urls = set()
        
        for match in self.patterns['url'].finditer(text):
            url = match.group(0)
            urls.add(url)
        
        return urls
    
    def detect_commands(self, text: str) -> Set[str]:
        """Detecta comandos suspeitos."""
        commands = set()
        lines = text.split('\n')
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Verifica padrões de comandos suspeitos
            for pattern in self.suspicious_commands:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    # Extrai o comando completo (primeiros 200 caracteres)
                    cmd = line.strip()[:200]
                    if cmd:
                        commands.add(cmd)
            
            # Verifica por comandos que contêm URLs ou IPs
            if any(keyword in line_lower for keyword in ['wget', 'curl', 'nc', 'ncat']):
                if self.patterns['url'].search(line) or self.patterns['ipv4'].search(line):
                    cmd = line.strip()[:200]
                    if cmd:
                        commands.add(cmd)
        
        return commands
    
    def detect_passwords(self, text: str) -> Set[str]:
        """Detecta possíveis senhas em texto."""
        passwords = set()
        
        # Padrão: password=valor ou password: valor
        for match in self.patterns['password'].finditer(text):
            pwd = match.group(1)
            # Filtra valores muito comuns
            if pwd and len(pwd) >= 4 and pwd.lower() not in ['null', 'none', 'false', 'true']:
                passwords.add(pwd)
        
        # Procura por padrões comuns de senha em arquivos de configuração
        password_patterns = [
            r'["\']?password["\']?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
            r'["\']?passwd["\']?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
            r'["\']?pwd["\']?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
            r'["\']?secret["\']?\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?',
            r'["\']?token["\']?\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?',
        ]
        
        for pattern_str in password_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                pwd = match.group(1)
                if pwd and len(pwd) >= 6:
                    passwords.add(pwd)
        
        return passwords
    
    def detect_software(self, text: str) -> Set[str]:
        """Detecta menções a softwares e ferramentas."""
        software = set()
        text_lower = text.lower()
        
        # Verifica palavras-chave de ransomware
        for keyword in self.ransomware_keywords:
            if keyword in text_lower:
                software.add(keyword)
        
        # Procura por nomes de executáveis suspeitos
        executable_patterns = [
            r'\b([a-zA-Z0-9_-]+\.(exe|bat|cmd|ps1|sh|py|pl|vbs|js|jar))\b',
            r'\b([a-zA-Z0-9_-]+\.(dll|sys|drv))\b',
        ]
        
        for pattern_str in executable_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                exe = match.group(1).lower()
                # Filtra executáveis comuns do sistema
                if not self._is_common_executable(exe):
                    software.add(exe)
        
        return software
    
    def _is_common_executable(self, exe: str) -> bool:
        """Verifica se é um executável comum do sistema."""
        common_exes = [
            'cmd.exe', 'powershell.exe', 'explorer.exe', 'notepad.exe',
            'calc.exe', 'regedit.exe', 'taskmgr.exe', 'services.exe',
            'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
            'kernel32.dll', 'ntdll.dll', 'user32.dll', 'kernelbase.dll'
        ]
        return exe.lower() in common_exes
    
    def detect_all(self, text: str) -> Dict[str, Set]:
        """Detecta todos os tipos de IOCs no texto."""
        results = {}
        
        results['ips'] = self.detect_ips(text)
        results['domains'] = self.detect_domains(text)
        results['urls'] = self.detect_urls(text)
        results['commands'] = self.detect_commands(text)
        results['passwords'] = self.detect_passwords(text)
        results['software'] = self.detect_software(text)
        
        return results

