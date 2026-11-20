import yaml

data = {
    'xss': [
        {'id': 'xss-script-tag', 'name': 'Script Tag Injection', 'pattern': r'(?i)<script[^>]*>.*?</script>', 'severity': 'high', 'description': 'Classic <script> tag injection'},
        {'id': 'xss-script-tag-open', 'name': 'Unclosed Script Tag', 'pattern': r'(?i)<script[^>]*>', 'severity': 'high', 'description': 'Unclosed script tag'},
        {'id': 'xss-onerror', 'name': 'onerror Event Handler', 'pattern': r'(?i)onerror\s*=', 'severity': 'high', 'description': 'Image/element onerror XSS vector'},
        {'id': 'xss-onload', 'name': 'onload Event Handler', 'pattern': r'(?i)onload\s*=', 'severity': 'high', 'description': 'Body/element onload XSS vector'},
        {'id': 'xss-javascript-protocol', 'name': 'JavaScript Protocol', 'pattern': r'(?i)javascript\s*:', 'severity': 'high', 'description': 'javascript: URI scheme'},
        {'id': 'xss-eval', 'name': 'eval() Injection', 'pattern': r'(?i)eval\s*\(', 'severity': 'medium', 'description': 'eval() code execution'},
        {'id': 'xss-alert', 'name': 'alert() Injection', 'pattern': r'(?i)alert\s*\(', 'severity': 'medium', 'description': 'alert() proof-of-concept'},
        {'id': 'xss-document-cookie', 'name': 'document.cookie Access', 'pattern': r'(?i)document\s*\.\s*cookie', 'severity': 'high', 'description': 'Cookie theft attempt'},
        {'id': 'xss-encoded-script', 'name': 'URL-Encoded Script Tag', 'pattern': '%3[Cc]script%3[Ee]', 'severity': 'high', 'description': '<script> URL-encoded'},
        {'id': 'xss-double-encoded', 'name': 'Double-Encoded Script', 'pattern': '%253[Cc]script%253[Ee]', 'severity': 'high', 'description': 'Double URL-encoded <script>'},
        {'id': 'xss-html-entity', 'name': 'HTML Entity Encoded', 'pattern': r'(&#x3[Cc];|&#6[01];).*?(&#x3[Ee];|&#62;)', 'severity': 'medium', 'description': 'HTML entity encoded tags'},
        {'id': 'xss-unicode', 'name': 'Unicode Escaped', 'pattern': r'(\\u003[cC]|\\u003[eE])', 'severity': 'medium', 'description': 'Unicode escaped angle brackets'},
    ],
    'sqli': [
        {'id': 'sqli-classic', 'name': 'Classic OR 1=1', 'pattern': r"(?i)'\s*(or|and)\s*'1'\s*=\s*'1", 'severity': 'high', 'description': 'Classic tautology injection'},
        {'id': 'sqli-union', 'name': 'UNION SELECT', 'pattern': r'(?i)union\s+(all\s+)?select', 'severity': 'high', 'description': 'UNION-based data exfiltration'},
        {'id': 'sqli-drop', 'name': 'DROP TABLE', 'pattern': r'(?i)drop\s+table', 'severity': 'critical', 'description': 'Destructive DDL injection'},
        {'id': 'sqli-comment', 'name': 'SQL Comment', 'pattern': r'(--|#|/\*)\s*$', 'severity': 'medium', 'description': 'Comment termination'},
        {'id': 'sqli-semicolon', 'name': 'Statement Terminator', 'pattern': ';--', 'severity': 'medium', 'description': 'Semicolon + comment'},
        {'id': 'sqli-sleep', 'name': 'Time-Based Blind (SLEEP)', 'pattern': r'(?i)(sleep|pg_sleep|waitfor\s+delay)\s*\(', 'severity': 'high', 'description': 'Time-based blind SQLi'},
        {'id': 'sqli-info-schema', 'name': 'Information Schema Query', 'pattern': r'(?i)information_schema', 'severity': 'medium', 'description': 'Schema enumeration'},
        {'id': 'sqli-generic', 'name': 'Generic SQLi Pattern', 'pattern': r"(?i)('|--|;)\s*(or|and|union|select|insert|update|delete|drop)\s", 'severity': 'medium', 'description': 'Generic SQL injection keywords'},
    ],
    'path_traversal': [
        {'id': 'path-trav-unix', 'name': 'Unix Path Traversal', 'pattern': r'(\.\./|\.\.%2f|\.\.%5c)', 'severity': 'high', 'description': '../ directory traversal'},
        {'id': 'path-trav-windows', 'name': 'Windows Path Traversal', 'pattern': r'(\.\.\\|\.\.%5c)', 'severity': 'high', 'description': '..\ directory traversal'},
        {'id': 'path-trav-encoded', 'name': 'Encoded Path Traversal', 'pattern': '%2e%2e%2f|%2e%2e%5c', 'severity': 'high', 'description': 'URL-encoded ../ or ..\\'},
        {'id': 'path-trav-etc-passwd', 'name': '/etc/passwd Access', 'pattern': r'(?i)/etc/passwd', 'severity': 'critical', 'description': 'Linux password file access'},
        {'id': 'path-trav-win-ini', 'name': 'Windows system.ini', 'pattern': r'(?i)windows[/]system32[/]drivers[/]etc[/]hosts', 'severity': 'high', 'description': 'Windows hosts file access'},
    ],
    'cmd_injection': [
        {'id': 'cmd-inject-semicolon', 'name': 'Command Separator (;)', 'pattern': r';\s*(ls|cat|id|whoami|pwd|uname|ps|netstat|ifconfig|ipconfig)', 'severity': 'critical', 'description': 'Command injection via semicolon'},
        {'id': 'cmd-inject-pipe', 'name': 'Pipe Injection', 'pattern': r'\|\s*(ls|cat|id|whoami|nc|ncat|wget|curl|bash|sh)', 'severity': 'critical', 'description': 'Command injection via pipe'},
        {'id': 'cmd-inject-backtick', 'name': 'Backtick Injection', 'pattern': r'`[^`]*(ls|cat|id|whoami|nc|wget|curl|bash)[^`]*`', 'severity': 'critical', 'description': 'Command substitution injection'},
        {'id': 'cmd-inject-dollar', 'name': 'Dollar Parenthesis', 'pattern': r'\$\([^)]*(ls|cat|id|whoami|nc|wget|curl|bash)[^)]*\)', 'severity': 'critical', 'description': '$() command substitution'},
    ],
    'network_scan': [
        {'id': 'syn-flood', 'name': 'SYN Flood / Port Scan', 'description': '>20 unique destination ports from same source in 5 seconds', 'threshold': {'unique_dst_ports': 20, 'time_window_seconds': 5}, 'severity': 'high'},
        {'id': 'port-sweep', 'name': 'Port Sweep (Horizontal Scan)', 'description': 'Same destination port across >50 unique destinations in 10 seconds', 'threshold': {'unique_dst_ips': 50, 'time_window_seconds': 10}, 'severity': 'high'},
        {'id': 'nmap-syn', 'name': 'NMAP SYN Scan Signature', 'description': 'SYN packets with no follow-up ACK, varying source ports', 'threshold': {'syn_without_ack_ratio': 0.8, 'min_packets': 10}, 'severity': 'medium'},
    ],
    'beaconing': [
        {'id': 'regular-beacon', 'name': 'Regular Interval Beaconing', 'description': 'Connections to same destination at consistent intervals (±10%)', 'threshold': {'min_connections': 6, 'interval_variance_pct': 10, 'time_window_minutes': 30}, 'severity': 'high'},
        {'id': 'dns-tunneling', 'name': 'DNS Tunneling', 'description': 'High volume of DNS queries to same domain, long subdomains', 'threshold': {'max_subdomain_len': 50, 'queries_per_minute': 30}, 'severity': 'high'},
    ],
    'tls': [
        {'id': 'tls-encrypted', 'name': 'TLS Encrypted Payload', 'description': 'TLS traffic - payload inspection not possible', 'action': 'flag_only', 'severity': 'info'},
    ],
}

with open('threat-detection/signatures.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print('Written successfully')