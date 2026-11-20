import yaml

# Read current signatures
with open('threat-detection/signatures.yaml', 'r') as f:
    data = yaml.safe_load(f)

# Add missing xss signatures
data['xss'].extend([
    {'id': 'xss-script-tag-open', 'name': 'Unclosed Script Tag', 'pattern': r'(?i)<script[^>]*>', 'severity': 'high', 'description': 'Unclosed script tag'},
    {'id': 'xss-onload', 'name': 'onload Event Handler', 'pattern': r'(?i)onload\s*=', 'severity': 'high', 'description': 'Body/element onload XSS vector'},
    {'id': 'xss-eval', 'name': 'eval() Injection', 'pattern': r'(?i)eval\s*\(', 'severity': 'medium', 'description': 'eval() code execution'},
    {'id': 'xss-alert', 'name': 'alert() Injection', 'pattern': r'(?i)alert\s*\(', 'severity': 'medium', 'description': 'alert() proof-of-concept'},
    {'id': 'xss-document-cookie', 'name': 'document.cookie Access', 'pattern': r'(?i)document\s*\.\s*cookie', 'severity': 'high', 'description': 'Cookie theft attempt'},
    {'id': 'xss-double-encoded', 'name': 'Double-Encoded Script', 'pattern': '%253[Cc]script%253[Ee]', 'severity': 'high', 'description': 'Double URL-encoded <script>'},
    {'id': 'xss-html-entity', 'name': 'HTML Entity Encoded', 'pattern': r'(&#x3[Cc];|&#6[01];).*?(&#x3[Ee];|&#62;)', 'severity': 'medium', 'description': 'HTML entity encoded tags'},
    {'id': 'xss-unicode', 'name': 'Unicode Escaped', 'pattern': r'(\\u003[cC]|\\u003[eE])', 'severity': 'medium', 'description': 'Unicode escaped angle brackets'},
])

# Add missing sqli signatures
data['sqli'].extend([
    {'id': 'sqli-comment', 'name': 'SQL Comment', 'pattern': r'(--|#|/\*)\s*$', 'severity': 'medium', 'description': 'Comment termination'},
    {'id': 'sqli-semicolon', 'name': 'Statement Terminator', 'pattern': ';--', 'severity': 'medium', 'description': 'Semicolon + comment'},
    {'id': 'sqli-sleep', 'name': 'Time-Based Blind (SLEEP)', 'pattern': r'(?i)(sleep|pg_sleep|waitfor\s+delay)\s*\(', 'severity': 'high', 'description': 'Time-based blind SQLi'},
    {'id': 'sqli-info-schema', 'name': 'Information Schema Query', 'pattern': r'(?i)information_schema', 'severity': 'medium', 'description': 'Schema enumeration'},
    {'id': 'sqli-generic', 'name': 'Generic SQLi Pattern', 'pattern': r"(?i)('|--|;)\s*(or|and|union|select|insert|update|delete|drop)\s", 'severity': 'medium', 'description': 'Generic SQL injection keywords'},
])

# Add missing path_traversal signatures
data['path_traversal'].extend([
    {'id': 'path-trav-windows', 'name': 'Windows Path Traversal', 'pattern': r'(\.\.\\\\|\.\.%5c)', 'severity': 'high', 'description': '..\\ directory traversal'},
    {'id': 'path-trav-encoded', 'name': 'Encoded Path Traversal', 'pattern': '%2e%2e%2f|%2e%2e%5c', 'severity': 'high', 'description': 'URL-encoded ../ or ..\\'},
    {'id': 'path-trav-win-ini', 'name': 'Windows system.ini', 'pattern': r'(?i)windows[/]system32[/]drivers[/]etc[/]hosts', 'severity': 'high', 'description': 'Windows hosts file access'},
])

# Add missing cmd_injection signatures
data['cmd_injection'].extend([
    {'id': 'cmd-inject-pipe', 'name': 'Pipe Injection', 'pattern': r'\|\s*(ls|cat|id|whoami|nc|ncat|wget|curl|bash|sh)', 'severity': 'critical', 'description': 'Command injection via pipe'},
    {'id': 'cmd-inject-backtick', 'name': 'Backtick Injection', 'pattern': r'`[^`]*(ls|cat|id|whoami|nc|wget|curl|bash)[^`]*`', 'severity': 'critical', 'description': 'Command substitution injection'},
    {'id': 'cmd-inject-dollar', 'name': 'Dollar Parenthesis', 'pattern': r'\$\([^)]*(ls|cat|id|whoami|nc|wget|curl|bash)[^)]*\)', 'severity': 'critical', 'description': '$() command substitution'},
])

# Add missing network_scan signatures
data['network_scan'].extend([
    {'id': 'port-sweep', 'name': 'Port Sweep (Horizontal Scan)', 'description': 'Same destination port across >50 unique destinations in 10 seconds', 'threshold': {'unique_dst_ips': 50, 'time_window_seconds': 10}, 'severity': 'high'},
    {'id': 'nmap-syn', 'name': 'NMAP SYN Scan Signature', 'description': 'SYN packets with no follow-up ACK, varying source ports', 'threshold': {'syn_without_ack_ratio': 0.8, 'min_packets': 10}, 'severity': 'medium'},
])

# Add missing beaconing signatures
data['beaconing'].extend([
    {'id': 'dns-tunneling', 'name': 'DNS Tunneling', 'description': 'High volume of DNS queries to same domain, long subdomains', 'threshold': {'max_subdomain_len': 50, 'queries_per_minute': 30}, 'severity': 'high'},
])

# Write back
with open('threat-detection/signatures.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print('Updated successfully')