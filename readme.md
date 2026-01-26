## dependencies
```bash
uv add pandas
uv add jinja2
uv add python-dateutil

uv run report.py
```

## test connection
```bash
ansible -i inventory/dev.yaml gmkservers -m ping
```

## find all open sockets with ssl information
```bash
ansible-playbook -i inventory/dev.yaml playbook.yml -K
```

## find all open sockets with ssl information local
```bash
ansible-playbook -i inventory/dev.yaml playbook.yml --limit localhost -K
ansible-playbook -i inventory/dev.yaml playbook.yml --limit gmk.lan -K
```

## test tls_scan
```bash
python3 roles/sslscan/files/tls_scan.py <ip> <port> <inventory_hostname> <level>

python3 roles/sslscan/files/tls_scan.py 192.168.178.91 8448 gmk.lan 5

python3 roles/sslscan/files/tls_scan.py 192.168.178.91 2443 gmk.lan 5
```
