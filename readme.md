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
```

## test tls_scan
```bash
python3 roles/sslscan/files/tls_scan.py <ip> <port> <pid> <inventory_hostname>

python3 roles/sslscan/files/tls_scan.py 192.168.178.91 8448 0 gmk.lan
```
