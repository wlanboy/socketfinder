
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