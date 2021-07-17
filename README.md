# Usage

Current Docker image: `avtandilko/vault-switcher:v0.0.7`

## Environment variables

* `VAULT_ADDR`
* `VAULT_TOKEN_FILE`
* `VAULT_TOKEN`
* `VAULT_MOUNT_POINT`
* `VAULT_SOURCE_SECRET`
* `VAULT_DEST_SECRET`
* `VAULT_SECRET_TO_DELETE`
* `VARIABLES_LIST`

## Command-line argiments

```sh
usage: vault-switcher.py [-h] -a {clone-secret,clone-variables,delete-secret}

optional arguments:
  -h, --help            show this help message and exit
  -a {clone-secret,clone-variables,delete-secret}, --action {clone-secret,clone-variables,delete-secret}
```

## Examples

### Common variables. Should be set always

```sh
export VAULT_ADDR = "https://127.0.0.1:8200"
export VAULT_TOKEN_FILE = "/var/run/secrets/vault_token"
```

### Scenario: full secret copy

```sh
export VAULT_MOUNT_POINT = "secrets"
export VAULT_SOURCE_SECRET = "source_secret"
export VAULT_DEST_SECRET = "dest_secret"

vault-switcher.py -a clone-secret
```

### Scenario: specific variables copy

```sh
export VAULT_MOUNT_POINT = "secrets"
export VAULT_SOURCE_SECRET = "source_secret"
export VAULT_DEST_SECRET = "dest_secret"
export VARIABLES_LIST = '["VAR1", "VAR2", "VAR3"]'

vault-switcher.py -a clone-variables
```

### Scenario: delete secret

```sh
export VAULT_MOUNT_POINT = "secrets"
export VAULT_SECRET_TO_DELETE = "secret_to_delete"

vault-switcher.py -a delete-secret
```
