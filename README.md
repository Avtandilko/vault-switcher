# Usage

Current Docker image: `avtandilko/vault-switcher:v0.0.4`

Environment variables:

* `VAULT_ADDR`
* `VAULT_TOKEN_FILE`
* `VAULT_TOKEN`
* `VAULT_MOUNT_POINT`
* `VAULT_SOURCE_PATH`
* `VAULT_DEST_PATH`
* `DUPLICATE_FULL_SECRET`
* `DUPLICATE_VARIABLES_LIST`
* `VARIABLES_LIST`

## Examples

### Common variables. Should be set always

```sh
export VAULT_ADDR = "https://127.0.0.1:8200"
export VAULT_TOKEN_FILE = "/var/run/secrets/vault_token"
export VAULT_MOUNT_POINT = "secrets"
export VAULT_SOURCE_PATH = "source"
export VAULT_DEST_PATH = "dest"
```

### Scenario: full secret copy

```sh
export DUPLICATE_FULL_SECRET = "True"
```

### Scenario: specific variables copy

```sh
export DUPLICATE_VARIABLES = "True"
export VARIABLES_LIST = '["VAR1", "VAR2", "VAR3"]'
```
