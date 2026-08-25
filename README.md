# System Overview

<picture>
  <img alt="Test Coverage" src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andrewlukoshko/fd471834348bb248a0881bc9ccfd45dd/raw/coverage-badge.json">
</picture>
<br/><br/>

AlmaLinux Build System Sing Node is designed to sign build packages.

Sign Node sends a request to the [Web-Server](https://github.com/AlmaLinux/albs-web-server) and receives back a task to sign packages. 
The process to fulfill the task:
* Sign Node downloads packages that belong to the build from the [Artifact Storage(PULP)](https://build.almalinux.org/pulp/content/builds/AlmaLinux-8-x86_64-22-br/);
* Sign Node uses the PGP key to sign each package. Sign Node checks the PGP key each time, that it was imported correctly by checking the config file and node keys. 
* Uploads a signed package back to the Artifact Storage(PULP).
* Sends the status to the Web-Server.

After the task is completed, a user will get a message `task is completed`. If there is no task for the Sign Node, a user will get a message `no task to be signed`.

Build System works with RPM packages, so to sign them python code emulates bash command `rpmsign`.


# Running docker-compose 

You can start the system using the Docker Compose tool.

Pre-requisites:
* `docker` and `docker-compose-plugin` tools are installed and set up;

To start the system, run the following command: `docker compose up -d`. To rebuild images after your local changes, just run `docker compose up -d --build`.

# Fetching GPG passphrases from a secret provider

By default the sign node asks for each PGP key passphrase interactively at
startup (or uses `dev_pgp_key_password` in development mode). Instead, it can
fetch them from Bitwarden or from HashiCorp Vault.

Only **one** provider may be enabled at a time — signing keys should have a
single unambiguous source of truth, so enabling both is a configuration error
rather than a fallback chain. Whichever provider is enabled takes precedence
over the development password and interactive prompts, and startup fails fast
if any keyid is missing from it or its passphrase does not unlock the GPG key.

## Bitwarden

Uses [py-bitwarden-wrapper](https://github.com/AlmaLinux/py-bitwarden-wrapper).

Requirements:
* The Bitwarden CLI (`bw`) must be installed and on `PATH`.
* For each keyid listed in `pgp_keys`, create a Bitwarden login item whose
  **name equals the keyid** and whose **password field** holds the passphrase.

Enable it in the node config (`sign_node.yml`):

```yaml
bitwarden_enabled: yes
bitwarden_username: signer@example.com
# Provide the master password via a file (preferred) ...
bitwarden_password_file: /run/secrets/bw_master
# ... or inline (less safe):
# bitwarden_password: "..."
# Optional: restrict the lookup to a single collection (real UUID only;
# omit to search the whole vault).
# bitwarden_collection_id: <uuid>
```

`bitwarden-wrapper` is not published on PyPI — it is installed directly from
GitHub via `requirements.txt`.

## HashiCorp Vault

Reads passphrases from a KV v2 store using
[hvac](https://github.com/hvac/hvac). For each keyid listed in `pgp_keys`,
create a secret at `<vault_mount>/<vault_path_prefix>/<keyid>` holding the
passphrase in the `passphrase` field:

```
vault kv put secret/albs/sign-keys/7C3955C2A345DA89 passphrase='...'
```

Enable it in the node config (`sign_node.yml`):

```yaml
vault_enabled: yes
vault_addr: https://vault.example.com:8200
vault_mount: secret               # KV v2 mount point
vault_path_prefix: albs/sign-keys
# Authenticate with a static token from a file (preferred) ...
vault_token_file: /run/secrets/vault_token
# ... or inline (less safe):
# vault_token: "..."
# ... or via AppRole:
# vault_role_id: <uuid>
# vault_secret_id_file: /run/secrets/vault_secret_id
# Optional: Vault Enterprise / HCP namespace and a custom CA bundle.
# vault_namespace: admin/albs
# vault_ca_cert: /etc/pki/vault-ca.pem
# Optional: read a different field, for an existing secret layout.
# vault_passphrase_field: passphrase
```

`VAULT_ADDR` and `VAULT_TOKEN` from the environment are used as a fallback when
the corresponding options are unset, so a host already running a Vault agent
needs no credentials in the config file.

Passphrases are read once at startup, so a short-lived token is sufficient and
no Vault session is renewed while the node runs.

# Reporting issues 

All issues should be reported to the [Build System project](https://github.com/AlmaLinux/build-system).
