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

# Fetching GPG passphrases from Bitwarden

By default the sign node asks for each PGP key passphrase interactively at
startup (or uses `dev_pgp_key_password` in development mode). Instead, it can
fetch passphrases from a Bitwarden vault using
[py-bitwarden-wrapper](https://github.com/AlmaLinux/py-bitwarden-wrapper).

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

When `bitwarden_enabled` is true, fetched passphrases take precedence over the
development password and interactive prompts. Startup fails fast if any keyid
is missing from the vault or its passphrase does not unlock the GPG key.

`bitwarden-wrapper` is not published on PyPI — it is installed directly from
GitHub via `requirements.txt`.

# Reporting issues 

All issues should be reported to the [Build System project](https://github.com/AlmaLinux/build-system).
