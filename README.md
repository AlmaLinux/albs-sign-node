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

# Reporting issues 

All issues should be reported to the [Build System project](https://github.com/AlmaLinux/build-system).
