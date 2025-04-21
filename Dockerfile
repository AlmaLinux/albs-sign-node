FROM almalinux/9-base:latest as sign-node

COPY signnode.repo /etc/yum.repos.d/signnode.repo
RUN <<EOT
  set -ex
  dnf upgrade -y
  dnf install -y rpm-sign pinentry keyrings-filesystem ubu-keyring debian-keyring raspbian-keyring git glibc-langpack-en
  dnf clean all
EOT

WORKDIR /sign-node
COPY requirements.txt .
RUN <<EOT
  set -ex
  python3 -m ensurepip
  pip3 install -r requirements.txt --user
  rm -rf requirements.txt ~/.cache/pip
EOT

ADD --chmod=755 https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /


FROM sign-node as sign-node-tests

COPY requirements-tests.txt .
RUN <<EOT
  set -ex
  pip3 install -r requirements-tests.txt
  rm -rf requirements-tests.txt ~/.cache/pip
EOT
