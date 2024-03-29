FROM almalinux:9

COPY signnode.repo /etc/yum.repos.d/signnode.repo
RUN <<EOT bash
  set -ex
  dnf upgrade -y
  dnf install -y rpm-sign pinentry keyrings-filesystem ubu-keyring debian-keyring raspbian-keyring git
  dnf clean all
EOT

WORKDIR /sign-node
COPY requirements.* .
RUN <<EOT bash
  set -ex
  python3 -m ensurepip
  pip3 install -r requirements.devel.txt
  rm requirements.*
EOT

ADD --chmod=755 https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /
