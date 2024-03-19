FROM almalinux:9

COPY signnode.repo /etc/yum.repos.d/signnode.repo
RUN dnf upgrade -y && dnf install -y --enablerepo="buildsystem" \
        rpm-sign pinentry keyrings-filesystem ubu-keyring debian-keyring raspbian-keyring git && \
    dnf clean all

WORKDIR /sign-node
COPY requirements.* .
RUN python3 -m ensurepip && pip3 install -r requirements.devel.txt && rm requirements.*

ADD --chmod=755 https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /
