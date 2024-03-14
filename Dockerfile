FROM almalinux:9 as prod

ARG UID=1000
ARG GID=1000
RUN groupadd -g $GID alt && \
    useradd -ms /bin/bash -u $UID -g $GID alt && \
    usermod -aG wheel alt

COPY ./signnode.repo /etc/yum.repos.d/signnode.repo
RUN dnf upgrade -y && dnf install -y --enablerepo="signnode" \
        rpm-sign pinentry keyrings-filesystem ubu-keyring debian-keyring raspbian-keyring git && \
    dnf clean all

WORKDIR /sign-node
COPY requirements.txt requirements.txt
RUN python3 -m ensurepip && pip3 install -r requirements.txt && \
    rm requirements.txt

RUN chown alt:alt /sign-node
USER alt


FROM prod as devel

USER root
RUN printf '%s ALL=(ALL) NOPASSWD:ALL\n' alt wheel >> /etc/sudoers
RUN dnf install -y sudo strace procps-ng which && \
    dnf clean all

COPY requirements.* .
COPY requirements.devel.txt requirements.devel.txt
RUN pip3 install -r requirements.devel.txt && \
    rm requirements.*

USER alt