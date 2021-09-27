FROM almalinux:8

COPY ./signnode.repo /etc/yum.repos.d/signnode.repo
RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="powertools" --enablerepo="epel" --enablerepo="signnode" \
        python3 gcc gcc-c++ python3-devel python3-virtualenv cmake \
        python3-pycurl libicu libicu-devel python3-lxml git tree mlocate mc createrepo_c \
        python3-createrepo_c xmlsec1-openssl-devel cpio\
        kernel-rpm-macros python3-libmodulemd dpkg-dev mock debootstrap pbuilder apt apt-libs \
        python3-apt keyrings-filesystem ubu-keyring debian-keyring raspbian-keyring qemu-user-static pinentry && \
    dnf clean all

RUN curl https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o wait_for_it.sh && chmod +x wait_for_it.sh

WORKDIR /sign-node

COPY requirements.txt /sign-node/requirements.txt

RUN python3 -m venv --system-site-packages env
RUN /sign-node/env/bin/pip install --upgrade pip==21.1 && /sign-node/env/bin/pip install -r requirements.txt && /sign-node/env/bin/pip cache purge

COPY ./sign_node /sign-node/sign_node
COPY almalinux_sign_node.py /sign-node/almalinux_sign_node.py

CMD ["/sign-node/env/bin/python", "/sign-node/almalinux_sign_node.py"]
