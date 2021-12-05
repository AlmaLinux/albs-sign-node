FROM almalinux:8

COPY ./signnode.repo /etc/yum.repos.d/signnode.repo
RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="powertools" --enablerepo="epel" --enablerepo="signnode" \
        python3 python3-devel python3-virtualenv \
        python3-pycurl git tree mlocate keyrings-filesystem \
        ubu-keyring debian-keyring raspbian-keyring && \
    dnf clean all

RUN curl https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o wait_for_it.sh && chmod +x wait_for_it.sh

WORKDIR /sign-node

COPY requirements.txt /sign-node/requirements.txt

RUN python3 -m venv --system-site-packages env
RUN /sign-node/env/bin/pip install --upgrade pip==21.1 && /sign-node/env/bin/pip install -r requirements.txt && /sign-node/env/bin/pip cache purge

COPY ./sign_node /sign-node/sign_node
COPY almalinux_sign_node.py /sign-node/almalinux_sign_node.py

CMD ["/sign-node/env/bin/python", "/sign-node/almalinux_sign_node.py"]
