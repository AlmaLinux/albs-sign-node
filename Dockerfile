FROM almalinux:9

COPY ./signnode.repo /etc/yum.repos.d/signnode.repo

RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="crb" --enablerepo="epel" --enablerepo="signnode" \
        rpm-sign python3 python3-devel python3-virtualenv git \
        python3-pycurl tree mlocate keyrings-filesystem pinentry \
        ubu-keyring debian-keyring raspbian-keyring && \
    dnf clean all

RUN curl https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o wait_for_it.sh && chmod +x wait_for_it.sh
RUN useradd -ms /bin/bash alt
RUN usermod -aG wheel alt
RUN echo 'alt ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN echo 'wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers


WORKDIR /sign-node

COPY requirements.txt /sign-node/requirements.txt

RUN python3 -m venv --system-site-packages env
RUN /sign-node/env/bin/pip install --upgrade pip==21.1 && /sign-node/env/bin/pip install -r requirements.txt && /sign-node/env/bin/pip cache purge

COPY ./sign_node /sign-node/sign_node
COPY almalinux_sign_node.py /sign-node/almalinux_sign_node.py

RUN chown -R alt:alt /sign-node /wait_for_it.sh /srv
USER alt

CMD ["/sign-node/env/bin/python", "/sign-node/almalinux_sign_node.py"]
