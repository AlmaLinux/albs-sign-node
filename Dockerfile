FROM almalinux:9

COPY ./signnode.repo /etc/yum.repos.d/signnode.repo

RUN dnf install -y epel-release && \
    dnf upgrade -y && \
    dnf install -y --enablerepo="crb" --enablerepo="epel" --enablerepo="signnode" \
        rpm-sign python3 python3-devel python3-virtualenv git \
        glibc-langpack-en \
        python3-pycurl tree mlocate keyrings-filesystem pinentry \
        ubu-keyring debian-keyring raspbian-keyring strace procps-ng sudo && \
    dnf clean all

RUN curl https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o wait_for_it.sh && chmod +x wait_for_it.sh
RUN groupadd -g 1000 alt && \
    useradd -ms /bin/bash -u 1000 -g 1000 alt && \
    usermod -aG wheel alt && \
    echo 'alt ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    echo 'wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

WORKDIR /sign-node

COPY requirements.txt /sign-node/requirements.txt

RUN python3 -m venv --system-site-packages env
RUN cd /sign-node && source env/bin/activate && pip3 install --upgrade pip && pip3 install -r requirements.txt --no-cache-dir

RUN chown -R alt:alt /sign-node /wait_for_it.sh /srv
USER alt

CMD ["/bin/bash", "-c", "source env/bin/activate && pip3 install --upgrade pip && pip3 install -r requirements.txt --no-cache-dir && python3 almalinux_sign_node.py"]
