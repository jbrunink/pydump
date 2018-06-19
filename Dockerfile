FROM python:3-stretch
ENV DEBIAN_FRONTEND noninteractive
ENV DOCKER_BUILD 1
WORKDIR /usr/src/app

RUN echo "force-unsafe-io" > /etc/dpkg/dpkg.cfg.d/02apt-speedup \
    && echo "Acquire::http {No-Cache=True;};" > /etc/apt/apt.conf.d/no-cache \
    && apt-get -q update && apt-get -qy dist-upgrade \
    && pip3 install --upgrade pip \
    && apt-get -y autoremove \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY main.py credentials.json client_secret.json ./
RUN groupadd -g 1001 appuser && \
    useradd -r -u 1001 -g appuser appuser -d /usr/src/app
RUN chown appuser.appuser -R /usr/src/app
USER appuser
EXPOSE 8000
CMD [ "python", "-u", "main.py" ]
