from docker.io/library/pypy:3.11-7.3.20-bookworm@sha256:ce037b0406b749c8d38fe30f72c90538ec71d7e430235c513ecda1ac2c6b03f6

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install -r requirements.txt
COPY . /usr/src/app

CMD /usr/src/app/start_buildbot.sh
