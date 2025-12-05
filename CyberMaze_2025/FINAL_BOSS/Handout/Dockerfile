# Minimal Ubuntu
FROM ubuntu:24.04

# Install Python
RUN apt-get update && apt-get install -y python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/app
WORKDIR /srv/app
COPY flag.txt /srv/app/flag.txt


COPY vuln /srv/app/run


COPY ld-2.39.so /srv/app/

RUN chmod +x /srv/app/ld-2.39.so

COPY libc.so.6 /srv/app/

#expose dynamic port

CMD ["/srv/app/run"]
