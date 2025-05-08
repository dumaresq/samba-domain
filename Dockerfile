FROM alpine:latest

RUN \
    apk add -U --upgrade --no-cache samba-dc \
    attr \
    openldap-clients \
    krb5 \
    supervisor \
    openvpn \
    iputils \
    ldb-tools \
    vim \
    curl \
    bind-tools \
    bash \
    openntpd \
    chrony \
    syslog-ng

VOLUME [ "/var/lib/samba", "/etc/samba/external" ]

ADD init.sh /init.sh
ADD domain.sh /domain.sh
RUN chmod 755 /init.sh /domain.sh
CMD /init.sh
