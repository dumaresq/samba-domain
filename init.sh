#!/bin/bash

set -e

appSetup () {

	# Set variables
	DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
	DOMAINPASS=${DOMAINPASS:-youshouldsetapassword^123}
	JOIN=${JOIN:-false}
	JOINSITE=${JOINSITE:-NONE}
	MULTISITE=${MULTISITE:-false}
	NOCOMPLEXITY=${NOCOMPLEXITY:-false}
	INSECURELDAP=${INSECURELDAP:-false}
	DNSFORWARDER=${DNSFORWARDER:-NONE}
	HOSTIP=${HOSTIP:-NONE}
	RPCPORTS=${RPCPORTS:-"49152-49172"}
	DOMAIN_DC=${DOMAIN_DC:-${DOMAIN_DC}}
	
	LDOMAIN=${DOMAIN,,}
	UDOMAIN=${DOMAIN^^}
	URDOMAIN=${UDOMAIN%%.*}

	# If multi-site, we need to connect to the VPN before joining the domain
	if [[ ${MULTISITE,,} == "true" ]]; then
		/usr/sbin/openvpn --config /docker.ovpn &
		VPNPID=$!
		echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
		sleep 30
	fi

	# Set host ip option
	if [[ "$HOSTIP" != "NONE" ]]; then
		HOSTIP_OPTION="--host-ip=$HOSTIP"
	else
		HOSTIP_OPTION=""
	fi

	# Set up samba
	mv /etc/krb5.conf /etc/krb5.conf.orig
	echo "[libdefaults]" > /etc/krb5.conf
	echo "    dns_lookup_realm = false" >> /etc/krb5.conf
	echo "    dns_lookup_kdc = true" >> /etc/krb5.conf
	echo "    default_realm = ${UDOMAIN}" >> /etc/krb5.conf
	# If the finished file isn't there, this is brand new, we're not just moving to a new container
	FIRSTRUN=false
	if [[ ! -f /etc/samba/external/smb.conf ]]; then
		FIRSTRUN=true
		mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
		if [[ ${JOIN,,} == "true" ]]; then
			if [[ ${JOINSITE} == "NONE" ]]; then
				samba-tool domain join ${LDOMAIN} DC -U"${URDOMAIN}\administrator" --password="${DOMAINPASS}" --dns-backend=SAMBA_INTERNAL
			else
				samba-tool domain join ${LDOMAIN} DC -U"${URDOMAIN}\administrator" --password="${DOMAINPASS}" --dns-backend=SAMBA_INTERNAL --site=${JOINSITE}
			fi
		else
			samba-tool domain provision --use-rfc2307 --domain=${URDOMAIN} --realm=${UDOMAIN} --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass=${DOMAINPASS} ${HOSTIP_OPTION}
			if [[ ${NOCOMPLEXITY,,} == "true" ]]; then
				samba-tool domain passwordsettings set --complexity=off
				samba-tool domain passwordsettings set --history-length=0
				samba-tool domain passwordsettings set --min-pwd-age=0
				samba-tool domain passwordsettings set --max-pwd-age=0
			fi
		fi
		sed -i "/\[global\]/a \
			\\\tidmap_ldb:use rfc2307 = yes\\n\
			wins support = yes\\n\
			template shell = /bin/bash\\n\
			template homedir = /home/%U\\n\
			idmap config ${URDOMAIN} : schema_mode = rfc2307\\n\
			idmap config ${URDOMAIN} : unix_nss_info = yes\\n\
			idmap config ${URDOMAIN} : backend = ad\\n\
			rpc server dynamic port range = ${RPCPORTS}\
			" /etc/samba/smb.conf
		sed -i "s/LOCALDC/${URDOMAIN}DC/g" /etc/samba/smb.conf
		if [[ $DNSFORWARDER != "NONE" ]]; then
			sed -i "/dns forwarder/d" /etc/samba/smb.conf
			sed -i "/\[global\]/a \
				\\\tdns forwarder = ${DNSFORWARDER}\
				" /etc/samba/smb.conf
		fi
		if [[ ${INSECURELDAP,,} == "true" ]]; then
			sed -i "/\[global\]/a \
				\\\tldap server require strong auth = no\
				" /etc/samba/smb.conf
		fi
		# Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
		cp -f /etc/samba/smb.conf /etc/samba/external/smb.conf
	else
		cp -f /etc/samba/external/smb.conf /etc/samba/smb.conf
	fi
        
	# Set up supervisor
	mkdir -p /etc/supervisor.d/
	echo "[supervisord]" > /etc/supervisor.d/samba.ini
	echo "nodaemon=true" >> /etc/supervisor.d/samba.ini
	echo "" >> /etc/supervisor.d/samba.ini
	echo "[program:syslog-ng]" >> /etc/supervisor.d/samba.ini
	echo "command=/usr/sbin/syslog-ng -F --cfgfile /etc/syslog-ng/syslog-ng.conf --control /var/lib/syslog-ng/syslog-ng.ctl --persist-file /var/lib/syslog-ng/syslog-ng.persist --pidfile /run/syslog-ng.pid" >> /etc/supervisor.d/samba.ini
	echo "[program:chrony]" >> /etc/supervisor.d/samba.ini
	echo "command=/usr/sbin/chronyd -n" >> /etc/supervisor.d/samba.ini
	echo "[program:samba]" >> /etc/supervisor.d/samba.ini
	echo "command=/usr/sbin/samba -i" >> /etc/supervisor.d/samba.ini
	if [[ ${MULTISITE,,} == "true" ]]; then
		if [[ -n $VPNPID ]]; then
			kill $VPNPID
		fi
		echo "" >> /etc/supervisor.d/samba.ini
		echo "[program:openvpn]" >> /etc/supervisor.d/samba.ini
		echo "command=/usr/sbin/openvpn --config /docker.ovpn" >> /etc/supervisor.d/samba.ini
	fi

	echo "ntpsigndsocket  /var/lib/samba/ntp_signd" >> /etc/chrony/chrony.conf
	echo "allow 0.0.0.0/0" >> /etc/chrony/chrony.conf

	appStart ${FIRSTRUN}
}

fixDomainUsersGroup () {
	GIDNUMBER=$(ldbedit -H /var/lib/samba/private/sam.ldb -e cat "samaccountname=domain users" | { grep ^gidNumber: || true; })
	if [ -z "${GIDNUMBER}" ]; then
		echo "dn: CN=Domain Users,CN=Users,${DOMAIN_DC}
changetype: modify
add: gidNumber
gidNumber: 3000000" | ldbmodify -H /var/lib/samba/private/sam.ldb
		net cache flush
	fi
}

setupSSH () {
	echo "dn: CN=sshPublicKey,CN=Schema,CN=Configuration,${DOMAIN_DC}
changetype: add
objectClass: top
objectClass: attributeSchema
attributeID: 1.3.6.1.4.1.24552.500.1.1.1.13
cn: sshPublicKey
name: sshPublicKey
lDAPDisplayName: sshPublicKey
description: MANDATORY: OpenSSH Public key
attributeSyntax: 2.5.5.10
oMSyntax: 4
isSingleValued: FALSE
objectCategory: CN=Attribute-Schema,CN=Schema,CN=Configuration,${DOMAIN_DC}
searchFlags: 8
schemaIDGUID:: cjDAZyEXzU+/akI0EGDW+g==" > /tmp/Sshpubkey.attr.ldif
	echo "dn: CN=ldapPublicKey,CN=Schema,CN=Configuration,${DOMAIN_DC}
changetype: add
objectClass: top
objectClass: classSchema
governsID: 1.3.6.1.4.1.24552.500.1.1.2.0
cn: ldapPublicKey
name: ldapPublicKey
description: MANDATORY: OpenSSH LPK objectclass
lDAPDisplayName: ldapPublicKey
subClassOf: top
objectClassCategory: 3
objectCategory: CN=Class-Schema,CN=Schema,CN=Configuration,${DOMAIN_DC}
defaultObjectCategory: CN=ldapPublicKey,CN=Schema,CN=Configuration,${DOMAIN_DC}
mayContain: sshPublicKey
schemaIDGUID:: +8nFQ43rpkWTOgbCCcSkqA==" > /tmp/Sshpubkey.class.ldif
	ldbadd -H /var/lib/samba/private/sam.ldb /var/lib/samba/private/sam.ldb /tmp/Sshpubkey.attr.ldif --option="dsdb:schema update allowed"=true
	ldbadd -H /var/lib/samba/private/sam.ldb /var/lib/samba/private/sam.ldb /tmp/Sshpubkey.class.ldif --option="dsdb:schema update allowed"=true
}

appStart () {
	/usr/bin/supervisord > /var/log/supervisor.log 2>&1 &
	if [ "${1}" = "true" ]; then
		echo "Sleeping 10 before checking on Domain Users of gid 3000000 and setting up sshPublicKey"
		sleep 10
		fixDomainUsersGroup
		setupSSH
	fi
	while [ ! -f /var/log/supervisor.log ]; do
		echo "Waiting for log files..."
		sleep 1
	done
	sleep 3
	tail -F /var/log/supervisor.log
}

appSetup

exit 0
