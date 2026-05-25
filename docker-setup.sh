#!/bin/bash
#
# Docker-specific Kura setup script.
# Replaces the kura-core.deb postinst which relies on systemd (unavailable in Docker).
# Called by the Dockerfile after dpkg -x extracts the kura-core .deb files.
#

set -e

INSTALL_DIR=/opt/eclipse

echo "Running Docker-specific Kura setup..."

# ── Create kura users ──
# shadow package provides useradd/passwd on Alpine
useradd -M kura 2>/dev/null || true
passwd -l kura 2>/dev/null || true
useradd -r -M kurad 2>/dev/null || true
passwd -l kurad 2>/dev/null || true

# ── Create required directories ──
mkdir -p ${INSTALL_DIR}/kura/.data
mkdir -p ${INSTALL_DIR}/kura/data
mkdir -p ${INSTALL_DIR}/kura/log
mkdir -p ${INSTALL_DIR}/kura/siblings
mkdir -p ${INSTALL_DIR}/kura/framework

# ── Create empty sibling-install-order registry ──
# Sibling .debs register themselves here during their postinst.
# In Docker we extract without postinst, so the Dockerfile appends entries.
: > ${INSTALL_DIR}/kura/framework/sibling-install-order
chmod 664 ${INSTALL_DIR}/kura/framework/sibling-install-order

# ── Copy snapshot_0.xml ──
# Kura needs this as the initial configuration backup
if [ -f ${INSTALL_DIR}/kura/user/snapshots/snapshot_0.xml ]; then
    cp ${INSTALL_DIR}/kura/user/snapshots/snapshot_0.xml ${INSTALL_DIR}/kura/.data/snapshot_0.xml
fi

# ── Make scripts executable ──
chmod +x ${INSTALL_DIR}/kura/bin/*.sh

# ── Set up sysconfig directory ──
if [ ! -d /etc/sysconfig ]; then
    mkdir -p /etc/sysconfig
fi

# ── Generate HTTPS keystore ──
# Kura's embedded Jetty needs this for the HTTPS management UI
keytool -genkey -alias localhost -keyalg RSA -keysize 2048 \
    -keystore ${INSTALL_DIR}/kura/user/security/httpskeystore.ks \
    -deststoretype pkcs12 \
    -dname "CN=YOFC, OU=信息技术部, O=长飞光纤光缆股份有限公司, L=武汉, S=湖北, C=中国" \
    -ext ku=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign \
    -ext eku=serverAuth,clientAuth,codeSigning,timeStamping \
    -validity 1000 -storepass changeit -keypass changeit

# ── Set ownership ──
chown -R kurad:kurad /opt/eclipse 2>/dev/null || true

echo "Docker setup complete."
