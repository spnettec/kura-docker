#!/bin/bash
#
# Docker-specific Kura setup script.
# Replaces the kura-core.deb postinst which relies on systemd (unavailable in Docker).
# Called by the Dockerfile after dpkg -x extracts the kura-core .deb files.
#

set -e
umask 077

INSTALL_DIR=/opt/eclipse

echo "Running Docker-specific Kura setup..."

# ── Create kura users ──
# shadow package provides useradd/passwd on Alpine
useradd -M kura
passwd -l kura
useradd -r -M kurad
passwd -l kurad

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

# HTTPS private keystores are generated at first runtime and retained in the volume.

echo "Docker setup complete."
