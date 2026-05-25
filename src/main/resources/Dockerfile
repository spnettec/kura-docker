# ============================================================
# Stage 1: Builder — extract .debs and run Docker-specific setup
# The 348MB of .deb files stay in this stage and are discarded.
# ============================================================
FROM alpine:latest AS builder

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# Copy ALL build context into builder (debs, scripts, configs)
COPY debs/ /tmp/debs/
COPY bin/ /usr/local/bin/
COPY docker-setup.sh /tmp/
COPY log4j/log4j.xml /tmp/log4j.xml
COPY snapshots/snapshot_0.xml /tmp/snapshot_0.xml

ENV KURA_DIR=/opt/eclipse/kura

RUN set -ex; \
    apk update && \
    apk add --no-cache openjdk21-jre bash shadow dpkg openssl gcompat && \
    \
    chmod a+x -R /usr/local/bin && \
    ln -s /bin/bash /usr/bin/bash && \
    \
    # Extract kura-core .deb (no postinst — systemd not available)
    dpkg -x /tmp/debs/kura-core.deb / && \
    for deb in kura-management-ui kura-wires kura-deployment; do \
        dpkg -x /tmp/debs/${deb}.deb / ; \
    done && \
    \
    # Consolidate: move sibling files into versioned dir, then symlink
    cp -a /opt/eclipse/kura/* /opt/eclipse/kura_*/ 2>/dev/null || true && \
    rm -rf /opt/eclipse/kura && \
    ln -snf /opt/eclipse/kura_* /opt/eclipse/kura && \
    \
    # Docker-specific setup: users, dirs, keystore, snapshot
    chmod +x /tmp/docker-setup.sh && /tmp/docker-setup.sh && \
    \
    # Override log4j (Console appender for docker logs) and snapshot
    cp /tmp/log4j.xml ${KURA_DIR}/log4j/log4j.xml && \
    cp /tmp/snapshot_0.xml ${KURA_DIR}/user/snapshots/snapshot_0.xml && \
    cp /tmp/snapshot_0.xml ${KURA_DIR}/.data/snapshot_0.xml && \
    \
    # Register siblings
    echo "management-ui" >> ${KURA_DIR}/framework/sibling-install-order && \
    echo "wires" >> ${KURA_DIR}/framework/sibling-install-order && \
    echo "deployment" >> ${KURA_DIR}/framework/sibling-install-order && \
    \
    # Configure fileinstall
    add-config-ini "felix.fileinstall.disableNio2=true" && \
    add-config-ini "felix.fileinstall.dir=/load" && \
    \
    # Cleanup temp files
    rm -rf /tmp/debs /tmp/docker-setup.sh /tmp/log4j.xml /tmp/snapshot_0.xml && \
    \
    # Permissions
    chmod -R go-rwx /opt/eclipse && \
    chmod a+rx /opt/eclipse && \
    find /opt/eclipse -type d | xargs chmod a+x && \
    install -m 0777 -d "${KURA_DIR}/data" && \
    mkdir -p ${KURA_DIR}/packages && \
    sed -i "s/\-printf '\%P.n'//g" /usr/local/bin/dp-install

# ============================================================
# Stage 2: Final — slim runtime image
# Only COPY --from=builder the installed files; .debs are discarded.
# ============================================================
FROM alpine:latest

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

ENV \
  KURA_DIR=/opt/eclipse/kura \
  LAUNCHER_VERSION="1.7.100" \
  KURA_CRYPTO_SECRET_KEY="kura-dev-key-005"

RUN set -ex; \
    apk update && \
    apk add --no-cache openjdk21-jre bash zip curl gcompat procps \
        unzip gzip tar dos2unix openssl net-tools which busybox-extras \
        bluez bluez-deprecated chrony eudev glib psmisc socat shadow dpkg && \
    \
    # Create kura users (must match builder stage UIDs for chown)
    useradd -M kura 2>/dev/null || true && \
    passwd -l kura 2>/dev/null || true && \
    useradd -r -M kurad 2>/dev/null || true && \
    passwd -l kurad 2>/dev/null || true && \
    \
    # sysconfig directory
    mkdir -p /etc/sysconfig

# Copy installed files from builder (NO .deb files!)
# --chown avoids a separate chown layer (which would duplicate 357MB in overlay FS)
COPY --from=builder --chown=kurad:kurad /opt/eclipse /opt/eclipse
COPY --from=builder /usr/local/bin /usr/local/bin

RUN set -ex; \
    chmod a+rx /usr/local/bin/* && \
    ln -sf /bin/bash /usr/bin/bash && \
    chmod a+rwx /var/log

EXPOSE 80 443

VOLUME ["/load"]

ENTRYPOINT ["/usr/local/bin/kura-entry-point"]
