# ============================================================
# Stage 1: Builder — extract .debs and run Docker-specific setup
# Debian inputs are mounted read-only without a large COPY cache layer.
# ============================================================
FROM alpine:latest AS builder

# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# Copy ALL build context into builder (debs, scripts, configs)
COPY bin/ /usr/local/bin/
COPY docker-setup.sh /tmp/
COPY log4j/log4j.xml /tmp/log4j.xml
COPY snapshots/snapshot_0.xml /tmp/snapshot_0.xml

ENV KURA_DIR=/opt/eclipse/kura
ARG TARGETARCH
ARG KURA_SKIP_DPS=false

RUN --mount=type=bind,source=.,target=/tmp/inputs,readonly set -eux; \
    apk add --no-cache openjdk21-jre bash shadow dpkg openssl gcompat python3; \
    \
    chmod a+x -R /usr/local/bin; \
    ln -s /bin/bash /usr/bin/bash; \
    \
    # The Debian inputs must match their package names and target ABI.
    case "$TARGETARCH" in arm64|amd64) ;; *) exit 1 ;; esac; \
    mkdir -p /usr/local/share/kura; \
    for name in kura-core kura-management-ui kura-deployment kura-wires; do \
        deb="/tmp/inputs/debs/$name.deb"; \
        test "$(dpkg-deb -f "$deb" Package)" = "$name"; \
        architecture="$(dpkg-deb -f "$deb" Architecture)"; \
        if [ "$name" = kura-core ]; then \
            test "$architecture" = "$TARGETARCH"; \
        else \
            test "$architecture" = all || test "$architecture" = "$TARGETARCH"; \
        fi; \
        printf '%s\t%s\t%s\t%s\n' "$name" "$(dpkg-deb -f "$deb" Version)" "$architecture" \
            "$(sha256sum "$deb" | cut -d ' ' -f 1)" >> /usr/local/share/kura/package-inputs.tsv; \
        dpkg-deb -x "$deb" /; \
    done; \
    \
    # Consolidate: move sibling files into versioned dir, then symlink
    set -- /opt/eclipse/kura_*_linux; \
    test "$#" = 1; test -d "$1"; test ! -L "$1"; \
    test -d "$KURA_DIR"; test ! -L "$KURA_DIR"; \
    cp -a "$KURA_DIR/." "$1/"; \
    rm -rf "$KURA_DIR"; \
    ln -s "$1" "$KURA_DIR"; \
    \
    # Docker-specific setup: users, directories and initial snapshot
    chmod +x /tmp/docker-setup.sh; /tmp/docker-setup.sh; \
    \
    # Override log4j (Console appender for docker logs) and snapshot
    cp /tmp/log4j.xml "${KURA_DIR}/log4j/log4j.xml"; \
    cp /tmp/snapshot_0.xml "${KURA_DIR}/user/snapshots/snapshot_0.xml"; \
    cp /tmp/snapshot_0.xml "${KURA_DIR}/.data/snapshot_0.xml"; \
    \
    # Register siblings
    printf '%s\n' management-ui deployment wires >> "${KURA_DIR}/framework/sibling-install-order"; \
    \
    # Install YOFC .dp deployment packages
    case "$KURA_SKIP_DPS" in \
        true) ;; \
        false) \
            set -- /tmp/inputs/dps/*.dp; \
            test -f "$1"; \
            install -m 0755 -d "${KURA_DIR}/kura/packages" "${KURA_DIR}/packages"; \
            for dp; do \
                cp "$dp" "${KURA_DIR}/kura/packages/"; \
                dp-register "${KURA_DIR}/kura/packages/$(basename "$dp")"; \
            done ;; \
        *) exit 1 ;; \
    esac; \
    \
    # Configure fileinstall
    add-config-ini "felix.fileinstall.disableNio2=true"; \
    add-config-ini "felix.fileinstall.dir=/load"; \
    \
    # Cleanup temp files + Docker-unneeded bundles (no USB/udev in container)
    rm -f /tmp/docker-setup.sh /tmp/log4j.xml /tmp/snapshot_0.xml; \
    rm -f "${KURA_DIR}"/plugins/*/org.eclipse.kura.linux.usb*.jar; \
    \
    # Permissions
    chmod -R go-rwx /opt/eclipse; \
    chmod a+rx /opt/eclipse; \
    find /opt/eclipse -type d -exec chmod a+x {} +; \
    for tree in bin framework log4j plugins share siblings; do \
        chmod -R a+rX "${KURA_DIR}/$tree"; \
    done; \
    if [ -d "${KURA_DIR}/kura/packages" ]; then chmod -R a+rX "${KURA_DIR}/kura"; fi; \
    install -m 0700 -d "${KURA_DIR}/data"; \
    mkdir -p "${KURA_DIR}/packages"; \
    sed -i "s/\-printf '\%P.n'//g" /usr/local/bin/dp-install; \
    python3 -I /usr/local/bin/kura-container-bootstrap.py inventory

# ============================================================
# Stage 2: Final — slim runtime image
# Only COPY --from=builder the installed files; .debs are discarded.
# ============================================================
FROM alpine:latest

ARG KURA_APK_MIRROR=mirrors.aliyun.com

ENV \
  KURA_DIR=/opt/eclipse/kura \
  PERSISTENT_DIR=/var/lib/kura \
  TZ=Asia/Shanghai

RUN set -eux; \
    case "$KURA_APK_MIRROR" in ""|*[!a-zA-Z0-9.-]*) exit 1 ;; esac; \
    sed -i "s|dl-cdn.alpinelinux.org|$KURA_APK_MIRROR|g" /etc/apk/repositories; \
    apk add --no-cache openjdk21-jre bash zip curl gcompat procps \
        unzip gzip tar dos2unix openssl net-tools which busybox-extras \
        chrony eudev glib psmisc socat shadow dpkg \
        tzdata python3 py3-cryptography setpriv; \
    useradd -M kura; passwd -l kura; \
    groupadd -g 122 kurad; useradd -r -M -u 122 -g kurad kurad; passwd -l kurad; \
    \
    # sysconfig directory
    mkdir -p /etc/sysconfig; \
    install -d -m 0700 -o kurad -g kurad /var/log/kura

# Copy installed files from builder (NO .deb files!)
# Keep package ownership. The privileged bootstrap only loads paired Root code.
COPY --from=builder /opt/eclipse /opt/eclipse
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/share/kura /usr/local/share/kura

RUN set -ex; \
    chmod a+rx /usr/local/bin/*; \
    ln -sf /bin/bash /usr/bin/bash

EXPOSE 80 443

VOLUME ["/load", "/var/lib/kura"]

ENTRYPOINT ["/usr/bin/python3", "-I", "-B", "/usr/local/bin/kura-container-bootstrap.py", "run"]
