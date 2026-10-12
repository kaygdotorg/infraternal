# Disposable target tooling for #169; no production host or identity is used.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus libpam-systemd openssh-server sudo zsh fish bash \
    tmux screen iproute2 procps python3 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd -m -u 1101 -s /bin/bash target \
    && passwd -d target \
    && printf 'target ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/target \
    && chmod 440 /etc/sudoers.d/target
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
