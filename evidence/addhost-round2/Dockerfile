# Real Debian SSH/systemd fixture for round-two installation and removal (#87); AGPL-3.0-only.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv libpam-systemd openssh-server ca-certificates sudo zsh dbus && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/bash hosttest && mkdir -p /run/sshd && systemctl enable ssh && printf 'PasswordAuthentication yes\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/fixture.conf
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
