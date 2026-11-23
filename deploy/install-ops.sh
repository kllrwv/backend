#!/bin/sh
set -eu

cd /root/killerwave
install -d -o 0 -g 10001 -m 0750 ops-state
install -d -o 0 -g 10001 -m 0770 ops-state/inbox
install -m 0644 deploy/killerwave-ops.service deploy/killerwave-ops.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now killerwave-ops.timer
