# HoneyBot-IoT — device machine image ("VM") for the real, restricted shell.
#
#   docker build -f vm/Dockerfile --build-arg DEVICE=smartlock -t honeybot/vm-smartlock:0.8 vm
#
# One image per emulated device (cctv | smartlock | sensor): a real BusyBox
# userland with that board's files, daemons and control tools. The sandbox
# service starts a fresh, throw-away container from it for every attacker
# session — no network, read-only root, size-limited tmpfs, CPU / memory /
# process limits — and removes it when the session ends.
FROM busybox:1.36-musl
ARG DEVICE
COPY rootfs/common/ /
COPY rootfs/${DEVICE}/ /
RUN test -f /etc/hb-device.conf \
 && mkdir -p /run/devctl /var/run /var/tmp /home/admin /root \
 && chmod 1777 /var/tmp \
 && chmod 600 /etc/shadow
LABEL org.honeybot.role="device-vm" org.honeybot.device="${DEVICE}"
# busybox init reads the device's /etc/inittab, so `ps` shows the board's daemons
CMD ["/bin/init"]
