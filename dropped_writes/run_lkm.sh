#!/bin/sh
# One-shot: boot alpine headlessly, wait for ssh, build+load the dropwrite LKM,
# build+run the LKM-driven Dirty-Pagetable exploit (lpe_lkm.c), then kill qemu.
#
# The stale PTE corrupts kernel page-table accounting, so the guest is expected
# to be unusable afterward -- that's why this boots a throwaway VM per attempt.
set -e

SSH_PORT=5555
SSHOPT="-o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p $SSH_PORT"
SCPOPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P $SSH_PORT"
HOST=root@localhost
MODDIR=dropwrite_mod

# Pre-flight: a stale VM (e.g. from a SIGKILLed run whose cleanup trap never
# fired) still holding the ssh-forward port would make our new qemu fail to bind
# it, and our ssh would silently connect to the OLD wedged VM instead -> a hang
# with no exploit output. Refuse to proceed until the port is actually free.
if ss -ltn 2>/dev/null | grep -q ":${SSH_PORT} "; then
	echo "[!] port ${SSH_PORT} already in use -- a stale VM is likely running."
	echo "    kill it first:  pkill -9 -f qemu-system-x86 ; then re-run."
	exit 1
fi

# fully headless: no graphics, no serial, no monitor.
# 512 MB / 2 CPUs: the grooming (PREFILL/FLUSH/spray budget in lpe_lkm.c) is
# tuned for this small guest so movable memory is easy to exhaust; the exploit
# also pins to CPU 1, so >=2 CPUs are required.
qemu-system-x86_64 -m 512 -smp 2 -accel kvm -cpu host \
	-hda alpine.qcow2 \
	-device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
	-display none -serial none -monitor none &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null; wait $QEMU_PID 2>/dev/null' EXIT

echo "[*] qemu pid $QEMU_PID, waiting for ssh..."
up=0
for i in $(seq 1 60); do
	if ssh $SSHOPT $HOST true 2>/dev/null; then up=1; break; fi
	sleep 1
done
[ "$up" = 1 ] || { echo "[!] ssh never came up"; exit 1; }
echo "[*] ssh up after ${i}s"

# ship + build the module and exploit
scp $SCPOPT "$MODDIR/dropwrite.c" "$MODDIR/Kbuild" lpe_lkm.c $HOST:/root/ >/dev/null
ssh $SSHOPT $HOST '
	set -e
	cd /root
	make -C /lib/modules/$(uname -r)/build M=/root modules >/tmp/build.log 2>&1 || { tail -20 /tmp/build.log; exit 1; }
	rmmod dropwrite 2>/dev/null || true
	insmod dropwrite.ko
	echo 0 > /proc/sys/kernel/kptr_restrict
	gcc -O2 -Wall -o lpe_lkm lpe_lkm.c
'

echo "[*] running exploit (60s host-side timeout)..."
set +e
# Host-side timeout is the real bound: the stale PTE wedges the exploit in
# uninterruptible kernel state on exit, so a guest-side `timeout` can't reap it
# and the ssh would otherwise hang. NO pty (-tt): a pty buffers the exploit's
# output and drops it when timeout kills ssh; piped stdout (exploit runs
# unbuffered) is flushed line-by-line and survives the kill.
# 60s: the grooming spray can take tens of seconds before it wins/exhausts.
timeout -k 2 60 ssh $SSHOPT $HOST '/root/lpe_lkm'
rc=$?
[ $rc -ge 124 ] && echo "[*] exploit wedged on teardown (expected); ssh timed out (rc=$rc)"
echo "[*] done (rc=$rc); killing qemu"
