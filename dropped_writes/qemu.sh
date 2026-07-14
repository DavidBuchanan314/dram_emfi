#!/bin/sh

qemu-system-x86_64 -m 512 -smp 4 -accel kvm -cpu host -hda alpine.qcow2 -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -nographic -serial pipe:/dev/stdout -monitor none
