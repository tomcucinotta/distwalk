#!/bin/bash
# Deletes the previously created VFs

PF_PCI=${1:-0000:04:00.0}

cur_vfs=$(cat /sys/bus/pci/devices/$PF_PCI/sriov_numvfs 2>/dev/null || echo 0)
for i in $(seq 0 $((cur_vfs - 1))); do
    vf_pci=$(basename "$(readlink /sys/bus/pci/devices/$PF_PCI/virtfn$i 2>/dev/null)" 2>/dev/null)
    [ -n "$vf_pci" ] && dpdk-devbind.py -u "$vf_pci" 2>/dev/null || true
done

echo 0 > /sys/bus/pci/devices/$PF_PCI/sriov_numvfs 2>/dev/null || true
