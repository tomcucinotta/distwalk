#!/bin/bash
# Creates the specified amount of VFs from a single PF
set -e

N=$1
PF_PCI=${2:-0000:04:00.0}
PF_IFACE=${3:-enp4s0f0np0}

echo $N > /sys/bus/pci/devices/$PF_PCI/sriov_numvfs
sleep 3

for i in $(seq 0 $((N - 1))); do
    vf_pci=$(basename "$(readlink /sys/bus/pci/devices/$PF_PCI/virtfn$i)")
    vf_iface=$(ls /sys/bus/pci/devices/$vf_pci/net/)
    mac=$(cat /sys/class/net/$vf_iface/address)
    dpdk-devbind.py -b vfio-pci $vf_pci
    echo "$vf_pci $mac"
done
