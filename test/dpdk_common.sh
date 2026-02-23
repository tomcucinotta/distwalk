DPDK_MODE="${DPDK_MODE:-}"
DPDK_IFACE=()
DPDK_MAC=()


dpdk_check_root() {
    if [ $(id -u) -ne 0 ]; then
        echo "DPDK tests require root privileges, run with sudo"
        exit 77
    fi
}

dpdk_check_binary() {
     if ! ldd ../src/dw_node_debug 2>/dev/null | grep -q "librte"; then
        echo "DPDK tests require USE_DPDK=1 build"
        exit 77
    fi
}

dpdk_find_pf() {
    for iface in /sys/class/net/*; do
        # /sys/class/net/*/device/driver is a link to /sys/bus/pci/drivers/driver/<iface_driver>
        local driver=$(basename "$(readlink -f $iface/device/driver 2>/dev/null)" 2>/dev/null)
        local name=$(basename $iface)

        # check if the driver is DPDK compatible
        case "$driver" in i40e|ice|ixgbe|mlx5_core)
            local pci=$(basename "$(readlink -f $iface/device)")
            local totalvfs=$(cat /sys/bus/pci/devices/$pci/sriov_totalvfs 2>/dev/null)

            # check if the PF supports SRIOV virtualization
            if [ -n "$totalvfs" ] && [ "$totalvfs" -gt 0 ]; then
                local state=$(cat /sys/class/net/$name/operstate 2>/dev/null)

                # making sure the PF is down
                if [ "$state" != "up" ]; then
                    echo "$pci $name"
                    return 0
                fi
            fi
        ;;esac
    done
    return 1
}

dpdk_auto_setup() {
    local n=${1:-4}
    local output

    if [ "$DPDK_MODE" = "vf" ]; then
        pf_info=$(dpdk_find_pf) || { echo "No DPDK-compatible PF found"; exit 77; }
    elif [ "$DPDK_MODE" != "veth" ]; then
        pf_info=$(dpdk_find_pf) && DPDK_MODE="vf" || DPDK_MODE="veth"
    fi

    if [ "$DPDK_MODE" = "vf" ]; then
        local pf_pci=$(echo "$pf_info" | cut -d' ' -f1)
        local pf_iface=$(echo "$pf_info" | cut -d' ' -f2)
        echo "Using VF backend: $pf_iface ($pf_pci), creating $n VFs"
        output=$(bash dpdk_vf_setup.sh "$n" "$pf_pci" "$pf_iface")
    else
        DPDK_MODE="veth"
        echo "Using veth backend ($n pairs)"
        output=$(bash dpdk_veth_setup.sh "$n")
    fi

    local i=0
    while read -r iface mac; do
        DPDK_IFACE[$i]="$iface"
        DPDK_MAC[$i]="$mac"
        i=$((i + 1))
    done <<< "$output"

}

dpdk_auto_teardown() {
    kill_all SIGKILL 2>/dev/null || true
    if [ "$DPDK_MODE" = "vf" ]; then
        bash dpdk_vf_destroy.sh
    elif [ "$DPDK_MODE" = "veth" ]; then
        bash dpdk_veth_destroy.sh
    fi
}