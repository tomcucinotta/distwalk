#!/bin/bash
#set -x

if ! command -v yq &> /dev/null
then
	echo "yq not found; install with 'sudo snap install yq' (Make sure /snap/bin is in env!!!)" >&2
    exit
fi

if ! command -v jq &> /dev/null
then
    echo "jq not found; install with 'sudo apt install jq'" >&2
    exit
fi

if [ -z "$1" ]; then
    echo "Run with '$0 <new-name> '" >&2
    exit 1
fi

yq e "(select(.kind == \"Pod\").spec.containers[0].name = \"$1\" | 
       .metadata.name = \"$1\" | 
       .metadata.labels.app = \"$1\" |
       select(.kind == \"Service\").spec.selector.app = \"$1\")" -i dw_node_with_storage.yaml

#sed -i s/dw-node/dw-node-1/g dw_node.yaml
