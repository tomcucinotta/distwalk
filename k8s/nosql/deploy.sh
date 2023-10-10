#!/bin/bash

kubectl delete pod,svc dw-client dw-node-0 dw-node-1 dw-node-2 dw-node-3


./node_rename.sh dw-node-0
kubectl apply -f dw_node_with_storage.yaml

./node_rename.sh dw-node-1
kubectl apply -f dw_node_with_storage.yaml

./node_rename.sh dw-node-2
kubectl apply -f dw_node_with_storage.yaml

./node_rename.sh dw-node-3
kubectl apply -f dw_node_with_storage.yaml

kubectl apply -f dw_client.yaml
