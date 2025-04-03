DistWalk leverages Ansible to simplify the automation and reproducibility of experiments.
Ansible is an open-source automation tool allowing users to define tasks in YAML-based playbooks, 
which can be executed on remote machines over SSH without requiring agent installation.

Example usage of Ansible with DistWalk:
```console
ansible-playbook -i <host-inventory.yaml> <ansible-playbook.yaml> --extra-vars "dw='<standard-dw-node-parameters>'" 
```
To correctly use and understand Ansible's role, please refer to `ansible/sample-dw-inventory.yaml`, `ansible/dw-setup.yaml` and `ansible/play-compute.yaml`.

Example of workflow:
1. Prepare hosts for DistWalk:
```console
ansible-playbook -i sample-dw-inventory.yaml dw-setup.yaml
```
**NOTE**: This setup step should be embedded within the playbook for the experiment (as shown in `ansible/play-dl.yaml`) for automation purposes.

2. Prepare hosts for experimental evaluation (i.e., block frequencies, isolate CPUs, etc. modify this script!)
```console
ansible-playbook -i sample-dw-inventory.yaml host-setup.yaml
```
**NOTE**: This setup step should be embedded within the playbook for the experiment (as shown in `ansible/play-dl.yaml`) for automation purposes.

3. Run experiment's playbook
```console
ansible-playbook -i sample-dw-inventory.yaml play-compute.yaml
```
**NOTE**: If you are planning to run simple workload, this step may be skipped and simply run through the command-line from a (network-reachable)
host.
