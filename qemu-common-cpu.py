#!/usr/bin/env python3

from pathlib import Path
import socket
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
import yaml

# from QEMU-CPU-MODELS(7)

QEMU_INTEL_CPU_MODELS = [
    ["ClearwaterForest"],
    ["SierraForest", "SierraForest-v2"],
    ["GraniteRapids", "GraniteRapids-v2"],
    ["Cascadelake-Server", "Cascadelake-Server-noTSX"],
    ["Skylake-Server", "Skylake-Server-IBRS", "Skylake-Server-noTSX-IBRS"],
    ["Skylake-Client", "Skylake-Client-IBRS", "Skylake-Client-noTSX-IBRS"],
    ["Broadwell", "Broadwell-IBRS", "Broadwell-noTSX", "Broadwell-noTSX-IBRS"],
    ["Haswell", "Haswell-IBRS", "Haswell-noTSX", "Haswell-noTSX-IBRS"],
    ["IvyBridge", "IvyBridge-IBRS"],
    ["SandyBridge", "SandyBridge-IBRS"],
    ["Westmere", "Westmere-IBRS"],
    ["Nehalem", "Nehalem-IBRS"],
    ["Penryn"],
    ["Conroe"],
]

QEMU_INTEL_CPU_FLAGS = [
    "pcid",
    "stibp",
    "ssbd",
    "pdpe1gb",
    "md-clear"
]

QEMU_INTEL_VULNS = yaml.safe_load('''
mds-no:
  control_file: /sys/devices/system/cpu/vulnerabilities/mds
  control_string: Not\\ affected
taa-no:
  control_file: /sys/devices/system/cpu/vulnerabilities/tsx_async_abort
  control_string: Not\\ affected
bhi-no:
  control_file: /sys/devices/system/cpu/vulnerabilities/spectre_v2
  control_string: BHI:\\ Not\\ affected
gds-no:
  control_file: /sys/devices/system/cpu/vulnerabilities/gather_data_sampling
  control_string: Not\\ affected
rfds-no:
  control_file: /sys/devices/system/cpu/vulnerabilities/reg_file_data_sampling
  control_string: Not\\ affected
''')

def make_qemu_test_cmd():
    qemu_test_cmd = [
        "qemu-system-x86_64",
        "-machine", "accel=kvm",
        "-nographic",
        "-nodefaults",
        "-boot", "c,reboot-timeout=1",
        "-no-reboot"
    ]

    return qemu_test_cmd

def make_ssh_cmd():
    cluster = get_cluster()
    ssh_cmd = [
        "/usr/bin/ssh",
        "-oHashKnownHosts=no",
        "-oGlobalKnownHostsFile=/var/lib/ganeti/known_hosts",
        "-oUserKnownHostsFile=/dev/null",
        "-oCheckHostIp=no",
        f"-oHostKeyAlias={cluster}",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes"
    ]

    return ssh_cmd

def init():
    master = Path("/var/lib/ganeti/ssconf_master_node").read_text().rstrip()
    this_host = socket.getfqdn()
    if master != this_host:
        sys.exit(f"this script should run on the master node {master}")

def get_cluster():
    cluster = Path("/var/lib/ganeti/ssconf_cluster_name").read_text().rstrip()

    return cluster

def get_nodes():
    all_nodes = Path("/var/lib/ganeti/ssconf_node_vm_capable").read_text().rstrip()
    nodes_vm_cap = []
    for n in all_nodes.split():
        name, _, vm_cap = n.partition("=")
        if vm_cap == "True":
            nodes_vm_cap.append(name)

    return nodes_vm_cap

def test_cpu(cpu):
    cmd = make_qemu_test_cmd()
    cmd.append("-cpu")
    cmd.append(f"{cpu},enforce")
    results = run_cluster_ssh(cmd)
    failed_nodes = []
    for node, ok, out in results:
        if not ok:
            failed_nodes.append(node.split(".")[0])

    return failed_nodes

def run_cluster_ssh(cmd):
    nodes = get_nodes()
    with ThreadPoolExecutor(max_workers=len(nodes)) as executor:
        results = list(executor.map(lambda n: run_ssh(node=n, test_cmd=cmd), nodes))

    return results

def run_ssh(node=None, test_cmd=None):
    ssh_cmd = make_ssh_cmd()
    cmd = ssh_cmd + [node] + test_cmd
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return (node, False, result.stderr.strip())

    return (node, True, result.stdout.strip())

def test_cpus(cpus):
    good_cpu = ""
    for cpu_model in cpus:
        for cpu_variant in cpu_model:
            failed_nodes = test_cpu(cpu_variant)
            if len(failed_nodes) > 0:
                print(f"bad CPU: {cpu_variant} on nodes {failed_nodes}")
            else:
                print(f"good CPU: {cpu_variant}")
                good_cpu = cpu_variant

    return good_cpu

def test_cpu_flags(flags):
    good_flags = []
    for flag in flags:
        cpu = f"{GOOD_CPU},{flag}"
        failed_nodes = test_cpu(cpu)
        if len(failed_nodes) > 0:
            print(f"bad CPU flag: {flag} on nodes {failed_nodes}")
        else:
            print(f"good CPU flag: {flag}")
            good_flags.append(flag)

    return good_flags

def test_vuln_flags(flags):
    good_flags = []
    for flag in flags.keys():
        failed_nodes = test_host_vuln(flags[flag])
        if len(failed_nodes) > 0:
            print(f"bad CPU flag: {flag} on nodes {failed_nodes}")
        else:
            print(f"good CPU flag: {flag}")
            good_flags.append(flag)

    return good_flags

def test_host_vuln(flag):
    cmd = [
        "grep", "-F",
        flag["control_string"],
        flag["control_file"]
    ]
    results = run_cluster_ssh(cmd)
    failed_nodes = []
    for node, ok, out in results:
        if not ok:
            failed_nodes.append(node.split(".")[0])

    return failed_nodes

# main
init()
GOOD_CPU = test_cpus(reversed(QEMU_INTEL_CPU_MODELS))
print(f"measured CPU type: {GOOD_CPU}")
CPU_FLAGS = ",".join(test_cpu_flags(QEMU_INTEL_CPU_FLAGS))
print(f"measured CPU type and flags: {GOOD_CPU},{CPU_FLAGS}")
VULN_FLAGS = ",".join(test_vuln_flags(QEMU_INTEL_VULNS))
print(f"measured CPU type, flags and vulns: {GOOD_CPU},{CPU_FLAGS},{VULN_FLAGS}")
KVM_CPU_TYPE=f"{GOOD_CPU},{CPU_FLAGS},{VULN_FLAGS}".replace(",","\\,")
print("Your common KVM cpu_type is: "
      f"gnt-cluster modify -H kvm:cpu_type=\'{KVM_CPU_TYPE}\\,enforce\'")
