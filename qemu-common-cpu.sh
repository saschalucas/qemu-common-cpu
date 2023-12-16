#!/bin/bash

set -euo pipefail

log_info() {
  echo "${@}" 
}

log_fail() {
  log_info "${@}"
  exit 1
}

# init
[[ "$(whoami)" == "root" ]] || log_fail "this script is intended to run as root"
CLUSTER="$(</var/lib/ganeti/ssconf_cluster_name)"
MASTER="$(</var/lib/ganeti/ssconf_master_node)"
THIS_HOST="$(hostname -f)"
[[ "${THIS_HOST}" == "${MASTER}" ]] || log_fail "this script is intended to run on master node ${MASTER}"

DSH="$(which dsh || true)"
[[ -x "${DSH}" ]] || log_fail "this script uses dsh, please install on ${THIS_HOST}"
DSH="${DSH} -f /var/lib/ganeti/ssconf_node_list -r ssh -o "-oHashKnownHosts=no" -o "-oGlobalKnownHostsFile=/var/lib/ganeti/known_hosts" -o "-oUserKnownHostsFile=/dev/null" -o "-oCheckHostIp=no" -o "-oHostKeyAlias=${CLUSTER}" -o "-oBatchMode=yes" -o "-oStrictHostKeyChecking=yes" -M  -c --"
QEMU_CPU_TEST="1>/dev/null 2>&1 qemu-system-x86_64 -machine accel=kvm -nographic -nodefaults -boot c,reboot-timeout=1 -no-reboot"
# known qemu CPU types (Intel) in order of precedence (later are better)
CPU_CODENAMES="Nehalem-IBRS Westmere-IBRS SandyBridge-IBRS IvyBridge-IBRS Haswell-noTSX-IBRS Broadwell-noTSX-IBRS Skylake-Server-noTSX-IBRS Cascadelake-Server-noTSX Icelake-Server-noTSX"

#### main
# microcode is essential for CPU bugs
echo -n "checking for intel-microcode package: "
if ${DSH} dpkg-query -W intel-microcode 1>/dev/null 2>&1; then
  echo "good"
else
  log_fail "please install intel-microcode on all nodes, then reboot affected"
fi

# testing if the local qemu know the cpu type
CPU_TYPES=""
for p in ${CPU_CODENAMES}; do
  if qemu-system-x86_64 -cpu help | grep ^x86 | awk '{ print $2}' | grep -q "^${p}$"; then 
    CPU_TYPES="${CPU_TYPES} ${p}"
  fi
done
for cpu in ${CPU_TYPES}; do
  echo -n "testing the ${cpu} CPU: "
  if ${DSH} ${QEMU_CPU_TEST} -cpu "${cpu},enforce" ; then
    echo "good"
  else
    log_info "failed"
    break
  fi
  good_cpu="${cpu}"
done

# known to be good CPU-Flags
CPU_FLAGS="pcid stibp ssbd pdpe1gb md-clear"
good_cpu_flags=""
for flag in ${CPU_FLAGS}; do
  echo -n "testing ${good_cpu} with flag ${flag}: "
  if ${DSH} ${QEMU_CPU_TEST} -cpu "${good_cpu},+${flag},enforce"; then
    echo "good"
    good_cpu_flags="${good_cpu_flags},+${flag}"
  else
    log_info "failed"
  fi
done

log_info "your common cpu_type is: ${good_cpu}${good_cpu_flags},enforce"
