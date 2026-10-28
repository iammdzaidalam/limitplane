#!/usr/bin/env bash
# Deletes everything provision.sh created (the whole resource group). Safe to rerun.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=common.sh
source ./common.sh
need_az

if [[ $(az group exists -n "$RG") != true ]]; then
	echo "resource group $RG does not exist; nothing to do"
	exit 0
fi
echo "deleting resource group $RG (VMs, disks, NICs, IPs, VNet); this takes a few minutes"
az group delete -n "$RG" --yes ${NO_WAIT:+--no-wait}
echo "done; the SSH key $SSH_KEY is kept"
