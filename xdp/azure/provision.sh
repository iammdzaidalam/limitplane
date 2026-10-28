#!/usr/bin/env bash
# Creates the resource group, VNet, NSG and two Ubuntu VMs. Safe to rerun: existing resources are kept.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=common.sh
source ./common.sh
need_az

[[ -f $SSH_KEY ]] || ssh-keygen -q -t ed25519 -N '' -C limitplane-xdp -f "$SSH_KEY"
my_ip=$(curl -fsS https://api.ipify.org) || die "could not find this machine's public IP"

exists() { az "$@" -o none 2>/dev/null; }

echo "resource group $RG in $LOCATION"
az group create -n "$RG" -l "$LOCATION" -o none

exists network nsg show -g "$RG" -n "$NSG" || az network nsg create -g "$RG" -n "$NSG" -o none
# SSH from this machine only; rerunning updates the rule if the IP changed. VNet traffic is allowed by default rules.
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n ssh-from-operator --priority 100 \
	--direction Inbound --access Allow --protocol Tcp --source-address-prefixes "$my_ip/32" \
	--destination-port-ranges 22 -o none

exists network vnet show -g "$RG" -n "$VNET" ||
	az network vnet create -g "$RG" -n "$VNET" --address-prefixes 10.42.0.0/16 \
		--subnet-name "$SUBNET" --subnet-prefixes 10.42.0.0/24 --network-security-group "$NSG" -o none

# accel SIZE prints true if the size supports accelerated networking in this region.
accel() {
	local v
	v=$(az vm list-skus -l "$LOCATION" --size "$1" --resource-type virtualMachines \
		--query "[?name=='$1'] | [0].capabilities[?name=='AcceleratedNetworkingEnabled'].value | [0]" -o tsv)
	[[ $v == True ]] && echo true || echo false
}

# vm NAME SIZE PRIVATE_IP
vm() {
	local name=$1 size=$2 ip=$3 an
	an=$(accel "$size")
	echo "$name: $size, private $ip, accelerated networking $an"
	exists network public-ip show -g "$RG" -n "$name-pip" ||
		az network public-ip create -g "$RG" -n "$name-pip" --sku Standard -o none
	exists network nic show -g "$RG" -n "$name-nic" ||
		az network nic create -g "$RG" -n "$name-nic" --vnet-name "$VNET" --subnet "$SUBNET" \
			--private-ip-address "$ip" --public-ip-address "$name-pip" --accelerated-networking "$an" -o none
	exists vm show -g "$RG" -n "$name" ||
		az vm create -g "$RG" -n "$name" --size "$size" --image "$IMAGE" --nics "$name-nic" \
			--admin-username "$ADMIN" --ssh-key-values "$SSH_KEY.pub" \
			--os-disk-size-gb 30 --storage-sku StandardSSD_LRS -o none
}

vm "$TARGET" "$TARGET_SIZE" "$TARGET_IP"
vm "$ATTACKER" "$ATTACKER_SIZE" "$ATTACKER_IP"

# The flood gets its own source IP so the probe (the attacker's primary IP) stays a separate, well-behaved client.
exists network nic ip-config show -g "$RG" --nic-name "$ATTACKER-nic" -n flood ||
	az network nic ip-config create -g "$RG" --nic-name "$ATTACKER-nic" -n flood --private-ip-address "$FLOOD_IP" -o none

for name in "$TARGET" "$ATTACKER"; do
	printf '%s public IP: %s\n' "$name" "$(az network public-ip show -g "$RG" -n "$name-pip" --query ipAddress -o tsv)"
done
echo "next: ./run-test.sh, then ./teardown.sh"
