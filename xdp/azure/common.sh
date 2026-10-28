# Shared settings for the Azure flood test. Override any of them from the environment.
# shellcheck shell=bash disable=SC2034
RG=${RG:-limitplane-xdp}
LOCATION=${LOCATION:-eastus}
TARGET_SIZE=${TARGET_SIZE:-Standard_D2s_v5}     # 2 vCPU: small enough that a flood visibly hurts
ATTACKER_SIZE=${ATTACKER_SIZE:-Standard_D4s_v5} # 4 vCPU: enough senders to outrun the target
ARCH=${ARCH:-amd64}                             # arm64 for Dpsv5/Dpsv6 sizes
IMAGE=${IMAGE:-Canonical:ubuntu-24_04-lts:server:latest}
ADMIN=${ADMIN:-azureuser}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/limitplane-xdp}
ADMIN_KEY=${ADMIN_KEY:-xdp-flood-test}

VNET=lp-vnet SUBNET=lp-subnet NSG=lp-nsg
TARGET=lp-target ATTACKER=lp-attacker
TARGET_IP=10.42.0.4   # gateway + limitplane-xdp
ATTACKER_IP=10.42.0.5 # the probe, i.e. a well-behaved client
FLOOD_IP=10.42.0.6    # second IP config on the attacker NIC, the flood source

die() {
	echo "error: $*" >&2
	exit 1
}

need_az() {
	command -v az >/dev/null || die "install the Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli"
	az account show -o none 2>/dev/null || die "run: az login"
}
