#!/bin/bash
# Run CrabEFI in QEMU with USB storage (xHCI)
#
# Usage: ./scripts/run-qemu-usb.sh [coreboot.rom] [disk.img]
#
# Prerequisites:
#   - Build coreboot with CrabEFI as payload
#   - Create test disk with ./scripts/create-test-disk.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default paths
COREBOOT_ROM="${1:-$HOME/src/coreboot/build/coreboot.rom}"
DISK_IMG="${2:-$PROJECT_DIR/test-disk.img}"

# Check for coreboot ROM
if [ ! -f "$COREBOOT_ROM" ]; then
    echo "Error: coreboot ROM not found: $COREBOOT_ROM"
    echo ""
    echo "Build coreboot with CrabEFI payload first."
    echo "See: ./scripts/run-qemu.sh for instructions"
    exit 1
fi

# Check for disk image
if [ ! -f "$DISK_IMG" ]; then
    echo "Error: Disk image not found: $DISK_IMG"
    echo ""
    echo "Create one with: sudo ./scripts/create-test-disk.sh"
    exit 1
fi

echo "=== CrabEFI QEMU Test (USB/xHCI) ==="
echo "coreboot ROM: $COREBOOT_ROM"
echo "Disk image:   $DISK_IMG"
echo ""
echo "Serial output will appear below. Press Ctrl+A X to exit QEMU."
echo "=========================================="
echo ""

# Run QEMU with Q35 machine (has xHCI support)
QEMU_ARGS=(
    -machine q35
    -bios "$COREBOOT_ROM"
    -m 512M
    -serial mon:stdio
    -nographic
    -no-reboot
)

# Add xHCI controller and USB mass storage device
QEMU_ARGS+=(
    -device qemu-xhci,id=xhci
    -drive "file=$DISK_IMG,if=none,id=usbdisk,format=raw"
    -device "usb-storage,drive=usbdisk,bus=xhci.0"
)

# Add debug options
QEMU_ARGS+=(
    -d guest_errors
)

# Use KVM if available
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo "[Using KVM acceleration]"
    QEMU_ARGS+=(-enable-kvm -cpu host)
else
    echo "[KVM not available, using software emulation]"
    QEMU_ARGS+=(-cpu qemu64)
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
