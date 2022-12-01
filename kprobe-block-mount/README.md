# block-mount

Block mounting of a block device having btrfs filesystem on it.

```bash
dd if=/dev/zero of=testfile.img bs=1M seek=1000 count=1
DEVICE=$(sudo losetup --show -f testfile.img)
sudo mkfs.btrfs -f $DEVICE
mkdir tmpmnt
mount $DEVICE tmpmnt
```

The mount should succeed with the ebpf program not running. It should fail with the following error with the eBPF program running.

```bash
mount: /tmpmnt: mount(2) system call failed: Cannot allocate memory.
```