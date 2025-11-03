# Security Patch for CVE-2025-38627

**F2FS Filesystem Use-After-Free Vulnerability**

---

## Quick Reference

| Item | Details |
|------|---------|
| **CVE ID** | CVE-2025-38627 |
| **Severity** | HIGH (CVSS 7.8) |
| **Target Kernel** | linux-yocto 6.12.47 |
| **Backported From** | Linux mainline 6.13+ |
| **Patch File** | 0001-kernel-fix-CVE-2025-38627-F2FS-compression-UAF.patch |
| **Required Action** | Apply patch and rebuild kernel |
| **Reboot Required** | Yes |
| **Module Rebuild** | Required (ABI changed) |

---

## Vulnerability Summary

**Type:** Use-After-Free (UAF) in F2FS compression cleanup  
**Attack Vector:** Local - Low complexity, Low privileges  
**Impact:** Kernel crash, memory disclosure, potential privilege escalation  

**Root Cause:** Race condition when compressed file is deleted during decompression. The cleanup may access freed inode memory.

**Fix:** Cache `sbi` and `compress_algorithm` values at allocation to avoid accessing freed inode during cleanup.

---

## Package Contents

| File | Description |
|------|-------------|
| `0001-kernel-fix-CVE-2025-38627-F2FS-compression-UAF.patch` | Security patch (8.9 KB) |
| `CUSTOMER-README.md` | This document |

**Upstream References:**
- Mainline commit: `39868685c2a9` (Linux kernel 6.13+)
- Stable backport: `8fae5b6addd5` (Stable kernel 6.6.x, 6.12.x series)
- **Backported from:** Linux mainline 6.13+ to linux-yocto 6.12.47
- **Original merge date:** June 13, 2025

---

## Compatibility

| Type | Status | Impact |
|------|--------|--------|
| Source | ✅ Compatible | No API changes |
| Binary (ABI) | ❌ Incompatible | **All f2fs modules must be rebuilt** |
| Runtime | ✅ Compatible | No filesystem changes |

---

## Yocto/Poky Build Instructions

### Prerequisites
- Docker with crops/poky container
- 150 GB disk space
- Poky branch: walnascar

### Setup (One-Time)

```bash
# On host - create workspace
mkdir -p ~/yocto-build-5-2/{workspace,dl,sstate}

# Start container
docker run --rm -it --name=yocto-builder \
  -v "$HOME/yocto-build-5-2/workspace:/home/pokyuser/workspace" \
  -v "$HOME/yocto-build-5-2/dl:/home/pokyuser/dl" \
  -v "$HOME/yocto-build-5-2/sstate:/home/pokyuser/sstate" \
  -w "/home/pokyuser/workspace" \
  ghcr.io/crops/poky:debian-12

# Inside container - clone Poky
cd /home/pokyuser/workspace
git clone https://git.yoctoproject.org/poky -b walnascar
source poky/oe-init-build-env build

# Configure
echo 'DL_DIR = "/home/pokyuser/dl"' >> conf/local.conf
echo 'SSTATE_DIR = "/home/pokyuser/sstate"' >> conf/local.conf

# Create custom layer
cd /home/pokyuser/workspace
bitbake-layers create-layer ../meta-root
bitbake-layers add-layer ../meta-root
```

### Apply Patch

```bash
# Copy patch from host to workspace
cp 0001-kernel-fix-CVE-2025-38627-F2FS-compression-UAF.patch \
   ~/yocto-build-5-2/workspace/

# Inside container - add Upstream-Status header (required by Yocto)
cd /home/pokyuser/workspace
patchfile="0001-kernel-fix-CVE-2025-38627-F2FS-compression-UAF.patch"
sed -i '/^---$/i Upstream-Status: Backport [https://git.kernel.org/torvalds/linux.git/commit/?id=39868685c2a9]' "$patchfile"

# Modify kernel
source poky/oe-init-build-env build
devtool modify linux-yocto

# Apply patch
cd /home/pokyuser/workspace/build/workspace/sources/linux-yocto
patch -p1 < /home/pokyuser/workspace/$patchfile

# Commit
git add fs/f2fs/
git commit -s -m "kernel: fix CVE-2025-38627 - F2FS compression UAF

Upstream-Status: Backport
CVE: CVE-2025-38627
Severity: HIGH (CVSS 7.8)"

# Update recipe
cd /home/pokyuser/workspace/build
devtool update-recipe -a ../meta-root linux-yocto
```

### Build

```bash
# Clean and build kernel
cd /home/pokyuser/workspace
source poky/oe-init-build-env build
bitbake -c cleansstate linux-yocto
bitbake linux-yocto                    # Time: 30-60 minutes

# Build image
bitbake core-image-minimal             # Time: 20-40 minutes
```

### Test in QEMU

```bash
# Boot image
cd /home/pokyuser/workspace/build
runqemu qemux86-64 nographic slirp

# Inside QEMU (login as root)
uname -r                               # Verify 6.12.47
modprobe f2fs && lsmod | grep f2fs     # Check module
dmesg | grep -i "use-after-free"       # Should be empty

# Quick stress test (attempts to trigger race)
dd if=/dev/zero of=/tmp/test.img bs=1M count=100
mkfs.f2fs -f -O compression /tmp/test.img
mkdir /mnt/test
mount -t f2fs -o compress_algorithm=lzo /tmp/test.img /mnt/test

for i in {1..20}; do
    dd if=/dev/urandom of=/mnt/test/file$i bs=1M count=1 2>/dev/null
done

for i in {1..20}; do
    cat /mnt/test/file$i > /dev/null 2>&1 &
    rm /mnt/test/file$i 2>&1 &
done
wait

dmesg | grep -i "UAF\|bug\|oops"       # Should be empty
umount /mnt/test

# Exit
poweroff
```

---

## Verification Checklist

| Step | Command | Expected | Status |
|------|---------|----------|--------|
| Kernel version | `uname -r` | 6.12.47 | [ ] |
| No UAF errors | `dmesg \| grep -i "UAF\|use-after-free"` | Empty | [ ] |
| F2FS loads | `modprobe f2fs && lsmod \| grep f2fs` | Module shown | [ ] |
| System stable | `uptime` | Normal uptime | [ ] |

---

## Rollback

```bash
cd /home/pokyuser/workspace/build
devtool reset linux-yocto
bitbake -c cleansstate linux-yocto
bitbake core-image-minimal
```

---

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Patch fails | Verify kernel is exactly 6.12.47 |
| Build errors | Check logs: `dmesg` or bitbake log files |
| Boot failure | Select previous kernel from bootloader |
| Missing Upstream-Status (Yocto) | Add header with sed command shown above |

---

**Document Version:** 1.0 | **Date:** 2025-11-03

---

**END OF DOCUMENT**
