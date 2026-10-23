# Reproduce the qualified default archive mtime without changing global UTS_VERSION.
# Metadata is recovered from the qualified .linux.initramfs newc headers.
usr/initramfs_data.cpio: export KBUILD_BUILD_TIMESTAMP := @1792710700
