# cross-rs 0.2.6 → Ubuntu 20.04 base (GLIBC 2.31). The 0.2.5 base
# (Ubuntu 16.04 / GLIBC 2.23) started failing on 2026-05-16 after the
# `rust:stable` image rolled forward and `build-script-build` binaries
# now require GLIBC_2.28+.
FROM ghcr.io/cross-rs/armv7-unknown-linux-musleabihf:0.2.6 AS headers
FROM ghcr.io/cross-rs/arm-unknown-linux-musleabihf:0.2.6

COPY --from=headers /usr/include/linux /usr/local/arm-linux-musleabihf/include/linux
