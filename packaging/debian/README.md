# Debian packaging skeleton

A minimal starting point for building a `.deb` of Heeler with
`dpkg-buildpackage` or `cargo-deb`. It is a skeleton: review and adapt
before publishing a package.

Files:

- `control` — package metadata;
- `heeler.postinst` — creates the `heeler` system user and installs the
  default configuration;
- `heeler.service` is taken from `../systemd/heeler.service`.

With [`cargo-deb`](https://crates.io/crates/cargo-deb) the equivalent
one-liner from the repository root is:

```sh
cargo deb -p heeler-server
```

after adding a `[package.metadata.deb]` section mirroring `control`.
