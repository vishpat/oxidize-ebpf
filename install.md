## VM

```
vagrant up
```

## Provision

```
vagrant ssh 
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
sudo apt-get install -y libssl-dev
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bindgen
cargo install bpf-linker
cargo install cargo-generate
cargo install cargo-xtask
```
