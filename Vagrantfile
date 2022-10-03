# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
git config --global user.email "vishpat@gmail.com"
git config --global user.name "Vishal Patil"
sudo apt-get install -y libssl-dev
sudo apt-get install -y clang
sudo apt install libclang-dev
sudo apt install libelf-dev
sudo apt install zlib1g
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
apt-get install -y libssl-dev
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bindgen
cargo install bpf-linker
cargo install cargo-generate
cargo install cargo-xtask
cargo install --git https://github.com/aya-rs/aya -- aya-tool

## Re-install if the kernel is upgraded. Required to generate correct vmlinux.rs

git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
SCRIPT


Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 2
  end
  config.disksize.size = '50GB'
  config.vm.provision "shell", inline: $script, privileged: false
end
