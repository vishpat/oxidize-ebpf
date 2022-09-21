# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
sudo apt-get install -y libssl-dev
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
apt-get install -y libssl-dev
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bindgen
cargo install bpf-linker
cargo install cargo-generate
cargo install cargo-xtask
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
