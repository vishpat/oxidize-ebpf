# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
#sudo dnf -y --disablerepo '*' --enablerepo=extras swap centos-linux-repos centos-stream-repos
#sudo dnf -y distro-sync
#sudo dnf -y install bpftool clang-devel
#sudo dnf -y install openssl-devel
curl https://sh.rustup.rs -sSf | sh -s -- -y
#sudo dnf -y install cargo
#sudo dnf -y install screen
sudo apt-get install -y libssl-dev
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bindgen
cargo install bpf-linker
cargo install cargo-generate
cargo install cargo-xtask
SCRIPT


Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.disksize.size = '50GB'
  config.vm.provision "shell", inline: $script
end
