# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-SCRIPT
sudo apt-get install -y libssl-dev
SCRIPT


Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 2
  end
  config.disksize.size = '50GB'
  config.vm.provision "shell", inline: $script
end
