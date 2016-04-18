sudo ip addr add 10.0.21.1/24 dev toto0;
sudo ifconfig toto0 up;
sudo sysctl net.ipv4.ip_forward=1;
sudo route add -net 192.168.67.0 netmask 255.255.255.0 dev toto0;
