## Build Instructions

Build the docker container image.

`docker build -t packetsrv .`

Run the container

`docker run --cap-add=NET_RAW --cap-add=NET_ADMIN -e IFACE=wlan0 --network host --name packetsrv1 packetsrv:latest`

We provide packet capture capabilities to the container and set the network to host to be able to capture packets on the host machines network(this can be changed according to your preference). 

The interface is set as wlan0 (Wireless interface on host machine, change this if your interface name differs).