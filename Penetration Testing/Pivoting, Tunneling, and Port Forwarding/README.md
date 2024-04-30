
## Pivoting
![PivotingandTunnelingVisualized](https://github.com/kiro6/penetration-testing-notes/assets/57776872/b721b187-e810-4985-b4ce-9b25f0d72fb9)


Utilizing multiple hosts to cross network boundaries you would not usually have access to. This is more of a targeted objective. The goal here is to allow us to move deeper into a network by compromising targeted hosts or infrastructure.

## Tunneling
Tunneling is a technique used to encapsulate and transfer one type of network traffic through another network protocol or connection. It allows you to create a virtual "tunnel" within a network, enabling communication between two endpoints while appearing as regular traffic of the encapsulating protocol. 


## Ping Sweep
```shell
# msfconsole
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23          

# shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done    

# CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```
