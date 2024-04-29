## chisel
- [chisel](https://github.com/jpillora/chisel)

- Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH.
- Chisel can create a client-server tunnel connection in a firewall restricted environment.

### Setting Up & Using Chisel
```shell
$ go install github.com/jpillora/chisel@latest

# or

$ git clone https://github.com/jpillora/chisel.git
$ cd chisel
$ go build
## shrinking the size of the binary
$ go build -ldflags="-s -w"
```

### 
