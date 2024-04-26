




forward every request to `localhost:1234` in our machine to `localhost:3306` in the target machine 10.129.202.64
```shell
# Forwarding single Port
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

# Forwarding Multiple Ports
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```
