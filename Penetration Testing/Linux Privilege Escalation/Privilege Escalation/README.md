## Path Abuse
we could replace a common binary such as ls with a malicious script such as a reverse shell.

```shell
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH
```
