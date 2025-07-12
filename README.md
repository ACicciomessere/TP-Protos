## Run:

### Run Server:
```bash
    $ make
    $ ./bin/socks5
```

### Run Client:
```bash
    $ make
    $ ./bin/client
```

# Casos de uso del TP:

### CURL:
```bash
        $ curl --socks5 127.0.0.1:1080 --proxy-user usuario:clave https://google.com
```

### NCAT:
```bash
        $ ncat --proxy 127.0.0.1:1080 --proxy-type socks5 --proxy-auth user:pass example.com 80
```


