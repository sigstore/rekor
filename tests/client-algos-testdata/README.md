# How to recreate files in this directory

## RSA

```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl dgst -sha256 -sign rsa_private.pem -out file1.rsa.sig file1
openssl dgst -sha512 -sign rsa_private.pem -out file2.rsa.sig file2
```

## ECDSA

```bash
openssl ecparam -name secp256k1 -genkey -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
openssl dgst -sha256 -sign ec_private.pem -out file1.ec.sig file1
openssl dgst -sha512 -sign ec_private.pem -out file2.ec.sig file2
```

## ED25519/ED25519-PH

```bash
openssl genpkey -algorithm ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem
```

## ED25519 signature

```bash
openssl pkeyutl -sign -inkey ed25519_private.pem  -rawin -in file1 -out file1.ed25519.sig
```

## ED25519-PH signature

```bash
openssl pkeyutl -sign -inkey ed25519_private.pem  -rawin -in file1 -pkeyopt instance:ed25519ph -out file1.ed25519ph.sig
```
