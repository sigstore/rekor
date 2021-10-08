# Signing and Uploading Other Types

This documentation contains information on how to sign and upload data in different pluggable types.
The following are covered:
- [Minisign](#minisign)
- [SSH](#ssh)
- [PKIX/X509](#pkixx509)
- OpenPGP / GPG (TODO)
- RPM (TODO)
- TSR (TODO)
- [TUF](#tuf)

## Minisign

Create a keypair with something like:

```console
$ minisign -G
Please enter a password to protect the secret key.

Password:
Password (one more time):
Deriving a key from the password in order to encrypt the secret key... done

The secret key was saved as /Users/dlorenc/.minisign/minisign.key - Keep it secret!
The public key was saved as minisign.pub - That one can be public.

Files signed using this key pair can be verified with the following command:

minisign -Vm <file> -P RWSzQI7+S6M0c4yReOwcDZ2petL8pAZsrNfkdyqr0V7j/HGafpjdKZQm
```

Sign a file:

```console
$ minisign -S -m README.md
Password:
Deriving a key from the password and decrypting the secret key... done
```

Upload to rekor:

```console
$ rekor-cli upload --artifact README.md --signature README.md.minisig --pki-format=minisign --public-key=minisign.pub
Created entry at index 5895, available at: https://rekor.sigstore.dev/api/v1/log/entries/008bfbbaa8f473a0b17cba5f8078d2c08410bca55f01d2ec71860795ef823b36
```

Look at the entry with:

```console
$ ./rekor-cli get --uuid=008bfbbaa8f473a0b17cba5f8078d2c08410bca55f01d2ec71860795ef823b36
LogID: c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
Index: 5895
IntegratedTime: 2021-07-14T01:39:50Z
UUID: 008bfbbaa8f473a0b17cba5f8078d2c08410bca55f01d2ec71860795ef823b36
Body: {
  "RekordObj": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "3d80236772ca7c5405e398a4d685e715859260a8733070b86de7322e233c68d2"
      }
    },
    "signature": {
      "content": "dW50cnVzdGVkIGNvbW1lbnQ6ClJXU3pRSTcrUzZNMGMrNUcxbVZzcmw2dmgvYi91VjlxclJySWpxd21abDFKYjZhTGJ2U1NWUzdObDNvUmpVTUdHUWpLVlEyd2JnMnJxNDZxdDdPTHE3L1c3Z2liMlo5Rzh3az0=",
      "format": "minisign",
      "publicKey": {
        "content": "akpGNDdCd05uYWw2MHZ5a0JteXMxK1IzS3F2Ulh1UDhjWnArbU4wcGxDWT0="
      }
    }
  }
}
```

## SSH

Generate a keypair with:

```console
$ ssh-keygen -C test@rekor.dev -t ed25519 -f id_ed25519
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_ed25519.
Your public key has been saved in id_ed25519.pub.
The key fingerprint is:
SHA256:73u0etmm2h7BehcLbjrwXqXe193k5R5Uz0Lnl83nTt4 test@rekor.dev
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|              . o|
|           . . ==|
|        S   + +oO|
|        .. o.=.==|
|         oo.B+o=B|
|         .oB=+o+X|
|         .BO=o.oE|
+----[SHA256]-----+
```

Sign a file with:

```console
$ ssh-keygen -Y sign -n file -f id_ed25519 README.md
Enter passphrase:
Signing file README.md
Write signature to README.md.sig
```

Upload it to rekor with:

```console
$ rekor-cli upload --artifact README.md --signature README.md.sig --pki-format=ssh --public-key=id_ed25519.pub
Created entry at index 5896, available at: https://rekor.sigstore.dev/api/v1/log/entries/0e81b4d9299e2609e45b5c453a4c0e7820ac74e02c4935a8b830d104632fd2d
```

Look at the entry with:

```console
$ rekor-cli get --uuid=0e81b4d9299e2609e45b5c453a4c0e7820ac74e02c4935a8b830d104632fd2d1
LogID: c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
Index: 5896
IntegratedTime: 2021-07-14T01:45:06Z
UUID: 0e81b4d9299e2609e45b5c453a4c0e7820ac74e02c4935a8b830d104632fd2d1
Body: {
  "RekordObj": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "3d80236772ca7c5405e398a4d685e715859260a8733070b86de7322e233c68d2"
      }
    },
    "signature": {
      "content": "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWdqNnhOWHFWdFJQb2JOaHg5TXNnbQp4Q2lYMlo3VFh5QXcyRHZpN0k1Nzdia0FBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6CmMyZ3RaV1F5TlRVeE9RQUFBRUM1N2xCUGtjWlF2K2RDOG1HMEd4ajZoeUVXOUtPZVVtN21WdFVicURSTDdramoKS1pTakYxaVFVcWVpUVQ4Z2ZKbGVyZVhhUmVMamZoR2FUN0llRENrRQotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K",
      "format": "ssh",
      "publicKey": {
        "content": "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUkrc1RWNmxiVVQ2R3pZY2ZUTElKc1FvbDltZTAxOGdNTmc3NHV5T2UrMjUK"
      }
    }
  }
}
```

## PKIX/X509

Generate a keypair with:

```console
$ openssl ecparam -genkey -name prime256v1 > ec_private.pem
$ openssl ec -in ec_private.pem -pubout > ec_public.pem
read EC key
writing EC key
```

Sign the file with:

```console
$ openssl dgst -sha256 -sign ec_private.pem -out README.md.sig README.md
```

Upload it to rekor with:

```console
$ ./rekor-cli upload --artifact README.md --signature README.md.sig --pki-format=x509 --public-key=ec_public.pem
Created entry at index 5897, available at: https://rekor.sigstore.dev/api/v1/log/entries/31a51c1bc20da83b66b2f24899184b85dbf8261c2de8571479165619ad87cd5d
```

View the entry with:

```console
$ rekor-cli get --uuid=31a51c1bc20da83b66b2f24899184b85dbf8261c2de8571479165619ad87cd5d
LogID: c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
Index: 5897
IntegratedTime: 2021-07-14T01:49:54Z
UUID: 31a51c1bc20da83b66b2f24899184b85dbf8261c2de8571479165619ad87cd5d
Body: {
  "RekordObj": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "3d80236772ca7c5405e398a4d685e715859260a8733070b86de7322e233c68d2"
      }
    },
    "signature": {
      "content": "MEUCICwZpVU/3fnWSZkejA8R2j/t5futtl5Co3CDj7k6J6PwAiEA75Cn2txgpg/KjsOitSKsydL3D6cQIf7NQJtsmvsRTRQ=",
      "format": "x509",
      "publicKey": {
        "content": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFYzJKUkJZbS9OQVo5ZHhhUnNWV05mdTcxV3B5TAo2cGx4L1hsZnNVTlM2SmcrWEhEVmpsaVNBNHV2ZEQ4ZW5XdUhNdWQybS9WdEVQaDZYT0M3bjR0aCtnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
      }
    }
  }
}
```

## OpenPGP / GPG

TODO

## RPM

TODO

## Alpine

TODO

## RPM

TODO

## TSR

TODO

## TUF

Generate a TUF repository (for example, with the [Python reference implementation](https://pypi.org/project/tuf/) or [go-tuf](https://github.com/theupdateframework/go-tuf)).

With go-tuf:

```console
$ tuf init
$ tuf gen-key root
$ tuf gen-key targets
$ tuf gen-key snapshot
$ tuf gen-key timestamp
$ tuf add path/to/some/target.txt
$ tuf snapshot
$ tuf timestamp
$ tuf commit
```

You will find the signed metadata in your TUF `repository/` directory:

```console
$ tree .
.
├── keys
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
```

Upload any TUF manifest to rekor by using the `root.json` as a the public key:

```console
$ ./rekor-cli upload --artifact repository/timestamp.json --type tuf --public-key repository/root.json
Created entry at index 0, available at: https://rekor.sigstore.dev/api/v1/log/entries/6ed8fa5e9f0aa31b6cdfd2cc6877692f5afba52edd7ff5774eebfb22228e8847
```

View the entry with:

```console
$ rekor-cli get --uuid=31a51c1bc20da83b66b2f24899184b85dbf8261c2de8571479165619ad87cd5d
LogID: 5c4ceffb024e0d0b50bb9e03bc308ce83a76353f1003f8e57a21c51f74cc1e0e
Index: 0
IntegratedTime: 2021-08-13T19:17:33Z
UUID: 6ed8fa5e9f0aa31b6cdfd2cc6877692f5afba52edd7ff5774eebfb22228e8847
Body: {
  "TufObj": {
    "manifest": {
      "expires": "2021-12-18 13:28:12.99008 -0600 CST",
      "signed": {
        "content": [...]
      },
      "version": 1
    },
    "root": {
      "expires": "2021-12-18 13:28:12.99008 -0600 CST",
      "signed": {
        "content": [...]
      },
      "version": 1
    }
  }
}

```
