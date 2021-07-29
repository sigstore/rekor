# Verify Rekor Binaries

> :notebook: We will refine this process over time to be more streamlined with a higher consensus threshold
   as well as an implementation of a [TUF](https://theupdateframework.io/) style policy. For now this is quite a
   multi step process. We will also deep dive a fair amount here, as its a good opporuntity to pull the covers aside
   and see how this all works.

Rekor releases are currently signed and verified using Fulcio OpenID connect based short lived signing certificates.

Rekor release signing artifacts are also stored within the public rekor instance.

Here we will show you how to verify a release, but also take the opportunity to dig down into sigstores
signing implementation and process.

## How to verify a release

Head over to the [release page](https://github.com/sigstore/rekor/releases) and select the correct release
for your systems architecture. Alongside downloading the main binary, also download the signature and signing
certificate from the same release.

For example, with binary `rekor-cli-linux-amd64`, also retrieve `rekor-cli-linux-amd64_cert.pem`
and `rekor-cli-linux-amd64_signature.sig`.

* `rekor-cli-linux-amd64`: The binary itself
* `rekor-cli-linux-amd64_cert.pem`: The signing cerificate. This is an X509 certificate signed by the sigstores
   root CA, with the email of a project maintainer embedded as a X509v3 Subject Alternative Name. This
   provides a guarantees that the binary was signed by the individual with access to that account. In turn
   this information is recorded into the transparency log, so that the account can be monitored for misuse
   or compromise.
* `rekor-cli-linux-amd64_signature.sig`: This is the signature generated as a result of the signing event.

#### Basic verify

With the above three files, wwe can now perform a rudimentary verification.

We grab the public key from the signing cert:

```
openssl x509 -pubkey -noout -in rekor-cli-linux-amd64_cert.pem > rekor-cli-linux-amd64_cert_public.pem
```

And then we verify


```
openssl dgst -sha256 -verify rekor-cli-linux-amd64_cert_public.pem -signature rekor-cli-linux-amd64_signature.sig rekor-cli-linux-amd64
Verified OK
```

#### Verify the certificate chain

However, how do we know we can trust that public key is from a maintainer at sigstore?

Let's look at mapping this to an identity..

First off all we should check the trust chain to sigstores Root CA

The root CA for fulcio is currently:

```
-----BEGIN CERTIFICATE-----
MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu
ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy
A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas
taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm
MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u
Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx
Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup
Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==
-----END CERTIFICATE-----
```

Save this locally to your machine as `fulcio-root.pem`

> :notebook: Note this situation that will change. We are looking at leveraging other trust stores for our Root CA
   consider this a temporary approach.

Let's now validate the cert chain:

```
openssl verify -verbose -no_check_time -CAfile fulcio-root.pem rekor-cli-linux-amd64_cert.pem

rekor-cli-linux-amd64_cert.pem: OK
```

> :notebook: Note we use `-no_check_time` as fulcio certificates are  (so always will be expired by design!)

#### Verify the signing identity

OK, so we have now verified the cert chain, lets look at the identity

```
openssl x509 -in rekor-cli-linux-amd64_cert.pem -noout -text |grep email
email:ctadeu@gmail.com
```

OK, so we can see that a fulcio generated certificate, with a chain to the root certificate
has the email identity of a sigstore maintainer, in this instance our own release manager the awesome Carlos.

If you really wanted to and our super paranoid, you could email Carlos and ask him to give you assurance
he is Carlos and he signed the release.

#### Verify the entry is in the transparency log

On the  [release page](https://github.com/sigstore/rekor/releases) you will see some URLs, these are the
rekor entries of the signing events.

This is the link for the binary and signing materials we have been working with in this guide

https://rekor.sigstore.dev/api/v1/log/entries/b6fdc91e6af5bdd8df133802b7966aa53c1e59365741ee56e287f11263e02c33

Let's dig into this;

```
curl -X GET "https://rekor.sigstore.dev/api/v1/log/entries/b6fdc91e6af5bdd8df133802b7966aa53c1e59365741ee56e287f11263e02c33"  | jq

{
  "b6fdc91e6af5bdd8df133802b7966aa53c1e59365741ee56e287f11263e02c33": {
    "attestation": {},
    "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJzcGVjIjp7ImRhdGEiOnsiaGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImNlOWE3YzgyZjMyMTk0OTk1ODg4NzU4Y2YxMDdlZjBjYzUyZTBiOGNkY2U3M2I0MjQwNjU4ZWU5ZTczNzgzY2IifX0sInNpZ25hdHVyZSI6eyJjb250ZW50IjoiTUdVQ01EM29LemdzR25QQWtKRVhlZ0RJc2RsaDRCRkNRYk02am5nNFN5M2F4WS8rMnRsSzk3b2UvQ2t4YWJUMVpYVXFDQUl4QUpEcSt6TGZSWlpFSkQ1RHZhS2hGRXUrSm0rakQ0VVhjM0NhWnAyTVNhamlyYWxtdGFsQTZmU0dDWGp3R2ZVek93PT0iLCJmb3JtYXQiOiJ4NTA5IiwicHVibGljS2V5Ijp7ImNvbnRlbnQiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VOcmFrTkRRV2hwWjBGM1NVSkJaMGxWUVUwckswZFlSRk41YlVOUFNXODJZbXhNTUc1RVpuZ3hiMjFuZDBObldVbExiMXBKZW1vd1JVRjNUWGNLUzJwRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5Va1YzUkhkWlJGWlJVVVJGZDJoNllWZGtlbVJIT1hsYVZFRmxSbmN3ZVFwTlZFRXpUV3BuZDA5RVRUTk9SRXBoUm5jd2VVMVVRVE5OYW1kM1QwUlZNMDVFUm1GTlFVRjNaR3BCVVVKblkzRm9hMnBQVUZGSlFrSm5WWEpuVVZGQkNrbG5UbWxCUVZKak1ETXJVVTR2VEhCck9HcHFVRlF3VG1WNWEwMXVjbTltTW5wWlVrSnhObTA1ZWk5VE1YaFJTemR1Wm5aaFUzZ3JSalVyVEV0d04zZ0tSMkV4YkhZMlNXTnZSWGR3VUhBMk1VZHNZbmQ1UzBWUVZXSkxkekpyWW5KeVJWcFBNbmhLVjNreGIwVkVVSEJZTWxKcWNUQllTMFJaY0VGNVppOW1Rd295WnpKalNuVnRhbWRuUlc1TlNVbENTWHBCVDBKblRsWklVVGhDUVdZNFJVSkJUVU5DTkVGM1JYZFpSRlpTTUd4Q1FYZDNRMmRaU1V0M1dVSkNVVlZJQ2tGM1RYZEVRVmxFVmxJd1ZFRlJTQzlDUVVsM1FVUkJaRUpuVGxaSVVUUkZSbWRSVlRSQlVEaHRUa0k0ZWpoU1pGSnlUVlZMWjFBMk1tMHhVRkVyZDNjS1NIZFpSRlpTTUdwQ1FtZDNSbTlCVlhsTlZXUkJSVWRoU2tOcmVWVlRWSEpFWVRWTE4xVnZSekFyZDNkbldUQkhRME56UjBGUlZVWkNkMFZDUWtsSFFRcE5TRFIzWmtGWlNVdDNXVUpDVVZWSVRVRkxSMk5IYURCa1NFRTJUSGs1ZDJOdGJESlpXRkpzV1RKRmRGa3lPWFZrUjFaMVpFTXdNazFFVG0xYVZHUnNDazU1TUhkTlJFRjNURlJKZVUxcVkzUlpiVmt6VGxNeGJVNUhXVEZhVkdkM1drUkpOVTVVVVhWak0xSjJZMjFHYmxwVE5XNWlNamx1WWtkV2FHTkhiSG9LVEcxT2RtSlRPV3BaVkUweVdWUkdiRTlVV1hsT1JFcHBUMWRhYWxscVJUQk9hVGxxV1ZNMWFtTnVVWGRJWjFsRVZsSXdVa0ZSU0M5Q1FsRjNSVzlGVVFwWk0xSm9Xa2RXTVZGSFpIUlpWMnh6VEcxT2RtSlVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVJVRTNUVEp3U3poUlVGUnJTR3MxYnpaMENtZG5hbXBaZGpCTFYxQlVhalJLVVRBd1UzUmpSMHhxYTFnM1NVMWlOQzlIZFhwWVJrUTRjelpET0VkM05tcHdNRUZxUVcxWGEySlJPVFZzTXpsblVHUUtSMnBqVWpCU1FVUmFUMGRZYjBOUFFVUndPRTVsU3poQkwyZEtkV2RuUjBaSU5IWllaMmwxT0RKc1FtNU1PRVpTYzA5alBRb3RMUzB0TFVWT1JDQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENnPT0ifX19LCJraW5kIjoicmVrb3JkIn0=",
    "integratedTime": 1627461494,
    "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    "logIndex": 25579,
    "verification": {
      "inclusionProof": {
        "hashes": [
          "779627efafc2601b0b5c4755d1aa27eb3cf8c1f034960ccc1038b9556b1d78bb",
          "892fffd41824856e3279fb815cdedd28fc76722985e508f6ffdf5af5684f0d84",
          "24259982c90f0e2e8a051c06f4cda83fb7f06c3e47b1307d5bc3e50a625b3dcb",
          "a5d5a5841e65786e0718db2f43d909ff92fbfa19bc90bc3187fc143e7af2eb29",
          "2cba9779511cd8c964ac59e4763ecd5257aa67695b20bfbc957341e326848b60",
          "b269aa60e284ce1f866f5c7abd9da16d8e29bf9ab069c66ce91cfe8d6a852458",
          "8af1c7cd9d0a691984963b643c572c560cee08fe38083e2013763df5131e63b3",
          "e86d56509d6b149df6bf2389e066a4b21516f5a13540b8ef52c790b8ed70efe2",
          "04cfd843e6ee05e78eee3229a1b547a4776a81e651888c09bdbfde866ac38d97",
          "339bd5b9f48f7ecf1116f0b0ec9f9eeb95b84f3d53f27b8081e56facbcd71548",
          "74c9aba66c2704b143e33c3ebc5f12a17be5bda8a8eba055bd471ed57a6fd0b4",
          "43a291f5a7301f1b18bbf76829435251a9189c477aa52633fef3f589e3d47446",
          "73b38c2b7d6eac887dc9f028500b67ede8655f136bc75354f8bfe94515327513",
          "4a33ede5d1c6be306c0362fbee2e9f692522327b4cae78165f810f7dcfaa8dd0"
        ],
        "logIndex": 25579,
        "rootHash": "9ecebec82edb290e54f8b45702b05b94efe1e2a7848d5b5aa2c4bbe188995ca2",
        "treeSize": 27024
      },
      "signedEntryTimestamp": "MEUCIHPlKC5Hh34bdjBrqk++9yuznsFOyolHsoulTTxjM+hGAiEA3MEf6d2zsxFJaiZsGCHIhN8Yvc+NZMmUolIBqUGCps0="
    }
  }
}
```

Woah, thats a lot of stuff, lets focus on the the body and decode it from base64

```
curl -X GET "https://rekor.sigstore.dev/api/v1/log/entries/b6fdc91e6af5bdd8df133802b7966aa53c1e59365741ee56e287f11263e02c33"  | jq -r '.[].body'| base64 -d | jq -r '.[]'

{
  "data": {
    "hash": {
      "algorithm": "sha256",
      "value": "ce9a7c82f32194995888758cf107ef0cc52e0b8cdce73b4240658ee9e73783cb"
    }
  },
  "signature": {
    "content": "MGUCMD3oKzgsGnPAkJEXegDIsdlh4BFCQbM6jng4Sy3axY/+2tlK97oe/CkxabT1ZXUqCAIxAJDq+zLfRZZEJD5DvaKhFEu+Jm+jD4UXc3CaZp2MSajiralmtalA6fSGCXjwGfUzOw==",
    "format": "x509",
    "publicKey": {
      "content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNrakNDQWhpZ0F3SUJBZ0lVQU0rK0dYRFN5bUNPSW82YmxMMG5EZngxb21nd0NnWUlLb1pJemowRUF3TXcKS2pFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweQpNVEEzTWpnd09ETTNOREphRncweU1UQTNNamd3T0RVM05ERmFNQUF3ZGpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBCklnTmlBQVJjMDMrUU4vTHBrOGpqUFQwTmV5a01ucm9mMnpZUkJxNm05ei9TMXhRSzduZnZhU3grRjUrTEtwN3gKR2ExbHY2SWNvRXdwUHA2MUdsYnd5S0VQVWJLdzJrYnJyRVpPMnhKV3kxb0VEUHBYMlJqcTBYS0RZcEF5Zi9mQwoyZzJjSnVtamdnRW5NSUlCSXpBT0JnTlZIUThCQWY4RUJBTUNCNEF3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVICkF3TXdEQVlEVlIwVEFRSC9CQUl3QURBZEJnTlZIUTRFRmdRVTRBUDhtTkI4ejhSZFJyTVVLZ1A2Mm0xUFErd3cKSHdZRFZSMGpCQmd3Rm9BVXlNVWRBRUdhSkNreVVTVHJEYTVLN1VvRzArd3dnWTBHQ0NzR0FRVUZCd0VCQklHQQpNSDR3ZkFZSUt3WUJCUVVITUFLR2NHaDBkSEE2THk5d2NtbDJZWFJsWTJFdFkyOXVkR1Z1ZEMwMk1ETm1aVGRsCk55MHdNREF3TFRJeU1qY3RZbVkzTlMxbU5HWTFaVGd3WkRJNU5UUXVjM1J2Y21GblpTNW5iMjluYkdWaGNHbHoKTG1OdmJTOWpZVE0yWVRGbE9UWXlOREppT1daallqRTBOaTlqWVM1amNuUXdIZ1lEVlIwUkFRSC9CQlF3RW9FUQpZM1JoWkdWMVFHZHRZV2xzTG1OdmJUQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqRUE3TTJwSzhRUFRrSGs1bzZ0CmdnampZdjBLV1BUajRKUTAwU3RjR0xqa1g3SU1iNC9HdXpYRkQ4czZDOEd3NmpwMEFqQW1Xa2JROTVsMzlnUGQKR2pjUjBSQURaT0dYb0NPQURwOE5lSzhBL2dKdWdnR0ZINHZYZ2l1ODJsQm5MOEZSc09jPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
    }
  }
}
```

Ok now you can see the digest of the artifact that was signed:

```
sha256sum rekor-cli-linux-amd64
ce9a7c82f32194995888758cf107ef0cc52e0b8cdce73b4240658ee9e73783cb  rekor-cli-linux-amd64
```

We can then also grab the signing certicate

```
echo LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNrakNDQWhpZ0F3SUJBZ0lVQU0rK0dYRFN5bUNPSW82YmxMMG5EZngxb21nd0NnWUlLb1pJemowRUF3TXcKS2pFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweQpNVEEzTWpnd09ETTNOREphRncweU1UQTNNamd3T0RVM05ERmFNQUF3ZGpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBCklnTmlBQVJjMDMrUU4vTHBrOGpqUFQwTmV5a01ucm9mMnpZUkJxNm05ei9TMXhRSzduZnZhU3grRjUrTEtwN3gKR2ExbHY2SWNvRXdwUHA2MUdsYnd5S0VQVWJLdzJrYnJyRVpPMnhKV3kxb0VEUHBYMlJqcTBYS0RZcEF5Zi9mQwoyZzJjSnVtamdnRW5NSUlCSXpBT0JnTlZIUThCQWY4RUJBTUNCNEF3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVICkF3TXdEQVlEVlIwVEFRSC9CQUl3QURBZEJnTlZIUTRFRmdRVTRBUDhtTkI4ejhSZFJyTVVLZ1A2Mm0xUFErd3cKSHdZRFZSMGpCQmd3Rm9BVXlNVWRBRUdhSkNreVVTVHJEYTVLN1VvRzArd3dnWTBHQ0NzR0FRVUZCd0VCQklHQQpNSDR3ZkFZSUt3WUJCUVVITUFLR2NHaDBkSEE2THk5d2NtbDJZWFJsWTJFdFkyOXVkR1Z1ZEMwMk1ETm1aVGRsCk55MHdNREF3TFRJeU1qY3RZbVkzTlMxbU5HWTFaVGd3WkRJNU5UUXVjM1J2Y21GblpTNW5iMjluYkdWaGNHbHoKTG1OdmJTOWpZVE0yWVRGbE9UWXlOREppT1daallqRTBOaTlqWVM1amNuUXdIZ1lEVlIwUkFRSC9CQlF3RW9FUQpZM1JoWkdWMVFHZHRZV2xzTG1OdmJUQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqRUE3TTJwSzhRUFRrSGs1bzZ0CmdnampZdjBLV1BUajRKUTAwU3RjR0xqa1g3SU1iNC9HdXpYRkQ4czZDOEd3NmpwMEFqQW1Xa2JROTVsMzlnUGQKR2pjUjBSQURaT0dYb0NPQURwOE5lSzhBL2dKdWdnR0ZINHZYZ2l1ODJsQm5MOEZSc09jPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==| base64 -d > tlog_signing_cert.pem```

Which is of course the same as our signing cert:

```
diff tlog_signing_cert.pem rekor-cli-linux-amd64_cert.pem 
```

And the signature..

```
echo MGUCMD3oKzgsGnPAkJEXegDIsdlh4BFCQbM6jng4Sy3axY/+2tlK97oe/CkxabT1ZXUqCAIxAJDq+zLfRZZEJD5DvaKhFEu+Jm+jD4UXc3CaZp2MSajiralmtalA6fSGCXjwGfUzOw== | base64 -d > tlog_signing_sig.sig

diff tlog_signing_sig.sig rekor-cli-linux-amd64_signature.sig 
```

So we can then do the same verification  (if you really wanted to):

```
openssl x509 -pubkey -noout -in tlog_signing_cert.pem > tlog_signing_cert_public.pem
openssl dgst -sha256 -verify tlog_signing_cert_public.pem -signature tlog_signing_sig.sig rekor-cli-linux-amd64
Verified OK
```

### Summarise

So we now know that the binary you downloaded, was signed by the individual in control of the OpenID based account.

In turn this account has 2FA enabled and is monitored for misuse as records are tranparent within the public rekor transparency log.