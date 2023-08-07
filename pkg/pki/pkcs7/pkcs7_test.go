/*
Copyright © 2021 The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sigstore/rekor/pkg/pki/identity"
	"github.com/sigstore/rekor/pkg/pki/x509/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const pkcsECDSAPEM = `-----BEGIN PKCS7-----
MIIW9QYJKoZIhvcNAQcCoIIW5jCCFuICAQExDzANBglghkgBZQMEAgEFADCCBAwG
CSqGSIb3DQEHAaCCA/0EggP5U2lnbmF0dXJlLVZlcnNpb246IDEuMA0KQ3JlYXRl
ZC1CeTogMTUgKEFkb3B0T3BlbkpESykNClNIQS0yNTYtRGlnZXN0LU1hbmlmZXN0
OiB6QzV4S3JxM1pIZS90UnNMMTR6bittM1lReWVaZFltbmxuNWJNdlJaZW5JPQ0K
U0hBLTI1Ni1EaWdlc3QtTWFuaWZlc3QtTWFpbi1BdHRyaWJ1dGVzOiBBZW00ckh4
eTYycmx6QzJVU0NVbDcwSEFmYmV2NzhXDQogUkNhUWNKcXEwTE5nPQ0KDQpOYW1l
OiBzaWdzdG9yZS9wbHVnaW4vU2lnbi5jbGFzcw0KU0hBLTI1Ni1EaWdlc3Q6IEZH
UVZGbDlROEQ1ZTAzRE1RaGN2aTNtK0orZCtUc3A3TmFxKzBUUXpoSW89DQoNCk5h
bWU6IE1FVEEtSU5GL21hdmVuL2Rldi5zaWdzdG9yZS9zaWdzdG9yZS1tYXZlbi1w
bHVnaW4vcG9tLnhtbA0KU0hBLTI1Ni1EaWdlc3Q6IFlWRUFpeXZRMDZOVHRkRFRq
cVJPYUZZbnQzcDY0QzFFa2NBbWlLNkpOcGM9DQoNCk5hbWU6IE1FVEEtSU5GL21h
dmVuL2Rldi5zaWdzdG9yZS9zaWdzdG9yZS1tYXZlbi1wbHVnaW4vcG9tLnByb3Bl
cnRpZXMNClNIQS0yNTYtRGlnZXN0OiA3aU1VWlpLeVI3cjdLelR1K2M2dVlsSWJ5
c0VuZE1wMVBacUVXR2pHU2lNPQ0KDQpOYW1lOiBNRVRBLUlORi9tYXZlbi9kZXYu
c2lnc3RvcmUvc2lnc3RvcmUtbWF2ZW4tcGx1Z2luL3BsdWdpbi1oZWxwLnhtbA0K
U0hBLTI1Ni1EaWdlc3Q6IG4yM1N4ZmlDcU43WW9FSnd5S0k3NUE3N3crRHREUmIr
dFI0bVl6SnZlWnc9DQoNCk5hbWU6IE1FVEEtSU5GL21hdmVuL3BsdWdpbi54bWwN
ClNIQS0yNTYtRGlnZXN0OiBTRktBeGVwMlErSzJNVmZVeUV2U1FvMFRBNDhDSitu
QXNxbmhzRWRJOUVFPQ0KDQpOYW1lOiBzaWdzdG9yZS9wbHVnaW4vU2lnbiQxLmNs
YXNzDQpTSEEtMjU2LURpZ2VzdDogNlEvQVExZW9QNE9hQVJwbnVSRklRb0tZUC9S
bmJ0TGxqOGJhUEg3TkdMZz0NCg0KTmFtZTogc2lnc3RvcmUvcGx1Z2luL0hlbHBN
b2pvLmNsYXNzDQpTSEEtMjU2LURpZ2VzdDogU3ZPNkhibVlBSzBMVEhyVCtYbmRB
OExJdUptZU5ub1dyYmVHS3dvTE9Pdz0NCg0KoIIEsjCCAfgwggF+oAMCAQICEzVZ
A2aAoqHzw7Mu3X5uoHi27ocwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3Rv
cmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTAzMDcwMzIwMjlaFw0zMTAy
MjMwMzIwMjlaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2ln
c3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS0sgOyIuZPqTTvGRFmNMpXplg6
MDpDWt5C/hmROWeRlnoS/fwPW0TQN0W67GeYtCXGrLWkS+0qeX6f4w+XcanP1HU1
Z5b0temp/tmH7MHv0Li6JUVAq3DhNvtogOfrc3ejZjBkMA4GA1UdDwEB/wQEAwIB
BjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTIxR0AQZokKTJRJOsNrkrt
SgbT7DAfBgNVHSMEGDAWgBTIxR0AQZokKTJRJOsNrkrtSgbT7DAKBggqhkjOPQQD
AwNoADBlAjB/JYliXzLour11wYYw4GODMLJZjf0ycVXv/N1qxaJsJjX9OestV+PB
fXOJt2t6M1wCMQCo0Wsuf2o/47CihiJJkGrYyPLrqR6//gsRb2iVpqWKjZCwxkVP
vaK84eYSNka3LmkwggKyMIICN6ADAgECAhQA0hq1XjiwESgeFBdACLc/8dxN/jAK
BggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNp
Z3N0b3JlMB4XDTIxMDQwNTE3MzA0MVoXDTIxMDQwNTE3NTAzM1owPDEcMBoGA1UE
CgwTYmNhbGxhd2FAcmVkaGF0LmNvbTEcMBoGA1UEAwwTYmNhbGxhd2FAcmVkaGF0
LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOQ44IV3v9zK5zLUoPpqt4Wy
snDT+OkgZQmPLq6PtNbqXOJnGtdi1crznvmlytJ1rsrNtobtG92Y3XtMSx+2fo6j
ggEnMIIBIzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDAYD
VR0TAQH/BAIwADAdBgNVHQ4EFgQU89SEXFUXE+hEwlqafHp6CayzjJcwHwYDVR0j
BBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG0+wwgY0GCCsGAQUFBwEBBIGAMH4wfAYI
KwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVudC02MDNmZTdlNy0wMDAw
LTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQuc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9j
YTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5jcnQwHgYDVR0RBBcwFYETYmNhbGxhd2FA
cmVkaGF0LmNvbTAKBggqhkjOPQQDAwNpADBmAjEAy3AOFlXTN7pMUyLyzsLk8tn8
v782Bo5hGSGYJMZn8eRHGktDSlx4bj51Gu+V1c4kAjEA9ISrLl83ZU6j1yP0emR1
FgAoHceF5dtx4KzSAi4B0Cghz7kBabfljWjCMy36Ce6rMYIOBDCCDgACAQEwQjAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlAhQA0hq1
XjiwESgeFBdACLc/8dxN/jANBglghkgBZQMEAgEFADALBgcqhkjOPQIBBQAERzBF
AiAttO+bYBcMnsMBQlkTdXII2f8CREQVkl9ehakvihSjBgIhAKYic4Ycq3qYLoV9
4GZWm0NT0EFbzRG5BJaoEZgUL/lyoYINUDCCDUwGCyqGSIb3DQEJEAIOMYINOzCC
DTcGCSqGSIb3DQEHAqCCDSgwgg0kAgEDMQ8wDQYJYIZIAWUDBAIBBQAwgYEGCyqG
SIb3DQEJEAEEoHIEcDBuAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQg
DpZGPZm1vvrjhj/lQAoCYWm+9GCixa/ySbShy9tPdjQCEBOsApMET86YdBu0FUV2
558YDzIwMjEwNDA1MTczMDQxWgIIMX79aENwnPqgggo3MIIE/jCCA+agAwIBAgIQ
DUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEV
MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
MTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5n
IENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEwNjAwMDAwMFowSDELMAkGA1UEBhMC
VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBU
aW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMLm
YYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQtSYQ/h3Ib5FrDJbnGlxI70Tlv5th
zRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4bbx9+cdtCT2+anaH6Yq9+IRdHnbJ
5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOKfF1FLUuxUOZBOjdWhtyTI433UCXo
ZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlKXAwxikqMiMX3MFr5FK8VX2xDSQn9
JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYervnpbCiAvSwnJlaeNsvrWY4tOpXIc
7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0MA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEEGA1UdIAQ6MDgwNgYJ
YIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29t
L0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQU
NkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2Ny
bDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6
Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEF
BQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBP
BggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOC
AQEASBzctemaI7znGucgDo5nRv1CclF0CiNHo6uS0iXEcFm+FKDlJ4GlTRQVGQd5
8NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4eTZ6J7fz51Kfk6ftQ55757TdQSKJ
+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2hF3MN9PNlOXBL85zWenvaDLw9MtAb
y/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1FUL1LTI4gdr0YKK6tFL7XOBhJCVP
st/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6Xt/Q/hOvB46NJofrOp79Wz7pZdmGJ
X36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaX
whUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEw
NzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hB
MiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+
57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZH
BhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlx
a+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1m
blZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89
zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1Ud
DgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
UYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
BgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgG
CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
Y29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zp
ze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4
J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY
1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7
U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRY
YJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJL
okqV2PWmjlIxggJNMIICSQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQD
EyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhANQkrg
vjqI/2BAIc4UAPDdMA0GCWCGSAFlAwQCAQUAoIGYMBoGCSqGSIb3DQEJAzENBgsq
hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjEwNDA1MTczMDQxWjArBgsqhkiG
9w0BCRACDDEcMBowGDAWBBTh14Ko4ZG+72vKFpG1qrSUpiSb8zAvBgkqhkiG9w0B
CQQxIgQggGa+Xld/PXUrauHVUANZD8tGkn6b2ioPrjbYztVzPikwDQYJKoZIhvcN
AQEBBQAEggEAj7sr/Yqkwqrm21IhIHPLXDDDhxBPfcv0DJhFsAOR77wlDzV52yg6
JrexTMuLWgPulVN0UyMoCISqMv22R9ELZGGxPjDYBu0jURFKZEryVEOoidA8U07x
TBSkcGB6Vf4P6mNxzl2whkIg4bgob8ynD8O6eb7aF6sTXFN6GyZHtYhMlMuJw3Tt
zNwtTy9bCZI4T4IlKscOhJ4hnVz0PO4mi/7C6Y/fLz/KoNXJR1q8LBTlHd5fNN5S
NCy1JqXRQ/EFawlOicDB5IFL7TFpPTPEXsyTg1x5j1o0tAKErU3FJg30wiblro49
oNLw5vSDnA3bG/vDsgshFr03RYcLPUVAtA==
-----END PKCS7-----`

const signedContent = `U2lnbmF0dXJlLVZlcnNpb246IDEuMA0KQ3JlYXRlZC1CeTogMTUgKEFkb3B0T3Bl
bkpESykNClNIQS0yNTYtRGlnZXN0LU1hbmlmZXN0OiB6QzV4S3JxM1pIZS90UnNM
MTR6bittM1lReWVaZFltbmxuNWJNdlJaZW5JPQ0KU0hBLTI1Ni1EaWdlc3QtTWFu
aWZlc3QtTWFpbi1BdHRyaWJ1dGVzOiBBZW00ckh4eTYycmx6QzJVU0NVbDcwSEFm
YmV2NzhXDQogUkNhUWNKcXEwTE5nPQ0KDQpOYW1lOiBzaWdzdG9yZS9wbHVnaW4v
U2lnbi5jbGFzcw0KU0hBLTI1Ni1EaWdlc3Q6IEZHUVZGbDlROEQ1ZTAzRE1RaGN2
aTNtK0orZCtUc3A3TmFxKzBUUXpoSW89DQoNCk5hbWU6IE1FVEEtSU5GL21hdmVu
L2Rldi5zaWdzdG9yZS9zaWdzdG9yZS1tYXZlbi1wbHVnaW4vcG9tLnhtbA0KU0hB
LTI1Ni1EaWdlc3Q6IFlWRUFpeXZRMDZOVHRkRFRqcVJPYUZZbnQzcDY0QzFFa2NB
bWlLNkpOcGM9DQoNCk5hbWU6IE1FVEEtSU5GL21hdmVuL2Rldi5zaWdzdG9yZS9z
aWdzdG9yZS1tYXZlbi1wbHVnaW4vcG9tLnByb3BlcnRpZXMNClNIQS0yNTYtRGln
ZXN0OiA3aU1VWlpLeVI3cjdLelR1K2M2dVlsSWJ5c0VuZE1wMVBacUVXR2pHU2lN
PQ0KDQpOYW1lOiBNRVRBLUlORi9tYXZlbi9kZXYuc2lnc3RvcmUvc2lnc3RvcmUt
bWF2ZW4tcGx1Z2luL3BsdWdpbi1oZWxwLnhtbA0KU0hBLTI1Ni1EaWdlc3Q6IG4y
M1N4ZmlDcU43WW9FSnd5S0k3NUE3N3crRHREUmIrdFI0bVl6SnZlWnc9DQoNCk5h
bWU6IE1FVEEtSU5GL21hdmVuL3BsdWdpbi54bWwNClNIQS0yNTYtRGlnZXN0OiBT
RktBeGVwMlErSzJNVmZVeUV2U1FvMFRBNDhDSituQXNxbmhzRWRJOUVFPQ0KDQpO
YW1lOiBzaWdzdG9yZS9wbHVnaW4vU2lnbiQxLmNsYXNzDQpTSEEtMjU2LURpZ2Vz
dDogNlEvQVExZW9QNE9hQVJwbnVSRklRb0tZUC9SbmJ0TGxqOGJhUEg3TkdMZz0N
Cg0KTmFtZTogc2lnc3RvcmUvcGx1Z2luL0hlbHBNb2pvLmNsYXNzDQpTSEEtMjU2
LURpZ2VzdDogU3ZPNkhibVlBSzBMVEhyVCtYbmRBOExJdUptZU5ub1dyYmVHS3dv
TE9Pdz0NCg0K`

const pkcsPEMEmail = `-----BEGIN PKCS7-----
MIIDCgYJKoZIhvcNAQcCoIIC+zCCAvcCAQExADALBgkqhkiG9w0BBwGgggLdMIIC
2TCCAjqgAwIBAgIUAL0Gw2SJvPW8PbXw+42XwmW8//owCgYIKoZIzj0EAwIwfTEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1BMQ8wDQYDVQQHDAZCb3N0b24xITAfBgNV
BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEOMAwGA1UEAwwFUmVrb3IxHTAb
BgkqhkiG9w0BCQEWDnRlc3RAcmVrb3IuZGV2MCAXDTIxMDQxOTE0MTMyMFoYDzQ0
ODUwNTMxMTQxMzIwWjB9MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzANBgNV
BAcMBkJvc3RvbjEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ4w
DAYDVQQDDAVSZWtvcjEdMBsGCSqGSIb3DQEJARYOdGVzdEByZWtvci5kZXYwgZsw
EAYHKoZIzj0CAQYFK4EEACMDgYYABABN0k2SaX5iK6Ahw8m+wXbQml4E8GEL0qLA
lA0Gu8thlhvAcOLdPzNxPl2tsM7bBzTrD2H4iLM4myvpT4x2NgbjyAClvhXfJTOY
m7oTFcKq0kNf8LEV2fjBpfdrw9yiS1DV6YWHwCzc3TUrZIChGhMYnfZPVu997wzy
euVBSUMeO5Lmp6NTMFEwHQYDVR0OBBYEFJPLiMMFN5Cm6/rjOTPR2HWbbO5PMB8G
A1UdIwQYMBaAFJPLiMMFN5Cm6/rjOTPR2HWbbO5PMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDgYwAMIGIAkIBmRqxw8sStWknjeOgdyKkd+vFehNuVaiHAKGs
z+6KG3jPG5xN5+/Ws+OMTAp7Hv6HH5ChDO3LJ6t/sCun1otdWmICQgCUqg1ke+Rj
nVqVlz1rUR7CTL2SlG9Xg1kAkYH4vMn/otEuAhnKf+GWLNB1l/dTFNEyysvIA6yd
FG8HXGWcnVVIVaEAMQA=
-----END PKCS7-----`

func TestSignature_Verify(t *testing.T) {
	tests := []struct {
		name  string
		pkcs7 string
	}{
		{
			name:  "ec",
			pkcs7: pkcsECDSAPEM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSignature(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}

			data, _ := base64.StdEncoding.DecodeString(signedContent)
			if err := s.Verify(bytes.NewReader(data), pub); err != nil {
				t.Fatalf("Signature.Verify() error = %v", err)
			}

			// Now try with the canonical value (this is a detached signature)
			cb, err := s.CanonicalValue()
			if err != nil {
				t.Fatal(err)
			}
			canonicalSig, err := NewSignature(bytes.NewReader(cb))
			if err != nil {
				t.Fatal(err)
			}
			if err := canonicalSig.Verify(bytes.NewReader(data), pub); err != nil {
				t.Fatalf("CanonicalSignature.Verify() error = %v", err)
			}
		})
	}
}

func TestSignature_VerifyFail(t *testing.T) {
	tests := []struct {
		name  string
		pkcs7 string
	}{
		{
			name:  "ec",
			pkcs7: pkcsECDSAPEM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make some fake data, and tamper with the signature
			s, err := NewSignature(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}

			pub, err := NewPublicKey(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}

			data := []byte("something that shouldn't verify")
			if err := s.Verify(bytes.NewReader(data), pub); err == nil {
				t.Error("Signature.Verify() expected error!")
			}
		})
	}
}

func TestEmailAddresses(t *testing.T) {
	tests := []struct {
		name   string
		pkcs7  string
		emails []string
	}{
		{
			name:   "ec",
			pkcs7:  pkcsECDSAPEM,
			emails: []string{},
		},
		{
			name:   "email",
			pkcs7:  pkcsPEMEmail,
			emails: []string{"test@rekor.dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := NewPublicKey(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}
			emails := pub.EmailAddresses()

			if len(emails) == len(tt.emails) {
				if len(emails) > 0 {
					sort.Strings(emails)
					sort.Strings(tt.emails)
					if !reflect.DeepEqual(emails, tt.emails) {
						t.Errorf("%v: Error getting email addresses from keys, got %v, expected %v", tt.name, emails, tt.emails)
					}
				}
			} else {
				t.Errorf("%v: Error getting email addresses from keys, got %v, expected %v", tt.name, emails, tt.emails)
			}

		})
	}
}

func TestSubjects(t *testing.T) {
	// dynamically generate a PKCS7 structure with multiple subjects set
	url, _ := url.Parse("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.1.1")
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	leafCert, leafKey, _ := testutils.GenerateLeafCert("subject@example.com", "oidc-issuer", url, rootCert, rootKey)

	b := pkcs7.NewBuilder(leafKey, []*x509.Certificate{leafCert}, crypto.SHA256)
	// set content to random data, only the certificate matters
	err := b.SetContentData([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("error setting content data in pkcs7: %v", err)
	}
	s, err := b.Sign()
	if err != nil {
		t.Fatalf("error signing pkcs7: %v", err)
	}
	pkcs7bytes, err := s.Marshal()
	if err != nil {
		t.Fatalf("error marshalling pkcs7: %v", err)
	}

	tests := []struct {
		name  string
		pkcs7 string
		subs  []string
	}{
		{
			name:  "ec",
			pkcs7: pkcsECDSAPEM,
			subs:  []string{},
		},
		{
			name:  "email in subject",
			pkcs7: pkcsPEMEmail,
			subs:  []string{"test@rekor.dev"},
		},
		{
			name:  "email and URI in subject alternative name",
			pkcs7: string(pkcs7bytes),
			subs:  []string{"subject@example.com", "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := NewPublicKey(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}
			subs := pub.Subjects()

			if len(subs) == len(tt.subs) {
				if len(subs) > 0 {
					sort.Strings(subs)
					sort.Strings(tt.subs)
					if !reflect.DeepEqual(subs, tt.subs) {
						t.Errorf("%v: Error getting subjects from keys, got %v, expected %v", tt.name, subs, tt.subs)
					}
				}
			} else {
				t.Errorf("%v: Error getting subjects from keys, got %v, expected %v", tt.name, subs, tt.subs)
			}

		})
	}
}

func TestIdentities(t *testing.T) {
	// dynamically generate a PKCS7 structure with multiple subjects set
	url, _ := url.Parse("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.1.1")
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	leafCert, leafKey, _ := testutils.GenerateLeafCert("subject@example.com", "oidc-issuer", url, rootCert, rootKey)
	leafPEM, _ := cryptoutils.MarshalPublicKeyToPEM(leafKey.Public())
	leafCertPEM, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	b := pkcs7.NewBuilder(leafKey, []*x509.Certificate{leafCert}, crypto.SHA256)
	// set content to random data, only the certificate matters
	err := b.SetContentData([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("error setting content data in pkcs7: %v", err)
	}
	s, err := b.Sign()
	if err != nil {
		t.Fatalf("error signing pkcs7: %v", err)
	}
	pkcs7bytes, err := s.Marshal()
	if err != nil {
		t.Fatalf("error marshalling pkcs7: %v", err)
	}

	pkcsECDSAPEMKey := `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtLIDsiLmT6k07xkRZjTKV6ZYOjA6Q1re
Qv4ZkTlnkZZ6Ev38D1tE0DdFuuxnmLQlxqy1pEvtKnl+n+MPl3Gpz9R1NWeW9LXp
qf7Zh+zB79C4uiVFQKtw4Tb7aIDn63N3
-----END PUBLIC KEY-----
`

	pkcsKeyCert := `-----BEGIN CERTIFICATE-----
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
`

	pkcsPEMEmailKey := `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQATdJNkml+YiugIcPJvsF20JpeBPBh
C9KiwJQNBrvLYZYbwHDi3T8zcT5drbDO2wc06w9h+IizOJsr6U+MdjYG48gApb4V
3yUzmJu6ExXCqtJDX/CxFdn4waX3a8PcoktQ1emFh8As3N01K2SAoRoTGJ32T1bv
fe8M8nrlQUlDHjuS5qc=
-----END PUBLIC KEY-----
`

	pkcsEmailCert := `-----BEGIN CERTIFICATE-----
MIIC2TCCAjqgAwIBAgIUAL0Gw2SJvPW8PbXw+42XwmW8//owCgYIKoZIzj0EAwIw
fTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1BMQ8wDQYDVQQHDAZCb3N0b24xITAf
BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEOMAwGA1UEAwwFUmVrb3Ix
HTAbBgkqhkiG9w0BCQEWDnRlc3RAcmVrb3IuZGV2MCAXDTIxMDQxOTE0MTMyMFoY
DzQ0ODUwNTMxMTQxMzIwWjB9MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUExDzAN
BgNVBAcMBkJvc3RvbjEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk
MQ4wDAYDVQQDDAVSZWtvcjEdMBsGCSqGSIb3DQEJARYOdGVzdEByZWtvci5kZXYw
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABABN0k2SaX5iK6Ahw8m+wXbQml4E8GEL
0qLAlA0Gu8thlhvAcOLdPzNxPl2tsM7bBzTrD2H4iLM4myvpT4x2NgbjyAClvhXf
JTOYm7oTFcKq0kNf8LEV2fjBpfdrw9yiS1DV6YWHwCzc3TUrZIChGhMYnfZPVu99
7wzyeuVBSUMeO5Lmp6NTMFEwHQYDVR0OBBYEFJPLiMMFN5Cm6/rjOTPR2HWbbO5P
MB8GA1UdIwQYMBaAFJPLiMMFN5Cm6/rjOTPR2HWbbO5PMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDgYwAMIGIAkIBmRqxw8sStWknjeOgdyKkd+vFehNuVaiH
AKGsz+6KG3jPG5xN5+/Ws+OMTAp7Hv6HH5ChDO3LJ6t/sCun1otdWmICQgCUqg1k
e+RjnVqVlz1rUR7CTL2SlG9Xg1kAkYH4vMn/otEuAhnKf+GWLNB1l/dTFNEyysvI
A6ydFG8HXGWcnVVIVQ==
-----END CERTIFICATE-----
`

	tests := []struct {
		name       string
		pkcs7      string
		identities []string
	}{
		{
			name:       "ec",
			pkcs7:      pkcsECDSAPEM,
			identities: []string{pkcsKeyCert, pkcsECDSAPEMKey},
		},
		{
			name:       "email in subject",
			pkcs7:      pkcsPEMEmail,
			identities: []string{pkcsEmailCert, pkcsPEMEmailKey},
		},
		{
			name:       "email and URI in subject alternative name",
			pkcs7:      string(pkcs7bytes),
			identities: []string{string(leafCertPEM), string(leafPEM)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := NewPublicKey(strings.NewReader(tt.pkcs7))
			if err != nil {
				t.Fatal(err)
			}
			ids, err := pub.Identities()
			if err != nil {
				t.Fatalf("unexpected error getting identities: %v", err)
			}
			if len(ids) != 2 {
				t.Fatalf("expected 2 identities, got %d", len(ids))
			}

			// compare certificate
			cert, _ := cryptoutils.UnmarshalCertificatesFromPEM([]byte(tt.identities[0]))
			expectedID := identity.Identity{Crypto: cert[0], Raw: []byte(tt.identities[0])}
			if !ids[0].Crypto.(*x509.Certificate).Equal(expectedID.Crypto.(*x509.Certificate)) {
				t.Errorf("certificates did not match")
			}
			if !reflect.DeepEqual(ids[0].Raw, expectedID.Raw) {
				t.Errorf("raw identities did not match, expected %v, got %v", ids[0].Raw, string(expectedID.Raw))
			}

			// compare public key
			key, _ := cryptoutils.UnmarshalPEMToPublicKey([]byte(tt.identities[1]))
			expectedID = identity.Identity{Crypto: key, Raw: []byte(tt.identities[1])}
			if err := cryptoutils.EqualKeys(expectedID.Crypto, ids[1].Crypto); err != nil {
				t.Errorf("%v: public keys did not match: %v", tt.name, err)
			}
			if !reflect.DeepEqual(ids[1].Raw, expectedID.Raw) {
				t.Errorf("%v: raw identities did not match", tt.name)
			}
		})
	}
}
