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
	"encoding/base64"
	"reflect"
	"sort"
	"strings"
	"testing"
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
			emails := pub.Subjects()

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
