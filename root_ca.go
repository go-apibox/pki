package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

const ROOT_CERT = `-----BEGIN CERTIFICATE-----
MIIEODCCAyACCQDDRhlT3ZHb5zANBgkqhkiG9w0BAQsFADCB3TELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBkZ1amlhbjEPMA0GA1UEBwwGRnV6aG91MSowKAYDVQQKDCFG
dXpob3UgUXV5dW4gVGVjaG5vbG9neSBDby4sIEx0ZC4xLTArBgNVBAsMJEFwcE5v
ZGUgRnJlZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEtMCsGA1UEAwwkQXBwTm9k
ZSBGcmVlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSIwIAYJKoZIhvcNAQkBFhNz
dXBwb3J0QGFwcG5vZGUuY29tMB4XDTE2MDgzMTA3MzEwOVoXDTM2MDgyNjA3MzEw
OVowgd0xCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAZGdWppYW4xDzANBgNVBAcMBkZ1
emhvdTEqMCgGA1UECgwhRnV6aG91IFF1eXVuIFRlY2hub2xvZ3kgQ28uLCBMdGQu
MS0wKwYDVQQLDCRBcHBOb2RlIEZyZWUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
LTArBgNVBAMMJEFwcE5vZGUgRnJlZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEi
MCAGCSqGSIb3DQEJARYTc3VwcG9ydEBhcHBub2RlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMQXKDpHuKit5tXh7pMxCzzE5oKkWYi7pz0cF4wg
/FIR71z7wUmZ8qvWgh5H1xdFNEUsTCecn3RURXQ/2Qi43t44/FY7ScmB7Ru7VhqR
5c6DvGdrHFoCVfqhdko3YFRU80vfYm8WmGr6G7GKjt8A1FHmxTKqoW36pfs2u/Op
3frOLRzo1mUeDI4wFyvK5PFo8N+NNqm5YzVwgksE0UlR2jlATP/1aR0bXRwzlDTU
9cobRIS5keziA2sO3HAYksmVXjEVcZiIv/Ipl3qQjWBo4f/kHNfx2Dz/FOAEGTix
Oy2KOdteeOBGzCQ5bjKtLklaJuW3jTpFqWCJYQAI4XqtVRECAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAMacRM1FGR/GYI4O7FjeoZWrxpbU2R6j051/1Fhmcdxu1x6l0
SNRZx1J9WJJc6I8PmNNxkoAhHGU7nb343AWG4hFEhega0Ry9E0aioXSu8fcnlRhn
3X14NMA5pRVCxCcrRRCzfQ4Mh3eLIoPlD5hxi9gSR5x67wZctF5YkuUCWJNyOe8I
4hUYD0VNbYHH6DBzbXEO+w1tFyJ1fSrI6ZV3pvKg93jTTMvbN4aaC3pEWAOOxLri
IsYJ9MFoGSiUr5EzPOQp5eJBxrk/r0pjW+LLjNNJMSMdTpub6W+QxONeDH9p1zao
NW75mHb4Df+ozGWCntpfjRSuL+NZwyCGAXk6lQ==
-----END CERTIFICATE-----
`

const ROOT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxBcoOke4qK3m1eHukzELPMTmgqRZiLunPRwXjCD8UhHvXPvB
SZnyq9aCHkfXF0U0RSxMJ5yfdFRFdD/ZCLje3jj8VjtJyYHtG7tWGpHlzoO8Z2sc
WgJV+qF2SjdgVFTzS99ibxaYavobsYqO3wDUUebFMqqhbfql+za786nd+s4tHOjW
ZR4MjjAXK8rk8Wjw3402qbljNXCCSwTRSVHaOUBM//VpHRtdHDOUNNT1yhtEhLmR
7OIDaw7ccBiSyZVeMRVxmIi/8imXepCNYGjh/+Qc1/HYPP8U4AQZOLE7LYo52154
4EbMJDluMq0uSVom5beNOkWpYIlhAAjheq1VEQIDAQABAoIBABbFAZzS2zRrDRTk
6UkaNs3Vp1agMu1XrPHBo1JYOjRldL/9U9JyF+WwQOe3O9it5oXpwOYQn8toRbBc
AZ2rqeVwBI0W0Viex6OiuzrWmjLCxUvU+jPRdZ5mxU+U4pCoVKAIzmtL2mMBq9mP
10s50223OErL2Xbl1gQ3tNd0cBxBRC5n3eJqqT9pYP7J7B1+18IsLY+ukn6qQVQf
nU5lBi0brkKW7QfHqWMb6pCbo3cI7QGbPTtI3ZgXk/rWe1JmyLGkLm1VSCqscMyy
drOhmlS0Ape+LiKQgu6rJYfwlJnLYqFU07zGCjvoctAofxZTnIycMXV0Zl2SreI9
i3V8RGECgYEA/yttN0ezIsFqITsCQDmlAS8yBa6728FynevplkcPaG7S1OL3C3RO
UAHAPvni40Jw0ohoRTGpa/9Aqc3NfdiSTzJa3QXZ+k8VtQLoeAiaJTsKlu0AwLqI
cvidiUTHUVgXg1sA43USISs1TXWzZRyngMV2SEcdgK4YpY6utn0oLu0CgYEAxLqD
e8iPMD1PvHpXHKFUNaA2D9DvmKKXbM1p5l7TWJ+kdUdF1HOxoQagWqmMAZ66yvqg
mDOmF/X1fKC69oBQhzW7/a41wJev226ZPBfQa6+2XAK7m8HAhc75sl0RhekYI86h
Xag8cD03CNVasbvHV3flS59UtE3BJmMKc4z4VjUCgYEA4zPVsW0kMgQp7aDPJkSt
iVpuneSx3MBov/i5KlfnfkN/cpMNCaPrvw1wEiMKRPR55NwUi9fmVQUYnJllKXLX
A7GAemClcF1OpLgMKiTuq8vgZ/Zrvy/YIxb/nqQhHWrktM8pAV7SX7pLYcc1jwhu
lRg9c6nuuQ9LXs6m/lJ+nxkCgYEAmn/UNQmMkpkEHwSBl2WH6dmZu5AeKuQ+Qd+M
tLRyDN7LXKONzszRiqHWm30eDEOpdTGhoAaoAZdTpP3h9ydMlvN3YUJIyqkWHiHc
zBnzwC6t69LlnexrE2s6JH78/QrTv4NOrWwrkwYwS4qrgHv1kNcDSAGolzWdZFVR
5u+mNKUCgYBewKQ4quSR2PN7ck5rPwB3sGsu8jCKiHc7TnXeqLGVBmTyCyzowKSn
T9A11GJltB39OOdKvLs06If4U5dqFdNSnb3zLr56C9VucXD6qxHhaunq8cM+I/ws
sHocy1Nb+BbrRo+DLj8ifTI9g3nLAh/kQzZSIjGYRbRJBbMN/e2dVw==
-----END RSA PRIVATE KEY-----
`

var RootCert *x509.Certificate
var RootKey *rsa.PrivateKey

func init() {
	certPem, _ := pem.Decode([]byte(ROOT_CERT))
	RootCert, _ = x509.ParseCertificate(certPem.Bytes)
	privKeyPem, _ := pem.Decode([]byte(ROOT_KEY))
	RootKey, _ = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
}
