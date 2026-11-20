module github.com/hybridgroup/tink

go 1.26.3

require (
	github.com/hybridgroup/tls13 v0.0.0-20261117102252-0c851989a2d3
	github.com/soypat/lcrypto v0.0.0-20261113123326-ff541f06137f
	github.com/soypat/lneto v0.4.1-0.20261119185226-0494b55c2511
	tinygo.org/x/drivers v0.37.0
	tinygo.org/x/espradio v0.5.1-0.20261120114622-52a3d08fa2e8
	tinygo.org/x/tinyfont v0.7.0
)

require github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect

replace github.com/soypat/lcrypto => github.com/hybridgroup/lcrypto v0.0.0-20261120100015-8b2c7daaab4a
