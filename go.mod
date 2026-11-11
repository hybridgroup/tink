module github.com/hybridgroup/tink

go 1.26.3

require (
	github.com/soypat/lcrypto v0.0.0-20261101144401-00245fd2536a
	github.com/soypat/lneto v0.4.1-0.20261111162121-94d0932e7b53
	tinygo.org/x/drivers v0.37.0
	tinygo.org/x/espradio v0.5.1-0.20261111151050-d9e867e06617
	tinygo.org/x/tinyfont v0.7.0
)

require github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect

replace github.com/soypat/lcrypto => github.com/hybridgroup/lcrypto v0.0.0-20261111160434-8b8b56bd7c08
