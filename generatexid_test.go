package dhcp4client

import (
	"bytes"
	"math/rand"
	"testing"
)

func Test_GenerateXID(t *testing.T) {
	//Set the math seed so we always get the same result.
	rand.Seed(1)

	cryptoMessageid := make([]byte, 4)
	CryptoGenerateXID(cryptoMessageid)

	t.Logf("Crypto Token: %v", cryptoMessageid)

	mathMessageid := make([]byte, 4)
	MathGenerateXID(mathMessageid)

	//Math token shouldn't change as we don't seed it.
	if !bytes.Equal(mathMessageid, []byte{82, 253, 252, 7}) {
		t.Errorf("Math Token was %v, expected %v", mathMessageid, []byte{82, 253, 252, 7})
		t.Fail()
	}

}
