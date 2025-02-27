package mlkem

import (
	"fmt"

	"github.com/chrisfenner/hpke-hybrid-kems/pkg/kems"
	"github.com/chrisfenner/mlkem768"
)

type mlkem768Internal struct{}

type EncapsulationKey []byte
type DecapsulationKey = mlkem768.DecapsulationKey
type Ciphertext []byte

var (
	MLKEM768 mlkem768Internal
	// Compile time assertion that MLKEM768 implements KEM
	_ kems.DerandomizedKEM[EncapsulationKey, DecapsulationKey, Ciphertext] = MLKEM768
)

func (mlkem768Internal) DeriveKeyPair(ikm []byte) (*EncapsulationKey, *DecapsulationKey, error) {
	if len(ikm) != 64 {
		return nil, nil, fmt.Errorf("ikm needs to be d || z, exactly 64 bytes")
	}
	priv, err := mlkem768.NewKeyFromSeed(ikm)
	if err != nil {
		return nil, nil, err
	}
	pub := EncapsulationKey(priv.EncapsulationKey())
	return &pub, priv, nil
}

func (mlkem768Internal) Encap(pub EncapsulationKey) ([]byte, *Ciphertext, error) {
	ctBytes, sharedKey, err := mlkem768.Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	ct := Ciphertext(ctBytes)
	return sharedKey, &ct, nil
}

func (mlkem768Internal) EncapDerand(pub EncapsulationKey, eseed []byte) ([]byte, *Ciphertext, error) {
	if len(eseed) != 32 {
		return nil, nil, fmt.Errorf("eseed must be exactly 32 bytes")
	}
	var seed [32]byte
	copy(seed[:], eseed)
	ctBytes, sharedKey, err := mlkem768.EncapsulateDerand(pub, seed)
	if err != nil {
		return nil, nil, err
	}
	ct := Ciphertext(ctBytes)
	return sharedKey, &ct, nil
}

func (mlkem768Internal) Decap(priv DecapsulationKey, ct Ciphertext) ([]byte, error) {
	return mlkem768.Decapsulate(&priv, ct)
}
