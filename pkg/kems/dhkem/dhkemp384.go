package dhkem

import (
	"fmt"

	"github.com/chrisfenner/hpke-hybrid-kems/pkg/kems"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type dhkemP384Internal struct{}

type EncapsulationKey = kem.PublicKey
type DecapsulationKey = kem.PrivateKey
type Ciphertext []byte

var (
	dhkem     = hpke.KEM_P384_HKDF_SHA384.Scheme()
	DHKEMP384 dhkemP384Internal
	// Compile time assertion that DHKEMP256 implements KEM
	_ kems.DerandomizedKEM[EncapsulationKey, DecapsulationKey, Ciphertext] = DHKEMP384
)

func (dhkemP384Internal) DeriveKeyPair(ikm []byte) (*EncapsulationKey, *DecapsulationKey, error) {
	if len(ikm) != 48 {
		return nil, nil, fmt.Errorf("ikm needs to be exactly 48 bytes")
	}
	pub, priv := dhkem.DeriveKeyPair(ikm)
	return &pub, &priv, nil
}

func (dhkemP384Internal) Encap(pub EncapsulationKey) ([]byte, *Ciphertext, error) {
	ctBytes, sharedKey, err := dhkem.Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	ct := Ciphertext(ctBytes)
	return sharedKey, &ct, nil
}

func (dhkemP384Internal) EncapDerand(pub EncapsulationKey, eseed []byte) ([]byte, *Ciphertext, error) {
	if len(eseed) != 48 {
		return nil, nil, fmt.Errorf("eseed must be exactly 48 bytes")
	}
	ctBytes, sharedKey, err := dhkem.EncapsulateDeterministically(pub, eseed)
	if err != nil {
		return nil, nil, err
	}
	ct := Ciphertext(ctBytes)
	return sharedKey, &ct, nil
}

func (dhkemP384Internal) Decap(priv DecapsulationKey, ct Ciphertext) ([]byte, error) {
	return dhkem.Decapsulate(priv, ct)
}
