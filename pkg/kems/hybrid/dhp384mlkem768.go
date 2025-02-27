package hybrid

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/chrisfenner/hpke-hybrid-kems/pkg/kems"
	"github.com/chrisfenner/hpke-hybrid-kems/pkg/kems/dhkem"
	"github.com/chrisfenner/hpke-hybrid-kems/pkg/kems/mlkem"
)

type dhp384PlusMLKEM768Internal struct{}

type EncapsulationKey struct {
	DH dhkem.EncapsulationKey
	ML mlkem.EncapsulationKey
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (e EncapsulationKey) MarshalBinary() (data []byte, err error) {
	dh, err := e.DH.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(dh)+len(e.ML))
	copy(result[:len(dh)], dh)
	copy(result[len(dh):], e.ML)
	return result, nil
}

type DecapsulationKey struct {
	DH dhkem.DecapsulationKey
	ML mlkem.DecapsulationKey
}

func (d DecapsulationKey) Public() EncapsulationKey {
	return EncapsulationKey{
		DH: d.DH.Public(),
		ML: d.ML.EncapsulationKey(),
	}
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (d DecapsulationKey) MarshalBinary() (data []byte, err error) {
	dh, err := d.DH.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ml := d.ML.Bytes()
	result := make([]byte, len(dh)+len(ml))
	copy(result[:len(dh)], dh)
	copy(result[len(dh):], ml)
	return result, nil
}

type Ciphertext struct {
	DH dhkem.Ciphertext
	ML mlkem.Ciphertext
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (ct Ciphertext) MarshalBinary() (data []byte, err error) {
	result := make([]byte, len(ct.DH)+len(ct.ML))
	copy(result[:len(ct.DH)], ct.DH)
	copy(result[len(ct.DH):], ct.ML)
	return result, nil
}

var (
	DHKEMP384PlusMLKEM768 dhp384PlusMLKEM768Internal
	// Compile time assertion that DHKEMP384PlusMLKEM768 implements KEM
	_ kems.DerandomizedKEM[EncapsulationKey, DecapsulationKey, Ciphertext] = DHKEMP384PlusMLKEM768
)

const (
	dhkemID uint16 = 0x0011
	mlkemID uint16 = 0x0041
)

func (dhp384PlusMLKEM768Internal) DeriveKeyPair(ikm []byte) (*EncapsulationKey, *DecapsulationKey, error) {
	okm, err := hkdf.Key(sha512.New, ikm, nil, "ecdh-p384-ml-kem-768-dkp", 112)
	if err != nil {
		return nil, nil, err
	}
	dhPub, dhPriv, err := dhkem.DHKEMP384.DeriveKeyPair(okm[:48])
	if err != nil {
		return nil, nil, err
	}
	mlPub, mlPriv, err := mlkem.MLKEM768.DeriveKeyPair(okm[48:])
	if err != nil {
		return nil, nil, err
	}
	ek := EncapsulationKey{
		DH: *dhPub,
		ML: *mlPub,
	}
	dk := DecapsulationKey{
		DH: *dhPriv,
		ML: *mlPriv,
	}
	return &ek, &dk, nil
}

func (d dhp384PlusMLKEM768Internal) Encap(pub EncapsulationKey) ([]byte, *Ciphertext, error) {
	m := make([]byte, 80)
	rand.Read(m)
	return d.EncapDerand(pub, m)
}

func keyCombiner(ssDH, ssML []byte, ct Ciphertext, pk EncapsulationKey) ([]byte, error) {
	dhpkBytes, err := pk.DH.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(dhpkBytes) != 97 {
		return nil, fmt.Errorf("unexpected output of MarshalBinary")
	}

	h := sha512.New()
	h.Write(ssDH)
	h.Write(ssML)
	h.Write(ct.DH)
	h.Write(ct.ML)
	h.Write(dhpkBytes)
	h.Write(pk.ML)
	binary.Write(h, binary.BigEndian, dhkemID)
	binary.Write(h, binary.BigEndian, mlkemID)
	return h.Sum(nil), nil
}

func (dhp384PlusMLKEM768Internal) EncapDerand(pub EncapsulationKey, eseed []byte) ([]byte, *Ciphertext, error) {
	if len(eseed) != 80 {
		return nil, nil, fmt.Errorf("eseed must be exactly 80 bytes")
	}
	dhKey, dhCT, err := dhkem.DHKEMP384.EncapDerand(pub.DH, eseed[:48])
	if err != nil {
		return nil, nil, err
	}
	mlKey, mlCT, err := mlkem.MLKEM768.EncapDerand(pub.ML, eseed[48:])
	if err != nil {
		return nil, nil, err
	}
	ct := Ciphertext{
		DH: *dhCT,
		ML: *mlCT,
	}
	key, err := keyCombiner(dhKey, mlKey, ct, pub)
	if err != nil {
		return nil, nil, err
	}
	return key, &ct, nil
}

func (dhp384PlusMLKEM768Internal) Decap(priv DecapsulationKey, ct Ciphertext) ([]byte, error) {
	dhKey, err := dhkem.DHKEMP384.Decap(priv.DH, ct.DH)
	if err != nil {
		return nil, err
	}
	mlKey, err := mlkem.MLKEM768.Decap(priv.ML, ct.ML)
	if err != nil {
		return nil, err
	}
	key, err := keyCombiner(dhKey, mlKey, ct, priv.Public())
	if err != nil {
		return nil, err
	}
	return key, nil
}
