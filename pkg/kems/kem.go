// Package kems implements some basic (non-hybrid) KEMs.
package kems

type KEM[PK any, SK any, CT any] interface {
	DeriveKeyPair(ikm []byte) (*PK, *SK, error)
	Encap(pub PK) ([]byte, *CT, error)
	Decap(priv SK, ct CT) ([]byte, error)
}

type DerandomizedKEM[PK any, SK any, CT any] interface {
	KEM[PK, SK, CT]
	EncapDerand(pub PK, eseed []byte) ([]byte, *CT, error)
}
