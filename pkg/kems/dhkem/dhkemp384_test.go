package dhkem

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(t *testing.T, h string) []byte {
	bytes, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("DecodeString() = %v", err)
	}
	return bytes
}

// There aren't any known-answer tests that I could find, so I generated some.
// Thus, these should be considered "change detection tests" until someone can
// confirm that these test vectors work for multiple known-good implementations.
func TestEncapDecapKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		ikm  []byte
		ek   []byte
		dk   []byte
		m    []byte
		ct   []byte
		k    []byte
	}{
		{
			name: "test vector 1",
			ikm:  mustDecodeHex(t, "2fceb82aa9d7d34c5ecb53d5e15bab2bed6200629529e04cc1f6725fd013462caf5c919dfdea0758d876f536492c3005"),
			ek:   mustDecodeHex(t, "0496d169c6198a63dbe26b4e0f946f83ccc937309c08b7a50c2d2919c3ebee6fc8c5a4962a5cb921057280827b5f00641d5f5a276620185c71cb4db214bb4c452fbc6ed3471c76f77a0dcc0d7790548d4b335bf9fb9494b5c486c0edf4a8b32e8e"),
			dk:   mustDecodeHex(t, "f418eb1224ee644fdfbc246b789169f9737e20293066369011920decf6f4e494bbcdff45edf30247b86f23d3f39357bc"),
			m:    mustDecodeHex(t, "a58903b10ac656b0dcdd96cb2972687b8b824641101b3e67fbd82764ced1238bdf53eb6ea3063c268fd8e8846079e6f6"),
			ct:   mustDecodeHex(t, "043892551a6c8ccc95b998f136b9b1772362c31a50d85844a80031c859efb98fa83a02ee7231c0b7b204c4babbcb55037c60da941d8679446aad398f8ef917039bca3b3bb494765cf15e99707fa0cca71bd200077d4e2e2a07bfe42581473cf49c"),
			k:    mustDecodeHex(t, "aa476c2dc0b53f25571fadfa2136961678887bc39df2b375a97b06dff95a55514a7671c547f8d455706b241874f46869"),
		},
		{
			name: "test vector 2",
			ikm:  mustDecodeHex(t, "1c384f1c38b95278e63ef899b8615f411159de7c5fe889d37971025d29f7a692a052e181d147cbb4a8ef1ef0a0948723"),
			ek:   mustDecodeHex(t, "04e340bf3c1ee80775426411bf3127896d559b45934cda29fe4cf141e3742678a007fd0ae2889ef58676bf387c49f9217fff9a171edd564c6636caab7181ff973b8d5458221a26a48d2bc480930411432893dbf31d0d26257fb67bad0aeeda56fd"),
			dk:   mustDecodeHex(t, "25c1b764f7b9c5c29630949289870a16d4776667a852e4ada148184140c5eb106c44fe0c6138deba50de1a2e1e50d7b1"),
			m:    mustDecodeHex(t, "8c40903199ad82aec8f7f37ead4fac6af9b6f96c18f069a162ced8dd34ce0a402d0afffc4aa8efc3f6423444770c5857"),
			ct:   mustDecodeHex(t, "041b76521cc5fa7c5bd17714899b97d366aeebc95fa086c80406816f6c4246fd38077ee9daefb92ff5ee2f7f50d7b63f0c72e394b4e494237cbab3d265a934e62481b46d2a84d5504909efcfe8ee7bf23e7a53ac5e03c7f28b3069dbb65728ea1c"),
			k:    mustDecodeHex(t, "e6c862c5e90191624a0b48ebfd1075e3d5dcc1a9fdcc47786f71db242394b34793d3612cbfddafebaa0943e316d41e2d"),
		},
		{
			name: "test vector 3",
			ikm:  mustDecodeHex(t, "d696223e74058e533376e100c0449599d89c39eb9acc8193151ee88925035955fc5efe6eadd1a3d67abf970bb9236591"),
			ek:   mustDecodeHex(t, "04e2edbeded8631d62429ae7e3f0c0de32fd9a48b49669f3a8adf5979f2c8e9b78f138bbf7680bcb1a5f100c034a00c76a963020828ef830847b1f633cfe22ae06d45dfe4570d9b457968636958a833c814547eddec4ce507c8f68de7f637586c4"),
			dk:   mustDecodeHex(t, "4e78141236c5091bcc8503156f66a65f321eaa7e87f9c6215f48cce80ab4485b706c43bf2f30d2c512091061e9e43390"),
			m:    mustDecodeHex(t, "393db0df9194dddd189cb8f03a0ab3d3043612a70cb321c30ef9b029235bc745e33ef3b62a6eb79bf8bb7b81af4f55c5"),
			ct:   mustDecodeHex(t, "04dc47f86234cf7cfa1010d25f5f52d40ce6c6e4698a2ac5a35937646ba7bf790a113a55c4a6de04d6d30f155a9195e5238257c09ef824adb414f517a3011b8e6d59765713ae7e3be246f9308320546aefe08cdb0046e59ec787923e8dce8e176d"),
			k:    mustDecodeHex(t, "2df63a61727b54401a314fa813a77ca5b96026fbca50952d51a9bb2fa80e545cb1c6072e93de4dcb657f96b4538981b8"),
		},
		{
			name: "test vector 4",
			ikm:  mustDecodeHex(t, "dabbfa4757d390caebdccf1c57411d0095253c5bd6939714d8d8623d79b365be651ded37cf954d77e900dd852e786b3e"),
			ek:   mustDecodeHex(t, "047fc7f9ac3401ccfe2743b779f34bff98ae1f50c4573be3119f9d8c5de420e79761aef256d8d569938bda45c9fcd99eb848a84f55fca9f93028c86e8ee6aa0a30e9f8d3eb7782b5c6e878819a7e32cce4ae3e8ef440aaa87506c6cbd495ae18be"),
			dk:   mustDecodeHex(t, "3320698b78569a17d107160da28e2f24ba13ec0515825857a4409f2d14473b8bdbb9dec9fc1a5190fd104a8f8f819cd5"),
			m:    mustDecodeHex(t, "12cb462cf161e78ca7a1ff913ed04b6de59eaf09cb83c236137091810a26fafa3a16466734ec4a210e8136978c40d7dc"),
			ct:   mustDecodeHex(t, "0497c947dccb5bd54962304a59e02ef5bd4fd23b8862b1f1dd5cb2027c1a4036a5f3e411c188aeeb3ebc35b66bd6efef88dc0e4e7bb0d2953f7984b293fcbdbba57abb89e0568373440b852c1f003d9d8e505a4215f7d9b275017d373116ce235b"),
			k:    mustDecodeHex(t, "d4f59698a854a02ade63e56f111f05438b8efd3dc6ef82a465e0067571dd25e145d876f75759e7efeeded3b1cd624235"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := DHKEMP384.DeriveKeyPair(tc.ikm)
			if err != nil {
				t.Fatalf("DeriveKeyPair = %v", err)
			}
			pubBytes, err := (*pub).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary = %v", err)
			}
			privBytes, err := (*priv).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary = %v", err)
			}
			if !bytes.Equal(pubBytes, tc.ek) {
				t.Errorf("ek =\n%x\nwant\n%x", pubBytes, tc.ek)
			}
			if !bytes.Equal(privBytes, tc.dk) {
				t.Errorf("dk =\n%x\nwant\n%x", privBytes, tc.dk)
			}

			key, ciphertext, err := DHKEMP384.EncapDerand(*pub, tc.m)
			if err != nil {
				t.Fatalf("EncapDerand = %v", err)
			}
			if !bytes.Equal(*ciphertext, tc.ct) {
				t.Errorf("ct =\n%x\nwant\n%x", *ciphertext, tc.ct)
			}
			if !bytes.Equal(key, tc.k) {
				t.Errorf("k =\n%x\nwant\n%x", key, tc.k)
			}

			decapsed, err := DHKEMP384.Decap(*priv, *ciphertext)
			if err != nil {
				t.Fatalf("Decap = %v", err)
			}
			if !bytes.Equal(decapsed, tc.k) {
				t.Errorf("k =\n%x\nwant\n%x", decapsed, tc.k)
			}
		})
	}
}
