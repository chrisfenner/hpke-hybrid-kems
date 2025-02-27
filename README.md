# hpke-hybrid-kems
Test vectors for hpke-hybrid-kems draft
(https://bluegate010.github.io/draft-andersen-hpke-hybrid-kems/draft-andersen-hpke-hybrid-kems.html).

This implementation of the proposed combined P384+MLKEM768 KEM for PKE is
intended for testing purposes only (i.e., to generate test vectors). It is based
on:

* Filippo's implementation of ML-KEM-768: https://github.com/FiloSottile/mlkem768
* Cloudflare's implementation of DHKEM-P384: https://github.com/cloudflare/circl

These KEMs are wrapped with a helper layer to assist in the hybrid construction.
The wrapped KEMs are tested using relevant test vectors where possible. There
are no well-known DHKEM-P384 test vectors, so this repository introduces some.
