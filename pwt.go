package pwtgo

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"time"

	"github.com/lemon-mint/pwt-go/header"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const encodeMode = 1
const decodeMode = 2
const sighash = 10

//Signer : encode, decode, sign, verify
type Signer struct {
	alg        Alg
	key        []byte
	rsaPrivKey *rsa.PrivateKey
	rsaPubKey  *rsa.PublicKey
	mode       int
	mac        hash.Hash
	sigtype    int
}

//NewHash : Cryptographic hash-based signer
func NewHash(alg Alg, key []byte) (*Signer, error) {
	s := new(Signer)
	s.mode = encodeMode
	s.key = key
	s.alg = alg
	s.sigtype = sighash
	var err error
	switch s.alg {
	case HS256:
		s.mac = hmac.New(sha256.New, s.key)
	case HS384:
		s.mac = hmac.New(sha512.New384, s.key)
	case HS512:
		s.mac = hmac.New(sha512.New, s.key)
	case BLAKE2B256:
		s.mac, err = blake2b.New256(s.key)
		if err != nil {
			return nil, err
		}
	case BLAKE2B384:
		s.mac, err = blake2b.New384(s.key)
		if err != nil {
			return nil, err
		}
	case BLAKE2B512:
		s.mac, err = blake2b.New512(s.key)
		if err != nil {
			return nil, err
		}
	}
	return s, err
}

//Encode : Encode Payload to PWT
func (s *Signer) Encode(payload protoreflect.ProtoMessage, expire time.Duration) (string, error) {
	head, err := proto.Marshal(&header.Header{
		Alg:     string(s.alg),
		Iss:     time.Now().UTC().Unix(),
		Exp:     time.Now().UTC().Add(expire).Unix(),
		Version: 1,
	})
	if err != nil {
		return "", err
	}
	headstring := base64.RawURLEncoding.EncodeToString(head)
	body, err := proto.Marshal(payload)
	if err != nil {
		return "", err
	}
	bodystring := base64.RawURLEncoding.EncodeToString(body)
	var sig []byte
	switch s.sigtype {
	case sighash:
		s.mac.Write([]byte(headstring + "." + bodystring))
		sig = s.mac.Sum(nil)
	}
	return headstring + "." + bodystring + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
