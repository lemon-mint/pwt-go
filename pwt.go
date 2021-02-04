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

//Signer : encode, decode, sign, verify
type Signer struct {
	alg        Alg
	key        []byte
	rsaPrivKey *rsa.PrivateKey
	rsaPubKey  *rsa.PublicKey
	mode       int
}

//Encode : Encode Payload to PWT
func (s *Signer) Encode(payload protoreflect.ProtoMessage, expire time.Duration) (string, error) {
	head, err := proto.Marshal(&header.Header{
		Alg:     string(s.alg),
		Iss:     time.Now().Unix(),
		Exp:     time.Now().Add(expire).Unix(),
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
	var mac hash.Hash
	var sig []byte
	switch s.alg {
	case HS256:
		mac = hmac.New(sha256.New, s.key)
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	case HS384:
		mac = hmac.New(sha512.New384, s.key)
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	case HS512:
		mac = hmac.New(sha512.New, s.key)
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	case BLAKE2B256:
		mac, err = blake2b.New256(s.key)
		if err != nil {
			return "", err
		}
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	case BLAKE2B384:
		mac, err = blake2b.New384(s.key)
		if err != nil {
			return "", err
		}
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	case BLAKE2B512:
		mac, err = blake2b.New512(s.key)
		if err != nil {
			return "", err
		}
		mac.Write([]byte(headstring + "." + bodystring))
		sig = mac.Sum(nil)
	}
	return headstring + "." + bodystring + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
