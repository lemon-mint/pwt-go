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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

//Alg : Signing Algorithm
type Alg string

//HS256 : HMAC-SHA-256
const HS256 Alg = "HMAC-SHA-256"

//HS384 : HMAC-SHA-384
const HS384 Alg = "HMAC-SHA-384"

//HS512 : HMAC-SHA-512
const HS512 Alg = "HMAC-SHA-512"

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
	switch s.alg {
	case HS256:
		mac = hmac.New(sha256.New, s.key)
	case HS384:
		mac = hmac.New(sha512.New384, s.key)
	case HS512:
		mac = hmac.New(sha512.New, s.key)
	}
	mac.Write([]byte(headstring + "." + bodystring))
	return headstring + "." + bodystring + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
