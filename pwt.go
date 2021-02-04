package pwtgo

import (
	"crypto/hmac"
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

func encode(payload protoreflect.ProtoMessage, expire time.Duration, alg Alg, key []byte) (string, error) {
	head, err := proto.Marshal(&header.Header{
		Alg:     string(alg),
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
	switch alg {
	case HS256:
		mac = hmac.New(sha256.New, key)
	case HS384:
		mac = hmac.New(sha512.New384, key)
	case HS512:
		mac = hmac.New(sha512.New, key)
	}
	mac.Write([]byte(headstring + "." + bodystring))
	return headstring + "." + bodystring + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
