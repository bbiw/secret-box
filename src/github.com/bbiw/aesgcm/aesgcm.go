package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/pkg/errors"
	"io"
)

const signature = 0x6147434d
const headerlen = 6

/*
produce a packet
  signature: "aGCM"
  noncelen: uint8(12)
  extralen: uint8
  nonce: radomly generated
  extra:
  sealed: plaintext authenticated and encrypted with key
          extra is also authenticated

  Note that the design of crypto/cipher.AEAD makes it difficult at best
  to create a streaming interface. We are stuck with a message-oriented
  protocol unless we want to reimplement the GCM.  This may or may not
  be a bad thing.
*/
func Seal(key, plaintext, extra []byte) (msg []byte, err error) {
	extralen := len(extra)
	msg = nil

	aes, err := aes.NewCipher(key)
	if err != nil {
		err = errors.Wrap(err, "cannot get AES cipher")
		return
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		err = errors.Wrap(err, "cannot get GCM mode")
		return
	}

	noncelen := aead.NonceSize()
	// at this point, we can calculate the length of the packed message
	//ml := headerlen + noncelen + aead.Overhead() + len(plaintext) + extralen

	// header
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, uint32(signature))
	err = buf.WriteByte(uint8(noncelen))
	err = buf.WriteByte(uint8(extralen))

	// nonce
	_, err = io.CopyN(buf, rand.Reader, int64(noncelen))
	if err != nil {
		err = errors.Wrap(err, "CopyN failed")
	}
	nonce := buf.Bytes()[headerlen : headerlen+noncelen]

	// extra
	buf.Write(extra)

	// data
	sealed := aead.Seal(nil, nonce, plaintext, extra)
	if err != nil {
		err = errors.Wrap(err, "Seal failed")
		return
	}
	buf.Write(sealed)

	msg = buf.Bytes()
	return
}

func readHeader(b []byte) (headerlen, noncelen, extralen int, err error) {
	var sig uint32
	buf := bytes.NewBuffer(b)
	err = binary.Read(buf, binary.BigEndian, &sig)
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "cannot read signature")
	}
	if sig != signature {
		return 0, 0, 0, errors.Errorf("signature failed: expected %x got %x", uint32(signature), sig)
	}
	nl, err := buf.ReadByte()
	el, err := buf.ReadByte()
	return len(b) - buf.Len(), int(nl), int(el), err
}

/*
 produce the plaintext and extra data from the packet created by Seal

 The key must be the same as the one used for encryption.
 Produce an error if the message cannot be authenticated.
*/
func Open(key []byte, packed []byte) (plaintext, extra []byte, err error) {
	hlen, noncelen, extralen, err := readHeader(packed)
	if err != nil {
		err = errors.Wrap(err, "invalid header")
		return
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		err = errors.Wrap(err, "cannot get AES cipher")
		return
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		err = errors.Wrap(err, "cannot get GCM mode")
		return
	}

	i := hlen
	nonce := packed[i : i+noncelen]
	i += noncelen
	j := i + extralen
	extra = packed[i:j]
	sealed := packed[j:]

	plaintext, err = aead.Open(nil, nonce, sealed, extra)
	return
}
