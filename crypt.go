// crypt is an encryption library.
// it aims to provide io readers and writers for ease of use

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type Reader struct {
	// r is the underlying reader
	r io.Reader

	// the gcm to be used
	gcm cipher.AEAD

	// buffer will be the chunk size used. (MUST BE SAME AS WITH ENCRYPTION)
	buf []byte
}

type Writer struct {
	// w is the underlying reader
	w io.Writer

	// the gcm to be used
	gcm cipher.AEAD

	// buffer will be allocated the correct size by the constructer
	buf []byte
}

// Write encrypts data then saves it to a buffer. once the buffer limit is reached
// it encrypts the buffer and writes it to the underlying writer
func (w Writer) Write(p []byte) (total int, err error) {
	// while we have data to write continue,
	for len(p) != 0 {
		// copy into buf
		n := copy(w.buf[:], p)
		total += n

		// if buf is full write to the underlying writer
		if n == len(w.buf) {
			// encrypt first
			nonce := newNonce(w.gcm.NonceSize())
			ciphertext := w.gcm.Seal(nonce, nonce, p, nil)
			nw, err := w.w.Write(w.buf)

			// make sure it wrote all the bytes
			if err != nil {
				return total + nw, err
			} else if nw != len(ciphertext) {
				// if some was not read decryption will fail so raise an error now
				err = errors.New("failed to write all data, decryption will fail")
			}

			total += nw
		}
	}

	return total, nil
}

// Read will read a full block, decrypt it and copy it into p
// it will continue to do this until p is filled
func (r Reader) Read(p []byte) (int, error) {
	if len(p) < r.gcm.NonceSize() {
		return 0, errors.New("buffer can't be smaller then gcm.NonceSize")
	}

	buf := make([]byte, len(p)+r.gcm.Overhead())
	n, err := r.r.Read(buf)
	if err != nil {
		return 0, err
	}
	ciphertext := buf[:n]

	// decrypt the data
	b, err := r.gcm.Open(nil,
		ciphertext[:r.gcm.NonceSize()],
		ciphertext[r.gcm.NonceSize():],
		nil,
	)

	if err != nil {
		return 0, err
	}

	return copy(p, b), nil
}

// NewReader creates a new reader using r and key
func NewReader(r io.Reader, key *[32]byte, bufSize int) (Reader, error) {
	// default bufSize to 1k at a time
	if bufSize == 0 {
		bufSize = 1 * 1024
	}

	gcm, err := newGCM(key)
	if err != nil {
		return Reader{}, err
	}

	return Reader{
		gcm: gcm,
		r:   r,
		buf: make([]byte, bufSize),
	}, nil
}

// NewWriter creates a new writer using w and key. bufSize can be left nil
// to use the default of 1k
func NewWriter(w io.Writer, key *[32]byte, bufSize int) (Writer, error) {
	// default bufSize to 1k at a time
	if bufSize == 0 {
		bufSize = 1 * 1024
	}

	gcm, err := newGCM(key)
	if err != nil {
		return Writer{}, err
	}

	return Writer{
		gcm: gcm,
		w:   w,
		buf: make([]byte, bufSize),
	}, nil
}

// newGCM skips allocating a cipher.Block and just returns the AEAD
func newGCM(key *[32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	return gcm, err
}

// Encrypt encrypts data using 256-bit AES-GCM. This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := newNonce(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM. This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	gcm, err := newGCM(key)

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext can't be smaller then gcm.NonceSize")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

// newNonce returns a new nonce for cryptograpic use
// if the source for secure randomness fails it will panic
func newNonce(size int) []byte {
	nonce := make([]byte, size)
	n, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}

	if n != size {
		panic("cryptograpic source of secure random failed")
	}

	return nonce
}
