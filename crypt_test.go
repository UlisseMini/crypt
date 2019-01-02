package crypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"testing"
)

const (
	// times to test encrypting then decrypting some random data
	smallTimes = 10

	// how large the random bytes for encrypt / decrypt should be in TestSmall
	// on fail the decrypted result and original data will be printed.
	smallSize = 5

	// permision bits to use when creating new files
	// for existing files it will keep the existing permision bits
	filePerm = 0666
)

// TestSmall makes sure it can encrypt / decrypt small amounts of data,
// does not use io readers and writers yet.
func TestSmall(t *testing.T) {
	t.Parallel()
	for i := 0; i < smallTimes; i++ {
		// generate a key and some random data
		key := randKey()
		data := randBytes(smallSize)

		// encrypt the data using the key
		encrypted, err := Encrypt(data, key)
		if err != nil {
			t.Fatal(err)
		}

		// now decrypt it and make sure it matches
		decrypted, err := Decrypt(encrypted, key)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decrypted, data) {
			t.Fatalf("[%X] != [%X]", decrypted, data)
		}
	}
}

// test encryption & decryption with files
func TestFiles(t *testing.T) {
	t.Parallel()

	// files to be tested
	tt := []string{
		"rand500MB",
		"rand100MB",
	}

	// key will be constant throughout the tests
	key := randKey()

	// all test files will be inside the testdata folder
	for _, pName := range tt {
		// the path to the plain file
		pPath := "testdata" + string(os.PathSeparator) + pName

		// name and path for the encrypted files
		eName := pName + ".enc"
		ePath := "testdata" + string(os.PathSeparator) + pName

		// name and path for the decrypted files
		dName := pName + ".dec"
		dPath := "testdata" + string(os.PathSeparator) + pName

		// inside function here so that defer will not wait till the test ends.
		t.Run("TestFile: "+pName, func(t *testing.T) {
			// open the plain file as read only
			pFile, err := os.Open(pPath)
			if err != nil {
				t.Fatal(err)
			}
			defer pFile.Close()

			// open and create the file to hold the encrypted data
			eFile, err := os.OpenFile(ePath, os.O_CREATE|os.O_WRONLY, filePerm)
			if err != nil {
				t.Fatal(err)
			}
			defer eFile.Close()

			// now we can create the cryptograpic writer
			encSteam, err := NewWriter(eFile, key, 32*1024)
			if err != nil {
				t.Fatal(err)
			}

			// encrypt all of the files data into the encrypted file
			_, err = io.Copy(encSteam, pFile)
			if err != nil {
				t.Fatal(err)
			}

			// if the encrypted file and the plain file are equal then fail
			err = notEqual(eFile, pFile)
			if err == nil {
				t.Fatalf("%s and %s are equal", pName, eName)
			}

			// create the decryption stream
			decStream, err := NewReader(eFile, key, 32*1024)
			if err != nil {
				t.Fatal(err)
			}

			// create decrypted file
			dFile, err := os.OpenFile(dPath, os.O_CREATE|os.O_WRONLY, filePerm)
			defer dFile.Close()

			// copy the decrypted stream into the decrypted file
			_, err = io.Copy(dFile, decStream)
			if err != nil {
				t.Fatal(err)
			}

			// decrypted file and plain file should now be equal
			err = notEqual(dFile, pFile)
			if err != nil {
				t.Fatalf("%s and %s should be equal", dName, pName)
			}
		})
	}
}

// notEqual returns an error if r1 and r2 are not equal
// intended use to be with files.
func notEqual(r1 io.Reader, r2 io.Reader) error {
	errNotEqual := errors.New("not equal")
	buf1 := make([]byte, 8)
	buf2 := make([]byte, 8)

	// If we get too meny errors then we'll return nil, errNotEqual should happen
	// before that though.
	errn := 0

	for errn < 5 {
		_, err := r1.Read(buf1[:])
		if err != nil {
			errn++
		}
		_, err = r2.Read(buf2[:])
		if err != nil {
			errn++
		}

		// if the chunk is not equal return errNotEqual
		if !bytes.Equal(buf1, buf2) {
			return errNotEqual
		}
	}

	return nil
}

// randKey returns a random key for encryption
// it will panic if rand.Reader fails.
func randKey() *[32]byte {
	randomKey := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, randomKey[:])
	if err != nil {
		panic(err)
	}

	return randomKey
}

// return s random bytes
// it will panic if rand.Reader fails.
func randBytes(s int) []byte {
	b := make([]byte, s)
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(err)
	}

	return b
}
