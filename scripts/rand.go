package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <filename> <size in MB>\n", os.Args[0])
		return
	}
	num, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile(os.Args[1],
		os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 1024)
	size := num * 1024
	for i := 0; i < size; i++ {
		_, err := io.ReadFull(rand.Reader, buf[:])
		if err != nil {
			log.Fatal(err)
		}
		f.Write(buf)
	}
}
