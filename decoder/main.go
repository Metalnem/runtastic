package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func main() {
	raw, err := ioutil.ReadFile("activity.dat")

	if err != nil {
		log.Fatal(err)
	}

	encoded := strings.Split(string(raw), "\\n")
	var decoded []byte

	for _, line := range encoded {
		b, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			log.Fatal(err)
		}

		decoded = append(decoded, b...)
	}

	fmt.Println(decoded)
}
