package main

import (
    "flag"
    "crypto/rand"
    "crypto/rsa"
)

// Genetare RSA Keys
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { fmt.Println(err.Error) }

    return privatekey, privatekey.PublicKey
}

func main() {
    mode := flag.Bool("v", false, "a bool")
    createkeys := flag.Bool("generate", false, "a bool")
    filename := flag.Args()[0]
    flag.Parse()

    // Getting keys
    privatekey, publicky := GenerateKeys()

}
