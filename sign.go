package main

import (
    "flag"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
)

// Genetare RSA Keys
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { fmt.Println(err.Error) }

    return privatekey, &privatekey.PublicKey
}

func Keys2String(privKey *rsa.PrivateKey, publKey *rsa.PublicKey) (string, string) {
    priv_bytes := x509.MarshalPKCS1PrivateKey(privKey)
    priv_pem := pem.EncodeToMemory(
        &pem.Block{
            Type  : "RSA PRIVATE KEY",
            Bytes : priv_bytes,
        },
    )

    publ_bytes, err := x509.MarshalPKIXPublicKey(publKey)
    if err != nil { errors.New("Fail to covert the public key to string") }

    publ_pem := pem.EncodeToMemory(
        &pem.Block{
            Type  : "RSA PUBLIC KEY",
            Bytes : publ_bytes,
        },
    )
    return string(priv_pem), string(publ_pem)
}

// func String2Keys2String() ()

func main() {
    mode := flag.Bool("v", false, "a bool")
    createkeys := flag.Bool("generate", false, "a bool")
    flag.Parse()
    filename := flag.Args()


    // Getting keys
    privatekey, publicky := GenerateKeys()

    // Converting Keys to String
    priv_key_str, pub_key_str := Keys2String(privatekey, publicky)

    fmt.Println(priv_key_str, pub_key_str)
    fmt.Println("mode: ", *mode)
    fmt.Println(*createkeys)
    fmt.Println(filename)
    if len(filename) > 0 {
        fmt.Println(filename)
    }
}
