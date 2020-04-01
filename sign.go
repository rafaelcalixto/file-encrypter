package main

import (
    "flag"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
)

// Genetare RSA Keys
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { fmt.Println(err.Error) }

    return privatekey, &privatekey.PublicKey
}

func Keys2String(privKey *rsa.PrivateKey, publKey *rsa.PublicKey) ([]byte, []byte) {
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
    return priv_pem, publ_pem
}

func WriteKeys(privKey []byte, publKey []byte, fname string) {
    errpriv := ioutil.WriteFile(fname + ".pem", privKey, 0644)
    if errpriv != nil { errors.New("Error while trying to write the private key") }
    errpub := ioutil.WriteFile(fname + "publickey", publKey, 0644)
    if errpub != nil { errors.New("Error while trying to write the private key") }

    fmt.Println("Key files generated.")
}

func main() {
    var filename string
    opt_check := flag.Bool("v", false, "a bool")
    opt_gen := flag.Bool("generate", false, "a bool")

    flag.Parse()
    args := flag.Args()

    // Getting keys
    privatekey, publicky := GenerateKeys()

    // Converting Keys to String
    priv_key_bytes, pub_key_bytes := Keys2String(privatekey, publicky)

    if *opt_gen {
        if len(args) == 0 {
            filename = "standard"
        } else {
            filename = args[0]
        }
        WriteKeys(priv_key_bytes, pub_key_bytes, filename)
    }

    fmt.Println("mode: ", *opt_check)
    fmt.Println(*opt_gen)
}
