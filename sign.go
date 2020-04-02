package main

import (
    "flag"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/sha256"
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

func String2Keys(priv_key_str string, publ_key_str string) (*rsa.PrivateKey, *rsa.PublicKey) {
    priv_block, _ := pem.Decode([]byte(priv_key_str))
    if priv_block == nil { panic("Error While trying to convert key") }

    publ_block, _ := pem.Decode([]byte(publ_key_str))
    if publ_block == nil { panic("Error While trying to convert key") }

    privKey, err1 := x509.ParsePKCS1PrivateKey(priv_block.Bytes)
    if err1 != nil { panic("Error While trying to convert key") }

    publKey, err2 := x509.ParsePKIXPublicKey(publ_block.Bytes)
    if err2 != nil { panic("Error While trying to convert key") }

    switch publKey := publKey.(type) {
    case *rsa.PublicKey:
        return privKey, publKey
    default:
        break
    }

    panic("Error in the end")
}

func WriteKeys(privKey []byte, publKey []byte, fname string) {
    errpriv := ioutil.WriteFile(fname + ".pem", privKey, 0644)
    if errpriv != nil { errors.New("Error while trying to write the private key") }
    errpub := ioutil.WriteFile(fname + "_publickey", publKey, 0644)
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

    // Keys creation
    if *opt_gen {
        if len(args) == 0 {
            filename = "standard"
        } else {
            filename = args[0]
        }
        WriteKeys(priv_key_bytes, pub_key_bytes, filename)
    }

    // File encrypt
    if !*opt_gen && !*opt_check  && len(args) > 0{
         file, err1 := ioutil.ReadFile(args[0])
         if err1 != nil { panic(err1) }

         privkey, err1 := ioutil.ReadFile(args[0] + ".pem")
         if err1 != nil { panic(err1) }

         pubkey, err4 := ioutil.ReadFile(args[0] + "_publickey")
         if err4 != nil { panic(err4) }

         _, publicKey := String2Keys(string(privkey), string(pubkey))

         message := []byte(string(file))

         label := []byte("")
         hash := sha256.New()

         hiddenmsg, err2 := rsa.EncryptOAEP(
             hash,
             rand.Reader,
             publicKey,
             message,
             label,
         )
         if err2 != nil { panic(err2) }

         err3 := ioutil.WriteFile(args[0] + ".sig", hiddenmsg, 0644)
         if err3 != nil { panic(err3) }
    }

    fmt.Println("mode: ", *opt_check)
    fmt.Println(*opt_gen)
}
