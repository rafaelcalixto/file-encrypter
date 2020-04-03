// go 1.10.1
// This is a libraby that provides functions to create RSA keys, write keys into
// files, convert the keys format from bytes to keys and vice versa

package rsakeysfunc

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
)

func CreateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { panic(err.Error) }

    return privatekey, &privatekey.PublicKey
}

func Keys2Bytes(privKey *rsa.PrivateKey, publKey *rsa.PublicKey) ([]byte, []byte) {
    priv_bytes := x509.MarshalPKCS1PrivateKey(privKey)
    priv_pem := pem.EncodeToMemory(
        &pem.Block{
            Type  : "RSA PRIVATE KEY",
            Bytes : priv_bytes,
        },
    )

    publ_bytes, err := x509.MarshalPKIXPublicKey(publKey)
    if err != nil { panic("Fail to covert the public key to string") }

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

func WriteKeys(privKey []byte, publKey []byte, fname string) (string) {
    var msg string
    errpriv := ioutil.WriteFile(fname + ".pem", privKey, 0644)
    if errpriv != nil { msg = "Error while trying to write the private key" }
    errpub := ioutil.WriteFile(fname + ".publickey", publKey, 0644)
    if errpub != nil { msg = "Error while trying to write the public key" }
    if msg == "" { msg = "Key files generated." }

    return msg
}

func GetRSAKeys(fname string) ([]byte, string) {
    // Check if exists specifict keys to the file
    files, err_ls := ioutil.ReadDir(".")
    if err_ls != nil { panic(err_ls) }

    var kname string
    checkprivkey := true
    checkpublkey := true
    for _, f := range files {
        if fname + ".pem" == f.Name() { checkprivkey = false }
        if fname + ".publickey" == f.Name() { checkpublkey = false }
    }

    // Read file to sign and RSA keys
    file, err_readfile := ioutil.ReadFile(fname)
    if err_readfile != nil { panic(err_readfile) }

    if checkprivkey && checkpublkey {
        kname = "standard"
    } else {
        kname = fname
    }
    privkey, err_readprivkey := ioutil.ReadFile(kname + ".pem")
    if err_readprivkey != nil { panic(err_readprivkey) }

    pubkey, err_readpublkey := ioutil.ReadFile(kname + ".publickey")
    if err_readpublkey != nil { panic(err_readpublkey) }

    // Getting data to sign the document
    _, publicKey := String2Keys(string(privkey), string(pubkey))
    message := []byte(string(file))
    label := []byte("")
    hash := sha256.New()

    secret, err_encrypt := rsa.EncryptOAEP(
        hash,
        rand.Reader,
        publicKey,
        message,
        label,
    )
    if err_encrypt != nil { panic(err_encrypt) }

    return secret, kname
}
