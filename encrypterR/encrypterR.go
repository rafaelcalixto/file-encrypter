// go 1.10.1
// This is a libraby that provides functions to create RSA keys, sign documents
// and validate the signature

package encrypterR

import (
    krsa "rsakeysfunc"
    "fmt"
    "io/ioutil"
    "bytes"
)

func GenerateRSAKeys(fname string) {
    // Create and return keys
    privatekey, publicky := krsa.CreateKeys()

    // Converting Keys to Bytes
    priv_key_bytes, pub_key_bytes := krsa.Keys2Bytes(privatekey, publicky)

    // Writing keys in a file
    status := krsa.WriteKeys(priv_key_bytes, pub_key_bytes, fname)
    fmt.Println(status)
}

func SignDoc(fname string) {
    // Get encrypted message
    secret, kname := krsa.GetRSAKeys(fname)

    // Write the signature into a file
    err_file := ioutil.WriteFile(fname + ".sig", secret, 0644)
    if err_file != nil { panic(err_file) }

    fmt.Println("Signature file '" + kname + ".sig' generated.")
}

func CheckSignature(fname string) {
    // Get encrypted message
    secret, kname := krsa.GetRSAKeys(fname)

    // Read signature file
    filesign, err_readfile := ioutil.ReadFile(kname + ".sig")
    if err_readfile != nil { panic(err_readfile) }

    fmt.Println("Comparing '" + fname + "' with signature '" + kname + ".sing'...")
    res := bytes.Compare(secret, filesign)
    fmt.Println(res)
    if string(secret) == string(filesign) {
        fmt.Println("Congratulations! This signature is valid!")
    } else {
        fmt.Println("Ooops! The signature is NOT valid.")
    }
}
