// go 1.10.1
// Those are the files to test the functions of the project. Here are tests to
// create binaries RSA keys, write RSA keys files, sign documents and check signatures

package main

import (
    "testing"
    "io/ioutil"
    krsa "rsakeysfunc"
    "bytes"
    "reflect"
)

func TestCreateBinaryKeys(t *testing.T) {
    // Test of Binary Keys creation
    privatekey, publicky := krsa.CreateKeys()
    priv_key_bytes, pub_key_bytes := krsa.Keys2Bytes(privatekey, publicky)
    if reflect.TypeOf(priv_key_bytes).Kind() != reflect.Slice {
        t.Error("Expected binary array to the private key")
    }
    if reflect.TypeOf(pub_key_bytes).Kind() != reflect.Slice {
        t.Error("Expected binary array to the public key")
    }
}

func TestCreateKeysFiles(t *testing.T) {
    // Test of writing keys in a file
    fname := "test"
    privatekey, publicky := krsa.CreateKeys()
    priv_key_bytes, pub_key_bytes := krsa.Keys2Bytes(privatekey, publicky)
    krsa.WriteKeys(priv_key_bytes, pub_key_bytes, fname)
    files, err_ls := ioutil.ReadDir(".")
    if err_ls != nil { panic(err_ls) }
    checkprivkey := true
    checkpublkey := true
    for _, f := range files {
        if fname + ".pem" == f.Name() { checkprivkey = false }
        if fname + ".publickey" == f.Name() { checkpublkey = false }
    }
    if checkprivkey {
        t.Error("Fail to create private key file")
    }
    if checkpublkey {
        t.Error("Fail to create public key file")
    }
}

func TestSignDoc(t *testing.T) {
    // Test of file signature
    fname := "test"
    err_f := ioutil.WriteFile(fname, []byte("test"), 0644)
    if err_f != nil { panic(err_f) }
    secret, _ := krsa.GetRSAKeys(fname)
    err_file := ioutil.WriteFile(fname + ".sig", secret, 0644)
    if err_file != nil { panic(err_file) }
    files, err_ls := ioutil.ReadDir(".")
    if err_ls != nil { panic(err_ls) }
    checksign := true
    for _, f := range files {
        if fname + ".sig" == f.Name() { checksign = false }
    }
    if checksign {
        t.Error("Fail to sign the document")
    }
}

func TestCheckSign(t *testing.T) {
    // Test to validate the signature
    fname := "test"
    originalmsg, err_readfile := ioutil.ReadFile(fname)
    if err_readfile != nil { panic(err_readfile) }
    decryptmsg, _ := krsa.DecryptMsg(fname)
    res := bytes.Compare(originalmsg, decryptmsg)
    if res != 0 {
        t.Error("Fail to validate the signature")
    }
}
