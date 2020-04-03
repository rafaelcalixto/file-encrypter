// go 1.10.1
// This is the main package of the project to create a CLI for sign documents
// with the RSA cryptograph

package main

import (
    crypto "encrypterR"
    "flag"
)

func main() {

    // Declaring variables to get options passed by parameter
    var filename string
    var sign bool
    opt_check := flag.Bool("v", false, "a bool")
    opt_gen := flag.Bool("generate", false, "a bool")
    flag.Parse()
    args := flag.Args()

    // Validation to the parameters
    switch l := len(args); l {
    case 0:
        filename = "standard"
        sign = false
    case 1:
        filename = args[0]
        sign = true
    default:
        panic("Wrong number of parameters passed in the command line")
    }

    // Code block if the command is to sign a file
    if !*opt_gen && !*opt_check && sign {
        crypto.SignDoc(filename)
    } else
    // Code block if the command is to create new keys (-generate)
    if *opt_gen && !*opt_check {
        crypto.GenerateRSAKeys(filename)
    } else
    // Code block if the command is to compare the doc with the signature new keys (-v)
    if *opt_check && !*opt_gen {
        crypto.CheckSignature(filename)
    }
}
