# file-encrypter
This is a challenge to build a Command Line software to encrypt local files using private and public keys.
This could be pretty useful to write secret messages and have the possibility to validate the original content after.

The application was been built using Go 1.10.1 and his standard libraries.

Follow those instructions to use the application:

1 - Move the directories encrypterR and rsakeysfunc to your GOPATH src directory

2 - Build the application with the command go build sign.go

3 - Copy to the directory of the project a file with the text to be encrypted

4 - To generate a new pair of keys execute the command {sign -generate [file name]}.
If the keys was successfully created the application will show the message {Key files generated.}
    *The file name is an optional parameter. If not informed the keys are created
    with the name 'standard'*

5 - To encrypt the message, just type {sign [file name]}.
If the file was successfully signed the application will show the message {Signature file '[file name]' generated.}

6 - To validate the signature of a file execute the command {sign -v '[file name]'}
If the signature is valid to the application will show the message {Congratulations! This signature is valid!}
If the signature is not valid to the application will show the message {Ooops! The signature is NOT valid.}

To test the functions of the application use the scripts in sign_test.go
