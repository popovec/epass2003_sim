# epass2003 simulator

This project was created during experimentation with secure messaging in the
OsEID project (https://github.com/popovec/oseid).

The project is simple simulator that creates simulated card reader with
simulated epass2003 token.  The primary goal of the project is to simulate
the epass2003 token so that this simulation can be used to verify the
epass2003 driver in the OpenSC project (https://github.com/OpenSC/OpenSC).

The author does not guarantee the correctness of the epass2003 token simulation!
USE AT YOUR OWN RISK ONLY!

Note: the author of this simulator owns the epass2003 token, but this token
does not support EC operations.  It uses AES encryption and AES CBC MAC for
secure messaging.  The author cannot guarantee the correctness of the EC
code simulation or the correctness of DES encryption or the use of CMAC_AES
for secure messaging. 


## What is currently possible to try with this simulator:

1. token initialization
   `pkcs15-init -C -T -p pkcs15+onepin --pin 1234 --puk 123456`

2a. RSA key import (max 1024 bit)
   `openssl genrsa -out tmp/rsa1024-key.pem 1024`
   `pkcs15-init --store-private-key tmp/rsa1024-key.pem --key-usage sign,decrypt --pin 1234 --auth-id 1`

2b. RSA key generation (1024, 1536 and 2048 bit)
   `pkcs15-init --generate-key rsa/1024 --key-usage sign,decrypt --pin 1234 --auth-id 01`
   `pkcs15-init --generate-key rsa/2048 --key-usage sign,decrypt --pin 1234 --auth-id 01`

3. EC key generation (prime256v1)
   `pkcs15-init --generate-key ec/prime256v1 --pin 1234 --auth-id 01`

4. RSA decrypt test
5. RSA signature test
6. EC signature test (partial, more info in epass2003_doc/EC.txt )

7. token erase
   `pkcs15-init -E -T`


The simulator fully supports secure messaging.  DES or AES encryption can be
used. MAC using DES, AES_CBC_MAC and CMAC_AES are supported.  Algorithm
selection is possible only during compilation.

## What is not functional:

1.  RSA key import works, but only for key sizes up to 1024 bits.
(arithmetic in this project uses CRT, but epass2003 uploads only modulus and
private exponent, P and Q is factorized from private/public exponent, but
due limited size of multiplication routines this is working only up to 1024
bit key).

2. filesystem allows access to any file, there is no check for security
attributes.

3. record based files - only partial support (not very well checked)

4. import of keys for SM does not work (encryption key or MAC key).

5.  Since I don't have the documentation for the epass2003 token, there are
still many functions that don't work or work but are not exactly the same as
on the real epass2003 token.


## How to compile and run

(tested on Debian 11)

`````
make card_reader
sudo make card_reader_install
`````

You can test the simulated card reader:
`````
$ pcsc_scan
Using reader plug'n play mechanism
Scanning present readers...
0: Simulated reader 00 00

Mon Mar 27 15:38:49 2023
 Reader 0: Simulated reader 00 00
  Event number: 0
  Card state: Card removed,
 -
`````

Then compile and run/test simulated token:
`````
make test
`````

To uninstall simulated reader (and stop the simulation):
`````
$ sudo make card_reader_uninstall
`````
