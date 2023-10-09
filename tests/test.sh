#!/bin/bash

set -e
echo "Erasing card"
pkcs15-init -E -T
echo "initializing card"
pkcs15-init -C -T -p pkcs15+onepin --pin 1234 --puk 123456
echo "generating rsa key"
rm -rf tmp/rsa1024-key.pem
openssl genrsa -out tmp/rsa1024-key.pem 1024
# this is working, up to 1024 bit
echo "uploading rsa key"
pkcs15-init --store-private-key tmp/rsa1024-key.pem --key-usage sign,decrypt --pin 1234 --auth-id 1
echo "generating RSA key (1024 bit)"
pkcs15-init --generate-key rsa/1024 --key-usage sign,decrypt --pin 1234 --auth-id 01
echo "generating RSA key (2048 bit)"
pkcs15-init --generate-key rsa/2048 --key-usage sign,decrypt --pin 1234 --auth-id 01
echo "generating EC key (prie256v1)"
pkcs15-init --generate-key ec/prime256v1 --pin 1234 --auth-id 01
echo "testing RSA decrypt"
tests/decrypt_test.sh
echo "testing RSA sign"
tests/rsa_sign_test.sh
echo 'testing RSA sign (pkcs#11)'
tests/rsa_sign_pkcs11_test.sh
echo "testing EC sing"
tests/ec_sign_test.sh
echo "Erasing card"
pkcs15-init -E -T
## run p11test
if [ -d "OpenSC/src/tests/p11test" ]; then
	echo "p11test, initializing token, keys..."
	pkcs15-init -C -T -p pkcs15+onepin --pin 1234 --puk 123456
	pkcs15-init --generate-key rsa/2048 --key-usage sign --pin 1234 --auth-id 01 --id 1 --label 'RSA2k key'
	pkcs15-init --generate-key rsa/2048 --key-usage decrypt --pin 1234 --auth-id 01 --id 2 --label 'RSA2k encryption key'
	pkcs15-init --generate-key ec/prime256v1 --key-usage sign --pin 1234 --auth-id 01 --id 3
	cd OpenSC/src/tests/p11test
	pwd
	ls
	make p11test
	./p11test -p 1234 -o epass2003_ref_new.json
	diff -u epass2003_ref.json epass2003_ref_new.json
fi
