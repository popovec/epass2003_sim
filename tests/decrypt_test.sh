#!/bin/bash
#
#    epass2003_decrypt_test.sh
#
#    Copyright (C) 2015-2023 Peter Popovec, popovec.peter@gmail.com
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#***************************************************************************************************************************
#export OPENSC_DEBUG=255
PIN=1234
failecho (){
	tput setaf 1 2>/dev/null;echo $@;tput sgr0 2>/dev/null
}
trueecho (){
	tput setaf 2 2>/dev/null;echo $@;tput sgr0 2>/dev/null
}
warnecho (){
	tput setaf 3 2>/dev/null;echo $@;tput sgr0 2>/dev/null
}
boldecho (){
	tput bold 2>/dev/null;echo $@;tput sgr0 2>/dev/null
}

export mode="RSA-DECRYPT-TEST"
export SCSlot=0

if [ $mode == "RSA-DECRYPT-TEST" ]; then
boldecho "testing RSA decrypt operation"
boldecho "-----------------------------"
mkdir -p tmp

echo "testtesttesttesttest" > tmp/rsa_decrypt_testfile.txt
TEST_OAEP=0;
set -o pipefail
pkcs11-tool --slot-index ${SCSlot} -M |grep -q -w RSA-PKCS-OAEP
if [ $? == 0 ]; then
	TEST_OAEP=1
fi

err=0
for keyID in $(pkcs15-tool --list-public-keys|gawk -F: '{if($1 ~ "ModLength"){if(strtonum($2)>=512)OK=1;else OK=0};if($1~"ID" && OK==1){print $2;OK=0}}') ; do
echo "Reading public key "$keyID
#pkcs15-tool --read-public-key $keyID |tee tmp/exported_rsa_key.pub
pkcs15-tool --read-public-key $keyID > tmp/exported_rsa_key.pub
if [ $? -ne 0 ]; then
	failecho "pkcs15-tool failed"
	exit 1
fi
openssl rsa -pubin -in tmp/exported_rsa_key.pub -text -noout|grep bit
echo "using openssl to encrypt test message"
openssl pkeyutl -encrypt -pubin -inkey tmp/exported_rsa_key.pub -in tmp/rsa_decrypt_testfile.txt -out tmp/rsa_encrypted_testfile.txt
if [ $? -ne 0 ]; then
	grep -v -- '---' tmp/exported_rsa_key.pub|base64 -d |hd
        failecho "openssl pkeyutl -encrypt fail"
        exit 1
fi

if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
echo "using pkcs11 interface to decrypt test message"
rm -f  tmp/rsa_pkcs11_tool_decrypted_testfile.txt

ST=$(date +%s.%N)
pkcs11-tool --slot-index ${SCSlot} --decrypt \
	--id $keyID \
	--input-file tmp/rsa_encrypted_testfile.txt \
	--output-file tmp/rsa_pkcs11_tool_decrypted_testfile.txt \
	-m RSA-PKCS --pin $PIN
if [ $? -ne 0 ]; then
	failecho "pkcs11-tool failed"
	exit 1
fi
ET=$(date +%s.%N)
echo "${ET} ${ST}"|gawk '{printf "pkcs11-tool RSA DECRYPT time %f\n",($1 - $2)}'

cmp tmp/rsa_decrypt_testfile.txt tmp/rsa_pkcs11_tool_decrypted_testfile.txt
if [ $? -eq 0 ]; then
	trueecho "OK"
else
	failecho "error in decrypt"
	err=$[$err + 1 ]
fi
if [ $TEST_OAEP == 1 ]; then
 echo "0123456789test0123456789" >tmp/oaep_test.plaintext
 KEY_LEN=`wc -m < tmp/exported_rsa_key.pub`
 # skil small keys (below 1024 bits)
 if [ $KEY_LEN -gt 250 ]; then
	 openssl pkeyutl -encrypt -pubin \
        -inkey tmp/exported_rsa_key.pub \
		-pkeyopt rsa_padding_mode:oaep \
		-pkeyopt rsa_oaep_md:sha1 \
		-in tmp/oaep_test.plaintext \
		-out tmp/oaep_test.ciphertext
	 if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
	 echo "using pkcs11 interface to decrypt test message (OAEP mode)"
	 rm -f  tmp/rsa_pkcs11_tool_decrypted_testfile.txt
	 ST=$(date +%s.%N)
	 pkcs11-tool --slot-index ${SCSlot} --decrypt \
		--id $keyID \
		--input-file tmp/oaep_test.ciphertext \
		--output-file tmp/rsa_pkcs11_tool_decrypted_testfile.txt \
		--mgf MGF1-SHA1 --hash-algorithm SHA-1 \
		-m RSA-PKCS-OAEP --pin $PIN
	if [ $? -ne 0 ]; then
		failecho "pkcs11-tool failed"
		exit 1
	fi
	ET=$(date +%s.%N)
	echo "${ET} ${ST}"|gawk '{printf "pkcs11-tool RSA DECRYPT time %f\n",($1 - $2)}'
	cmp tmp/oaep_test.plaintext tmp/rsa_pkcs11_tool_decrypted_testfile.txt
	if [ $? -eq 0 ]; then
		trueecho "OK"
	else
		failecho "error in decrypt"
		err=$[$err + 1 ]
	fi
 fi
fi
done
if [ $err -gt 0 ]; then
	failecho "RSA-DECRYPT-TEST: ${err} errors!"
	exit 1
fi
fi
