#!/bin/bash
#
#    epass2003_rsa_sign_test.sh
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
mechanism2hash () {
	case "${1}" in
	"SHA1-RSA-PKCS"|"SHA1-RSA-PKCS-PSS"|"ECDSA-SHA1")
		echo "sha1";;
	"SHA224-RSA-PKCS"|"SHA224-RSA-PKCS-PSS"|"ECDSA-SHA224")
		echo "sha224";;
	"SHA256-RSA-PKCS"|"SHA256-RSA-PKCS-PSS"|"ECDSA-SHA256")
		echo "sha256";;
	"SHA384-RSA-PKCS"|"SHA384-RSA-PKCS-PSS"|"ECDSA-SHA384")
		echo "sha384";;
	"SHA512-RSA-PKCS"|"SHA512-RSA-PKCS-PSS"|"ECDSA-SHA512")
		echo "sha512";;
	*)
		echo "${1}";;
	esac
}
# return minimal RSA key size for mechanism...
# MyEID card allow us about 40% payload if PKCS1 v1.5 padding is applied...
test_keysize_mechanism () {
	case "${1}" in
	"SHA1-RSA-PKCS")
		echo "768";;	# 20 bytes HASH and 15 bytes digest info = 35 bytes
	"SHA1-RSA-PKCS-PSS")
		echo "512";;	# no PKCS1 padding no 40% limit
	"SHA256-RSA-PKCS")
		echo "1024";;	# 32 bytes HASH and 19 bytes digest info = 51 bytes
	"SHA256-RSA-PKCS-PSS")
		echo "768";;	# no PKCS1 padding, no 40% limit
	"SHA384-RSA-PKCS")
		echo "1536";;	# 48 bytes HASH and 19 bytes digest info = 67 bytes
	"SHA384-RSA-PKCS-PSS")
		echo "1024";;	# no PKCS1 padding, no 40% limit
	"SHA512-RSA-PKCS")
		echo "2048";;	# 64 bytes HASH and 19 bytes digest info = 83 bytes
	"SHA512-RSA-PKCS-PSS")
		echo "1536";;	#  no PKCS1 padding, no 40% limit
	*)
		echo "65536";;
	esac

}

export mode="RSA-SIGN-PKCS11-TEST"
export SCSlot=0
#***************************************************************************************************************************
if [ $mode == "RSA-SIGN-PKCS11-TEST" ]; then
mkdir -p tmp
boldecho "testing RSA signature (pkcs11-tool, several mechanisms)"
boldecho "-------------------------------------------------------"

echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" > tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
dd if=/dev/urandom bs=5000 count=1 >> tmp/rsa_sign_testfile.txt 2>/dev/null

# create hashes (to test PSS)
openssl dgst -sha1  -binary -out tmp/rsa_sign_testfile.txt.sha1 tmp/rsa_sign_testfile.txt
if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
openssl dgst -sha256 -binary -out tmp/rsa_sign_testfile.txt.sha256 tmp/rsa_sign_testfile.txt
if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
openssl dgst -sha384 -binary -out tmp/rsa_sign_testfile.txt.sha384 tmp/rsa_sign_testfile.txt
if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
openssl dgst -sha512 -binary -out tmp/rsa_sign_testfile.txt.sha512 tmp/rsa_sign_testfile.txt
if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
# list all RSA keys

err=0
for keyID in $(pkcs15-tool --list-public-keys|gawk -F: '{if($1 ~ "ModLength"){if(strtonum($2)>=512)OK=1;else OK=0};if($1~"ID" && OK==1){print $2;OK=0}}') ; do
echo "Reading public key "$keyID
pkcs15-tool --read-public-key $keyID |tee tmp/exported_rsa_key.pub
LEN=$(openssl rsa -in tmp/exported_rsa_key.pub -text -noout -pubin |gawk '/Public-Key:/ {print $1}' FPAT='[0-9]+')
if [ "x${LEN}" == "x" ]; then
	exit 1
fi
BITLEN=$LEN
LEN=$[$[$LEN + 7 ] / 8 ]

dd if=tmp/rsa_sign_testfile.txt bs=${LEN} count=1 of=tmp/rsa_sign_testfile_${LEN}.txt 2>/dev/null
# RSA-X-509
echo "using pkcs11 interface to sign message, mechanism RSA-X-509"
rm -f  tmp/rsa_sign_testfile.txt.sign
echo -n "ttt" > tmp/rsa_sign_testfile_short.txt
gawk -b -v LEN=${LEN} '{for(i=0;i<LEN-1-length($0);i++)printf("%c",0);printf("%c%s",0,$0);exit}' tmp/rsa_sign_testfile_short.txt >tmp/rsa_sign_testfile_x509.txt
pkcs11-tool --slot-index ${SCSlot} --sign  -m RSA-X-509\
	--id $keyID \
	--input-file tmp/rsa_sign_testfile_x509.txt \
	--output-file tmp/rsa_sign_testfile.txt.sign \
	--pin ${PIN}
if [ $? -eq 0 ]; then
	echo "testing RSA-X-509 signature (openssl pkeyutl)"
	openssl pkeyutl -pubin -verifyrecover -in tmp/rsa_sign_testfile.txt.sign -inkey tmp/exported_rsa_key.pub -pkeyopt rsa_padding_mode:none -out tmp/rsa_sign_testfile.txt.sign_verify
	if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
	cmp tmp/rsa_sign_testfile_x509.txt tmp/rsa_sign_testfile.txt.sign_verify
	if [ $?	-ne 0 ]; then
		failecho "RSA-X-509 signature fail"
		err=$[$err + 1 ]
		hd tmp/rsa_sign_testfile_x509.txt
		hd tmp/rsa_sign_testfile.txt.sign_verify
	else
		trueecho "Verified OK"
	fi
else
	failecho "pkcs11 fail"
	err=$[$err + 1 ]
fi

# RSA-PKCS
echo "using pkcs11 interface to sign message, mechanism RSA-PKCS"
rm -f tmp/rsa_sign_testfile.txt.sign
rm -f tmp/rsa_sign_testfile.txt.sign_verify1 tmp/rsa_sign_testfile.txt.sign_verify2

echo -n "ttt" > tmp/rsa_sign_testfile_short.txt
pkcs11-tool --slot-index ${SCSlot} --sign  -m RSA-PKCS \
	--id $keyID \
	--input-file tmp/rsa_sign_testfile_short.txt \
	--output-file tmp/rsa_sign_testfile.txt.sign \
	--pin ${PIN}
if [ $? -eq 0 ]; then
	echo "testing RSA-PKCS signature (openssl pkeyutl)"
	#openssl rsautl -raw -verify -pubin -inkey tmp/exported_rsa_key.pub < tmp/rsa_sign_testfile.txt.sign > tmp/rsa_sign_testfile.txt.sign_verify
	openssl pkeyutl -pubin -verifyrecover -in tmp/rsa_sign_testfile.txt.sign -inkey tmp/exported_rsa_key.pub -pkeyopt rsa_padding_mode:none -out tmp/rsa_sign_testfile.txt.sign_verify1
	if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
	# create testfile with padding...
	gawk -b -v LEN=${LEN} '{LEN=LEN-3;LEN=LEN-length($0);printf("%c%c",0,1);for(i=0;i<LEN;i++)printf("%c",255);printf("%c%s",0,$0);exit}' tmp/rsa_sign_testfile_short.txt >tmp/rsa_sign_testfile.txt.sign_verify2
	cmp tmp/rsa_sign_testfile.txt.sign_verify1 tmp/rsa_sign_testfile.txt.sign_verify2
	if [ $?	-ne 0 ]; then
		failecho "RSA-PKCS signature fail"
		err=$[$err + 1 ]
		hd tmp/rsa_sign_testfile.txt.sign_verify1
		hd tmp/rsa_sign_testfile.txt.sign_verify2
	else
		trueecho "Verified OK"
	fi
else
	failecho "pkcs11 fail"
	err=$[$err + 1 ]
fi


for MECHANISM in "SHA1-RSA-PKCS" "SHA256-RSA-PKCS" "SHA384-RSA-PKCS" "SHA512-RSA-PKCS" ; do
RLEN=$(test_keysize_mechanism "${MECHANISM}")
if [ $RLEN -gt $BITLEN ]; then
	continue
fi
echo "using pkcs11 interface to sign message, mechanism ${MECHANISM}"
file_hash=$(mechanism2hash "${MECHANISM}")
rm -f  tmp/rsa_sign_testfile.txt.sign
# use pkcs11-tool to do same as:
# openssl dgst -sha1 -sign _private_key.pem_ --input-file tmp/rsa_sign_testfile.txt --output-file tmp/rsa_sign_testfile.txt.sign
pkcs11-tool --slot-index ${SCSlot} --sign  -m "${MECHANISM}" \
	--id $keyID \
	--input-file tmp/rsa_sign_testfile.txt \
	--output-file tmp/rsa_sign_testfile.txt.sign \
	--pin ${PIN}
if [ $? -eq 0 ]; then
	echo "signature verification (openssl dgst)"
	openssl dgst "-${file_hash}" -verify tmp/exported_rsa_key.pub -signature tmp/rsa_sign_testfile.txt.sign tmp/rsa_sign_testfile.txt >/dev/null
	if [ $?	-ne 0 ]; then
		failecho "openssl signature test fail"
		err=$[$err + 1 ]
	else
		trueecho "Verified OK"
	fi
	echo "signature verification (pkcs11-tool)"
	pkcs11-tool --slot-index ${SCSlot} --verify  -m "${MECHANISM}" --id $keyID --input-file tmp/rsa_sign_testfile.txt --signature-file tmp/rsa_sign_testfile.txt.sign|grep -q "^Signature is valid$"
	if [ $? -ne 0 ]; then
		failecho "pkcs11-tool --verify failed"
		err=$[$err + 1 ]
	else
		trueecho "Verified OK"
	fi

else
	failecho "pkcs11 fail"
	err=$[$err + 1 ]
fi

done	# mechanism loop (no PSS mechanisms)


# test PSS signature
for MECHANISM in "SHA1-RSA-PKCS-PSS" "SHA256-RSA-PKCS-PSS" "SHA384-RSA-PKCS-PSS" "SHA512-RSA-PKCS-PSS" ; do
RLEN=$(test_keysize_mechanism "${MECHANISM}")
if [ $RLEN -gt $BITLEN ]; then
        continue
fi
file_hash=$(mechanism2hash "${MECHANISM}")
rm -f tmp/rsa_sign_testfile.txt.${file_hash}.sign
# use pkcs11-tool to do same operation as:
# openssl pkeyutl -sign \
#	-in tmp/rsa_sign_testfile.txt.sha1 \
#	-inkey _private_key.pem_ -pkeyopt digest:sha1 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 \
#	-out tmp/rsa_sign_testfile.txt.sha1.sign
echo "using pkcs11 interface to sign message, mechanism ${MECHANISM}"
pkcs11-tool --slot-index ${SCSlot} --sign  -m "${MECHANISM}" \
	--id $keyID \
	--input-file tmp/rsa_sign_testfile.txt \
	--output-file tmp/rsa_sign_testfile.txt.${file_hash}.sign \
	--pin ${PIN}
if [ $? -eq 0 ]; then
	openssl pkeyutl -pubin -verify -in tmp/rsa_sign_testfile.txt.${file_hash} \
		 -sigfile tmp/rsa_sign_testfile.txt.${file_hash}.sign \
	         -inkey tmp/exported_rsa_key.pub -pkeyopt rsa_padding_mode:pss \
		 -pkeyopt rsa_pss_saltlen:-1 \
		 -pkeyopt digest:${file_hash}
	if [ $?	-ne 0 ]; then
		failecho "openssl signature test fail"
		err=$[$err + 1 ]
	else
		trueecho "Verified OK"
	fi
	echo "signature verification (pkcs11-tool)"
	pkcs11-tool --slot-index ${SCSlot} --verify  -m "${MECHANISM}" --id $keyID --input-file tmp/rsa_sign_testfile.txt --signature-file tmp/rsa_sign_testfile.txt.${file_hash}.sign|grep -q "^Signature is valid$"
	if [ $? -ne 0 ]; then
		failecho "pkcs11-tool --verify failed"
		err=$[$err + 1 ]
        else
		trueecho "Verified OK"
	fi
else
	failecho "pkcs11 fail"
	err=$[$err + 1 ]
fi
done # mechanism loop (PSS mechanisms)
done    # key loop
if [ $err -gt 0 ]; then
	failecho "RSA-SIGN-PKCS11-TEST: ${err} errors!"
	exit 1
fi
fi
