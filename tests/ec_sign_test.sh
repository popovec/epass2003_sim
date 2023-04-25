#!/bin/bash
#
#    epass2003_ec_sign_test.sh
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

export mode="EC-SIGN-TEST"
export SCSlot=0

if [ $mode == "EC-SIGN-TEST" ]; then

mkdir -p tmp
boldecho "testing RAW ECDSA (pkcs15-crypt)"
boldecho "--------------------------------"
#pkcs15-tool --list-public-keys|tee /dev/tty |\
pkcs15-tool --list-public-keys|
gawk  -F: '{if($1 ~ "FieldLength")OK=1;if($1~"ID" && OK==1){print $2;OK=0}}' |\
while read keyID ; do
  echo "Reading public key "$keyID
  #pkcs15-tool --read-public-key $keyID |tee tmp/exported_ec_key.pub
  pkcs15-tool --read-public-key $keyID > tmp/exported_ec_key.pub
  openssl ec -inform PEM -pubin -in tmp/exported_ec_key.pub
  if [ $? -ne 0 ]; then
  	failecho "wrong public key"
  	exit 1
  fi
  echo "generating plain sha1 hash file:"
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" > tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  dd if=/dev/urandom bs=5000 count=1 >> tmp/testfile.txt 2>/dev/null

  # we use openssl dgst to verify signature, hash is needed for sign...
  # for some reason, it is necessary to align the input data to 32 bytes 
  # the card driver should do this, but it doesn't
  dd if=/dev/zero count=1 bs=12 > tmp/testfile.txt.sha1 2>/dev/null
  sha1sum tmp/testfile.txt|cut -d ' ' -f 1|xxd -p -r >> tmp/testfile.txt.sha1

  echo "generating RAW ECDSA signature by pkcs15-crypt (input length 32 bytes)"
  warnecho "WARNING, this test only works with input data length of 32 bytes"
  warnecho "(read epass2003_doc/EC.txt)"
  rm -f tmp/testfile.txt.pkcs11.sha1.sig
  ST=$(date +%s.%N)
  pkcs15-crypt  --pin $PIN -k $keyID --signature-format "openssl" -s -i tmp/testfile.txt.sha1 -o tmp/testfile.txt.pkcs11.sha1.sig
  if [ $? -ne 0 ]; then
	failecho "pkcs15-crypt failed"
	exit 1
  fi
  ET=$(date +%s.%N)
  echo "${ET} ${ST}"|gawk '{printf "pkcs15-tool EC SIGN time %f\n",($1 - $2)}'
  echo "testing signature (openssl dgst)"
  openssl dgst -sha1 -verify tmp/exported_ec_key.pub -signature tmp/testfile.txt.pkcs11.sha1.sig tmp/testfile.txt >/dev/null
  if [ $? -ne 0 ]; then
	failecho "openssl signature test fail"
	exit 1
  fi
  trueecho "OK"
done # key loop
fi


export mode="EC-SIGN-PKCS11-TEST"

if [ $mode == "EC-SIGN-PKCS11-TEST" ]; then
mkdir -p tmp
boldecho "testing ECDSA (pkcs11-tool, several mechanisms)"
boldecho "-----------------------------------------------"

ECC_SIZE_TEST=$(pkcs11-tool --slot-index ${SCSlot} -M 2>/dev/null)
ECC_SIZE_MAX=0
echo ${ECC_SIZE_TEST}|grep -q -F -e 'ECDSA-SHA1' && ECC_SIZE_MAX=256
if [ $ECC_SIZE_MAX -eq 0 ]; then warnecho "card does not support EC funcfions";exit 0;fi
echo ${ECC_SIZE_TEST}|grep -q -F -e 'ECDSA-SHA1, keySize={192,384}' && ECC_SIZE_MAX=384
echo ${ECC_SIZE_TEST}|grep -q -F -e 'ECDSA-SHA1, keySize={192,521}' && ECC_SIZE_MAX=521

pkcs15-tool --list-public-keys|\
gawk -v SIZE=$ECC_SIZE_MAX -F: '{if($1 ~ "FieldLength"){if(strtonum($2)<=SIZE){OK=1;fl=$2}else OK=0}if($1~"ID" && OK==1){print $2" "fl;OK=0}}' |\
while read keyID fl; do
  bfl=$[$fl + 7 ]
  bfl=$[bfl / 8 ]
  echo "Reading public key ${keyID}  field length=${fl} (${bfl} bytes)"

  pkcs15-tool --read-public-key $keyID > tmp/exported_ec_key.pub

  echo "pkcs11-tool sign and pkcs11-tools --verify"

  echo -n "testtesttesttesttesttesttesttesttest" > tmp/testfile.txt
  rm -f tmp/testfile.txt.pkcs11.sig
  ST=$(date +%s.%N)
  pkcs11-tool --slot-index ${SCSlot} --pin ${PIN} --sign  -m ECDSA --signature-format "sequence" --input-file tmp/testfile.txt --output-file tmp/testfile.txt.pkcs11.sig --id $keyID
  if [ $? -ne 0 ]; then
	failecho "pkcs11-tool failed"
	exit 1
  fi
  ET=$(date +%s.%N)
  echo "${ET} ${ST}"|gawk '{printf "pkcs11-tool EC SIGN time %f\n",($1 - $2)}'

  pkcs11-tool --slot-index ${SCSlot} --verify -m ECDSA  --signature-format "sequence" --input-file tmp/testfile.txt --signature-file tmp/testfile.txt.pkcs11.sig --id $keyID|grep -q "^Signature is valid$"
  if [ $? -ne 0 ]; then
	failecho "pkcs11-tool signature test fail"
	exit 1
  else
	trueecho "Verified OK"
  fi

  echo "pkcs11-tool sign and openssl verify"
  # we using openssl dgst we need to sign digest ..
  echo "generating plain sha1 hash file:"
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" > tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/testfile.txt
  dd if=/dev/urandom bs=5000 count=1 >> tmp/testfile.txt 2>/dev/null
  # we use openssl dgst to verify signature, hash is needed for sign...
  sha256sum tmp/testfile.txt|cut -d ' ' -f 1|xxd -p -r > tmp/testfile.txt.sha256

  rm -f tmp/testfile.txt.pkcs11.sha256.sig
  echo "generating RAW ECDSA signature by pkcs11-tool $bfl"
  rm -f tmp/testfile.txt.pkcs11.sha256.sig
  pkcs11-tool --slot-index ${SCSlot} --pin ${PIN} --sign  -m ECDSA --signature-format "openssl" --input-file tmp/testfile.txt.sha256 --output-file tmp/testfile.txt.pkcs11.sha256.sig --id $keyID
  if [ $? -ne 0 ]; then
	failecho "pkcs11-tool failed"
	exit 1
  fi
  echo "testing signature.. (openssl)"
  openssl dgst -sha256 -verify tmp/exported_ec_key.pub -signature tmp/testfile.txt.pkcs11.sha256.sig tmp/testfile.txt >/dev/null
  if [ $? -ne 0 ]; then
	failecho "openssl signature test fail"
	exit 1
  else
	trueecho "Verified OK"
  fi

  for d in sha1 sha224 sha256 sha384 sha512 ; do
  	ignore=0
	D=$(echo ${d}|tr '[[:lower:]]' '[[:upper:]]')
  	case $d in
  		sha224|sha384|sha512)
  		warnecho "Warning, ignoring error for ECDSA-$D, seems this is not working (more info in  epass2003_doc/EC.txt)"
  			ignore=1 
  		;;
  		*)
  		;;
  	esac	
	rm -f tmp/testfile.txt.pkcs11.${d}.sig
	# pkcs11 operation corresponds to:
	# openssl dgst -sha1 -sign keys/secp384r1-key.pem -out tmp/testfile.txt.pkcs11.sha1.sig tmp/testfile.txt
	pkcs11-tool --slot-index ${SCSlot} --pin 1234 --sign --signature-format "openssl" -m ECDSA-${D} --input-file tmp/testfile.txt --output-file tmp/testfile.txt.pkcs11.${d}.sig --id $keyID
	if [ $? -ne 0 ]; then
		failecho "pkcs11-tool failed"
		[ $ignore != 0 ]||exit 1
	fi
	echo "testing ECDSA-${D} signature (openssl dgst)"
	openssl dgst -${d} -verify tmp/exported_ec_key.pub -signature tmp/testfile.txt.pkcs11.${d}.sig tmp/testfile.txt >/dev/null
	if [ $? -ne 0 ]; then
		failecho "openssl signature test fail"
		[ $ignore != 0 ]||exit 1
	else
		trueecho "Verified OK"
	fi
	echo "testing ECDSA-${D} signature.. (pkcs11-tool)"
	pkcs11-tool --slot-index ${SCSlot} --verify  --signature-format "openssl" -m ECDSA-${D} --id $keyID --input-file tmp/testfile.txt --signature-file tmp/testfile.txt.pkcs11.${d}.sig|grep -q "^Signature is valid$"
	if [ $? -ne 0 ]; then
		failecho "pkcs11-tool --verify failed"
		[ $ignore != 0 ]||exit 1
	else
		trueecho "Verified OK"
	fi
  done # digest loop
done # key loop
exit $?
fi
