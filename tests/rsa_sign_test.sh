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

export mode="RSA-SIGN-TEST"
export SCSlot=0

if [ $mode == "RSA-SIGN-TEST" ]; then
mkdir -p tmp
boldecho "testing RSA signature (pkcs15-crypt)"
boldecho "------------------------------------"

echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" > tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
echo "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest" >> tmp/rsa_sign_testfile.txt
dd if=/dev/urandom bs=5000 count=1 >> tmp/rsa_sign_testfile.txt 2>/dev/null


#list all RSA keys 

err=0
for keyID in $(pkcs15-tool --list-public-keys|gawk -F: '{if($1 ~ "ModLength"){if(strtonum($2)>=512)OK=1;else OK=0};if($1~"ID" && OK==1){print $2;OK=0}}') ; do
echo "Reading public key "$keyID
#PKCS15-TOOL --read-public-key $keyID |tee tmp/exported_rsa_key.pub
pkcs15-tool --read-public-key $keyID > tmp/exported_rsa_key.pub
LEN=$(openssl rsa -in tmp/exported_rsa_key.pub -text -noout -pubin |gawk '/Public-Key:/ {print $1}' FPAT='[0-9]+')
if [ "x${LEN}" == "x" ]; then
	exit 1
fi
LEN=$[$LEN / 8 ]
dd if=tmp/rsa_sign_testfile.txt bs=$LEN count=1 of=tmp/rsa_sign_testfile_${LEN}.txt 2>/dev/null

	echo "using pkcs15-crypt to sign RAW message, message length $LEN"
	pkcs15-crypt --pin ${PIN} -k $keyID  -s \
	   -i tmp/rsa_sign_testfile_${LEN}.txt \
	   -o tmp/rsa_sign_testfile_${LEN}.txt.sign
	if [ $? -eq 0 ]; then
		echo "testing signature (openssl pkeyutl)"
		openssl pkeyutl -pubin -verifyrecover \
			-inkey tmp/exported_rsa_key.pub \
			-pkeyopt rsa_padding_mode:none \
			-in tmp/rsa_sign_testfile_${LEN}.txt.sign \
			-out tmp/rsa_sign_testfile_${LEN}.txt.check
		if [ $? -ne 0 ]; then failecho "openssl fail";exit 1;fi
		cmp tmp/rsa_sign_testfile_${LEN}.txt.check tmp/rsa_sign_testfile_${LEN}.txt
		if [ $? -eq 0 ]; then
			trueecho "Verified OK"
		else
			failecho "RAW sign fail "
			err=$[$err + 1 ]
		fi
	else
		failecho "pkcs15-crypt fail"
		err=$[$err + 1 ]
	fi
done
if [ $err -gt 0 ]; then
	failecho "RSA-SIGN-TEST: ${err} errors!"
	exit 1
fi
fi
