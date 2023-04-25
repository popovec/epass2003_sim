/*
    epass2003_emu.c

    In March 2023, this file was derived from the OsEID project.
    https:/oseid.sourceforge.io
    https://github.com/popovec/oseid

    This is part of epass2003 simulator.
    
    Copyright (C) 2015-2023 Peter Popovec, popovec.peter@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/** @file
 *  @brief Emulation of epass2003 functions
 */
/*

 Functions are derived from opensc sources https://github.com/OpenSC/OpenSC - card-epass2003.c

*/

#define DEBUG_MyEID_EMU
#include "debug.h"

#define C_DES 0
#define C_AES 1
#define C_AES_FIPS 2
// epass2003 emulation:
#define SM_CRYPT C_AES
// AES_FIPS, AES, DES
#ifndef SM_CRYPT
#define SM_CRYPT C_AES
#endif

// use predefined RANDOM muber for key exchange (for debug purposes)
#define FIXED_RANDOM

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <alloca.h>
#include "card_io.h"
#include "ec.h"
#include "iso7816.h"
#include "fs.h"
#include "key.h"
#include "rsa.h"
#include "des.h"
#include "aes.h"
#include "constants.h"
#include "bn_lib.h"
#include "mem_device.h"

#define M_CLASS message[0]
#define M_CMD message[1]
#define M_P1 message[2]
#define M_P2 message[3]
#define M_P3 message[4]

#if RSA_BYTES > 128
#error RSA_BYTES over 128, for atmega only 256 byte buffers are reserved!
#endif

#ifndef I_VECTOR_MAX
#define I_VECTOR_MAX 16
#endif
static uint8_t sec_env_reference_algo __attribute__((section(".noinit")));
static uint16_t key_file_uuid __attribute__((section(".noinit")));
static uint16_t target_file_uuid __attribute__((section(".noinit")));
static uint8_t i_vector[I_VECTOR_MAX] __attribute__((section(".noinit")));
static uint8_t i_vector_len __attribute__((section(".noinit")));

// bits 0,1 = template in environment (depend on ISO7816-8, manage secutiry env, P2 (P2>>1)&3
#define SENV_TEMPL_CT 0
#define SENV_TEMPL_AT 2
#define SENV_TEMPL_DST 3
#define SENV_TEMPL_MASK 3

// mask for encipher operation
#define SENV_ENCIPHER    0x04
// mask for valid file reference
#define SENV_FILE_REF    0x10
// mask for valir reference algo
#define SENV_REF_ALGO    0x20
// mask for valid init vector
#define SENV_INIT_VECTOR 0x40
// mask for valid  target ID
#define SENV_TARGET_ID 	 0x80

uint8_t sec_env_valid __attribute__((section(".noinit")));

////////////////////////////////////////////////////////////////////////////////////
//  base helpers

static void reverse_string(uint8_t * p, uint16_t len)
{
	uint8_t *t, tmp;

	t = p + len - 1;
	len /= 2;
	while (len--) {
		tmp = *p;
		*p = *t;
		*t = tmp;
		t--;
		p++;
	}
}

static void reverse_copy(uint8_t * d, uint8_t * s, uint16_t len)
{
	s += len - 1;
	while (len--) {
		*d = *s;
		s--;
		d++;
	}
}

////////////////////////////////////////////////////////////////////////////////////
//  base helpers for key manipulation/checks
//

// 0xffff = error
static uint16_t get_key_file_uuid(uint16_t id)
{
	uint16_t old_uuid;
	uint16_t uuid;

	old_uuid = fs_get_selected_uuid();
	if (S0x6100 != fs_select_ef(id, NULL))
		return 0xffff;
	uuid = fs_get_selected_uuid();
	fs_select_uuid(old_uuid, NULL);
	return uuid;
}

// target pointer must allow store RSA_BYTES of bytes
uint8_t get_rsa_key_part(void *here, uint8_t id)
{
	uint16_t part_size;
	uint8_t *key = here;

	memset(key, 0, RSA_BYTES);
	part_size = fs_key_read_part(NULL, id);
	if (part_size > RSA_BYTES)
		return 0;
	fs_key_read_part(key, id);
	return part_size;
}

// do sign/decrypt with selected key, return 0 if error,
// or len of returned message (based on key size).
// input length of message, message, result after sign/decrypt
// WARNING, message and result buffers must hold 256 bytes!
// flag 0 - raw data, must match key size
// flag 1 - add OID of SHA1 before message, then add padding..
// flag 2 - add padding only (type 01), SHA1 digest is in message
static uint16_t rsa_raw(uint16_t len, uint8_t * message, uint8_t * result, uint8_t flag)
{
	uint16_t part_size;
	uint8_t ret;

	DPRINT("message first byte 0x%02x size %d\n", *message, len);

	reverse_string(message, len);	// number from message
	if (len < RSA_BYTES)
		memset(message + len, 0, RSA_BYTES * 2 - len);

	HPRINT("reversed message =\n", message, RSA_BYTES * 2);

	// test if key match data size
	part_size = fs_key_read_part(NULL, KEY_RSA_p);
	part_size *= 2;		// calculate message size

	DPRINT("key modulus: %d, message len: %d flag: %d\n", part_size, len, flag);
	if (flag == 0) {
		if (len != part_size)
			return 0;
	}
	if (flag == 1) {
		DPRINT("adding SHA1 OID to message\n");
// this test is not needed, minimal key modulus is 512 bit
/*
      if (len + 15 > part_size)
	return 0;
*/
		// SHA1 need 20 bytes len message exact
		if (len != 20)
			return 0;
		// add sha1 oid before message
		get_constant(message + len, N_PSHA1_prefix);

		reverse_string(message + len, 15);
		flag = 2;
		len += 15;

		HPRINT("reversed message with SHA1 OID=\n", message, RSA_BYTES * 2);
	}
	if (flag == 2) {
		DPRINT("adding padding type 1 size of modulus %d, message size %d\n",
		       part_size, len);
// add padding- type 1 (00 01 [FF .. FF] 00 .. minimal 8 bytes 0xff
// MyEID manual 2.1.4:  Size of the DigestInfo must not exceed 40% of the RSA key modulus length.
		if (len + 11 > part_size)
			return 0;
		message[len] = 0;
		len++;
		while (len < part_size)
			message[len++] = 0xff;
		message[part_size - 1] = 0x00;
		message[part_size - 2] = 0x01;
		flag = 0;
	}
	// check unknown padding
	if (flag != 0)
		return 0;

	HPRINT("message\n", message, RSA_BYTES * 2);

	DPRINT("calculating RSA\n");
	ret = rsa_calculate(message, result, len / 2);

	if (ret) {
// prevent sensitive data
		DPRINT("RSA fail clearing buffers\n");
		memset(message, 0, 256);
		memset(result, 0, 256);
		return 0;
	}
	DPRINT("RSA ok, reversing\n");
	reverse_string(result, part_size);
	DPRINT("return size %d\n", part_size);
	return part_size;
}

// for NIST curves and for secp256k1 A is not needed
// Special values of A (A=0, A=-3) are indicated in the c->curve_type
// (A and B is needed for ECDH operation to check if point is on curve)

// size 24/32/48 for ecc 192,256/384 bis, id 0 get key from selected file and use
// key size to setup ec parameters
static uint8_t prepare_ec_param(struct ec_param *c, ec_point_t * p, uint8_t size)
{
	uint16_t ret;
	uint8_t var_C;

	memset(c, 0, sizeof(struct ec_param));

	// ACL and file existence is checked in fs_key_read, return value can be used to select
	// 192/256/384 key algo

	if (size == 0) {
		ret = fs_key_read_part(NULL, KEY_EC_PRIVATE);
		if (ret > MP_BYTES)
			return 0;
		// c->working_key size is MP_BYTES, not overrun...
		// coverity[overrun-buffer-val]
		if (ret != fs_key_read_part((uint8_t *) & c->working_key, KEY_EC_PRIVATE))
			return 0;
	} else
		ret = size;
/*
#ifndef NIST_ONLY
	if (fs_get_file_type() == EC2_KEY_EF) {
		var_C = C_SECP256K1 | C_SECP256K1_MASK;
	} else
#endif
	{
		if (ret == 24) {
			var_C = C_P192V1 | C_P192V1_MASK;
		}
#if MP_BYTES >= 32
		else if (ret == 32) {
			var_C = C_P256V1 | C_P256V1_MASK;
		}
#endif
#if MP_BYTES >= 48
		else if (ret == 48) {
			var_C = C_SECP384R1 | C_SECP384R1_MASK;
		}
#endif
#if MP_BYTES >= 66
		else if (ret == 66) {
			var_C = C_SECP521R1 | C_SECP521R1_MASK;
		}
#endif
		else
			return 0;
	}
*/
	var_C = C_P256V1 | C_P256V1_MASK;
	//ret = 32;
	c->curve_type = var_C;
	var_C &= 0x3f;
	if (p) {
		memset(p, 0, sizeof(ec_point_t));
		get_constant((uint8_t *) & (p->X), var_C + 5);
		get_constant((uint8_t *) & (p->Y), var_C + 6);
	}
	get_constant(&c->prime, var_C + 1);
	get_constant(&c->order, var_C + 2);
	get_constant(&c->a, var_C + 3);
	get_constant(&c->b, var_C + 4);

	reverse_string((uint8_t *) & c->working_key, ret);
	c->mp_size = ret;

	return ret;
}

// return error code if fail, or response if ok
static uint8_t sign_ec_raw(uint8_t * message, struct iso7816_response *r, uint16_t size)
{
#if MP_BYTES > 48
	ecdsa_sig_t *e = alloca(sizeof(ecdsa_sig_t));
	struct ec_param *c = alloca(sizeof(struct ec_param));
#else
// reuse "message" buffer for ecdsa_sig_t (warning, this is really only for max 48 bytes in bignum_t)
	ecdsa_sig_t *e = (ecdsa_sig_t *) (message + sizeof(bignum_t));
// reuse result buffer for ec_param structure
	struct ec_param *c = (struct ec_param *)r->data;
#endif
	uint16_t ret;

	DPRINT("%s\n", __FUNCTION__);

	// prepare Ec constant, use size based on key  (key from selected file)
	// generator point into e->signature
	ret = prepare_ec_param(c, &e->signature, 0);
	if (ret == 0) {
		DPRINT("Error, unable to get EC parameters/key\n");
		return S0x6985;
	}

	if (ret < size)
		return S0x6700;	// Incorrect length

	// message to number
	reverse_string(message, size);

	// pad message to match key length

	if (size < sizeof(bignum_t))
		memset(message + size, 0, sizeof(bignum_t) - size);
	HPRINT("message =\n", message, ret);
	HPRINT("working key:\n", c->working_key.value, ret);
	HPRINT("prime:\n", c->prime.value, ret);
	HPRINT("a:\n", c->a.value, ret);
	HPRINT("b:\n", c->b.value, ret);
	HPRINT("order:\n", c->order.value, ret);
	DPRINT("size: %d\n", c->mp_size);
	DPRINT("type: %d\n", c->curve_type);

	DPRINT("SIGN ...\n");
	if (ecdsa_sign(message, e, c)) {
		DPRINT("SIGN FAIL\n");
		return S0x6985;
	}
	DPRINT("SIGN OK, generating response\n");
	HPRINT("SIGNATURE R:\n", e->R.value, ret);
	HPRINT("SIGNATURE S:\n", e->S.value, ret);

	DPRINT("size=%d\n", c->mp_size);
	reverse_copy(&r->data[0], e->R.value, 32);
	reverse_copy(&r->data[32], e->S.value, 32);
	DPRINT("EC signature OK\n");
	RESP_READY(64);
}

// EPASS2003 RSA decrypt
// 00 22 41 B8 07 
//      80 01 84 
//      81 02 29 00
//
// EC  sign
// 00 22 41 B6
//     80 01 92
//     81 02 29 20
// SHA1:
// 00 22 41 B6 07
//      80 01 91
//      81 02 29 00
uint8_t security_env_set_reset(uint8_t * message, __attribute__((unused))
			       struct iso7816_response *r)
{
	uint16_t tagval;
	uint8_t xlen, *data;;
	uint8_t tag;
	uint8_t taglen;
	uint8_t s_env = 0;

// invalidate sec env
	sec_env_valid = 0;

// this is used to initialize sec_env_valid after reboot
	if (message == NULL)
		return 0;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	DPRINT("sec env operation: %1x ", M_P1 & 15);
	DPRINT("%s", (M_P1 & 15) == 1 ? "set" : "");
	DPRINT("%s", (M_P1 & 15) == 2 ? "store" : "");
	DPRINT("%s", (M_P1 & 15) == 3 ? "restore" : "");
	DPRINT("%s", (M_P1 & 15) == 4 ? "erase" : "");
	DPRINT("\n");

	// X3h = restore, FXh = all sec env (for sec messaging and for enciph/deciph)
	if (M_P1 == 0xf3) {
		DPRINT("%s, Restore security environment %02X\n", __FUNCTION__, M_P2);
		if (M_P3 != 0 || M_P2 != 0) {
			DPRINT("%s lc/le not 0 ? \n", __FUNCTION__);
			return S0x6a87;	// len inconsistent with P1
		}
		return (S_RET_OK);
	}
#if 0
// MyEID manual 2.1.4: P1 must be set to 0xA4 for ECDH, but opensc 0.17 set
// this to 0x41 and P2 is set to 0xA4 ..  allow A4 here too
// this violates ISO (A4 = erase sec env for sec messaging an verification..)
// (this seems to be a typo error in MyEID manual, A4 is for auth teplate..)
	if (M_P1 == 0xA4) {
		M_P1 = 0x41;
		M_P2 = 0xA4;
	}
#endif
// ISO: bit 0x80 = decipher, sign, unwrap etc..  operation with private key
// ISO: bit 0x40 = encripher, wrap ..
// allow only set sec env. (only bits bits 7,6 and 0 are allowed)

// for LC==0  this function fails in code below

// encipher operation
	if (M_P1 == 0x81) {
		// allowed template CT only!
		if (M_P2 != 0xb8)
			return S0x6985;	//    Conditions not satisfied
		s_env |= SENV_ENCIPHER;
		DPRINT("encipher requested, s_env=%02x\n", s_env);
	} else if (M_P1 == 0x41) {
		switch (M_P2) {
			// check teplate type
		case 0xB8:
		case 0xB6:
		case 0xA4:
			s_env |= (M_P2 >> 1) & 3;
			DPRINT("decipher requested, s_env=%02x\n", s_env);
			break;
		default:
			// unknown template
			return S0x6985;	//    Conditions not satisfied
		}
	} else
		return S0x6a81;	//Function not supported // change to wrong arg ?

	// Empty or concatenation of Control Reference Data Objects (CRDO)
	xlen = M_P3;
	data = message + 5;
	for (;;) {
		if (!(xlen--))
			break;
		tag = *(data++);
		if (tag == 0 || tag == 0xff)
			continue;
		if (!(xlen--))
			break;
		taglen = *(data++);
		if (taglen > 16)
			return S0x6984;	//maximal tag size is 16 (init vector)
		if (xlen < taglen)	// not enough data in buffer (to match taglen)
			return S0x6984;	//invalid data
		tagval = *data;
		if (taglen == 2)
			tagval = (tagval << 8) | *(data + 1);
		switch (tag) {
		case 0x80:
			if (taglen != 1)
				return S0x6a81;	//Function not supported      // change to wrong arg ?
			DPRINT("reference algo=%02x\n", tagval);
			switch (tagval) {
			case 0x84:	// epass2003 RSA decipher
			case 0x92:	// epass2003 EC sign operation (SHA256 or raw ECDSA)
			case 0x91:	// epass2003 EC sign operation (SHA1 in message)
				break;
			default:
				return S0x6a81;	//Function not supported // change to wrong arg ?
			}
			sec_env_reference_algo = tagval;	//=[D;// *data;
			s_env |= SENV_REF_ALGO;
			DPRINT("ref algo defined s_env=%02x\n", s_env);
			break;
		case 0x81:
			if (taglen != 2)
				return S0x6a81;	//Function not supported      // change to wrong arg ?
			DPRINT("KEY file ID=%04x\n", tagval);
			key_file_uuid = get_key_file_uuid(tagval);
			if (key_file_uuid == 0xffff)
				return S0x6a88;	//    Reference data not found
			s_env |= SENV_FILE_REF;
			DPRINT("added file reference s_env=%02x\n", s_env);

			break;
		case 0x83:	// MyEID requeres this for AES!
		case 0x84:
			if (taglen == 2)	// TARGET FILE ID (for UNWRAP)
			{
				DPRINT("target file ID=%04x\n", tagval);
				target_file_uuid = get_key_file_uuid(tagval);
				if (target_file_uuid == 0xffff)
					return S0x6a88;	//    Reference data not found
				s_env |= SENV_TARGET_ID;
				DPRINT("added target file reference s_env=%02x\n", s_env);
			} else if (taglen == 1) {
				DPRINT("reference for key=%d\n", *data);
				if (*data != 0) {
					// MyEID support only one key per file, then this reference must be 0
					return S0x6a81;	//Function not supported // change to wrong arg ?
				}
			} else
				return S0x6a81;	//Function not supported // change to wrong arg ?
			break;
		case 0x87:
			// maximal taglen 16 is already checked
			i_vector_len = taglen;
			memcpy(i_vector, data, taglen);
			s_env |= SENV_INIT_VECTOR;
			break;
		default:
			return S0x6a80;	// incorrect parameters in the data field / wrong data
		}
		xlen -= taglen;
		data += taglen;
	}
	// minimum template - reference algo and file
	if ((s_env & (SENV_FILE_REF | SENV_REF_ALGO))
	    != (SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("not all env variables present = %02x\n", s_env);
		return S0x6a81;	//Function not supported // change to wrong arg ?
	}
	DPRINT("Final s_env=%02x\n", s_env);
	sec_env_valid = s_env;
	return S_RET_OK;
}

static uint8_t security_operation_rsa_ec_sign(struct iso7816_response *r)
{
	uint8_t flag;
	uint16_t size = r->Nc;
	DPRINT("%s reference algo %d\n", __FUNCTION__, sec_env_reference_algo);
// is security environment set to sign ?
	if ((sec_env_valid &
	     (SENV_TEMPL_MASK | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) !=
	    (SENV_TEMPL_DST | SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("invalid sec env - no DTS teplate or encipher defined (%02x)\n",
		       sec_env_valid);
		DPRINT("sec env %02x\n", sec_env_valid);
		DPRINT("mask %02x\n",
		       SENV_TEMPL_MASK | SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO);
		DPRINT("To:  %02x\n", SENV_TEMPL_DST | SENV_FILE_REF | SENV_REF_ALGO);
		return S0x6985;	//    Conditions not satisfied
	}
	if (!r->Nc)
		return S0x6700;
	DPRINT("sec environment %0x2 valid sign algo = 0x%02x, message len %d key uuid %04x\n",
	       sec_env_valid, sec_env_reference_algo, size, key_file_uuid);

	// Wait for full APDU if chaining is active
	if (r->chaining_state & APDU_CHAIN_RUNNING) {
		DPRINT("APDU chaining is active, waiting more data\n");
		return S_RET_OK;
	}
	// this is  long operation, start sending NULL
	card_io_start_null();

// SIGN operation possible values for reference algo: 0,2,4,0x12
	if (sec_env_reference_algo == 0x91) {
		DPRINT("RAW-ECDSA-PKCS algo %02x\n", sec_env_reference_algo);
		// in buffer SHA1 hash
		return sign_ec_raw(r->input + 5, r, size);
	} else if (sec_env_reference_algo == 0x92) {
		DPRINT("RAW-ECDSA-PKCS algo %02x\n", sec_env_reference_algo);
		// in buffer RAW data to be signed
		return sign_ec_raw(r->input + 5, r, size);
	} else if (sec_env_reference_algo == 2) {
		DPRINT("Digest Info data in packet\n");
		flag = 2;
	} else if (sec_env_reference_algo == 0x12) {
		DPRINT("SHA1 message in buffer\n");
		flag = 1;
	} else if (sec_env_reference_algo == 0) {
		DPRINT("RAW message in buffer\n");
		flag = 0;
	} else
		return S0x6985;	//    Conditions not satisfied

	size = rsa_raw(size, r->input + 5, r->data, flag);
//  DPRINT ("RSA calculation %s, returning APDU\n", size ? "OK":"FAIL");
	if (size != 0) {
		DPRINT("RSA sign OK\n");
		RESP_READY(size);
	}
	return S0x6985;		//    Conditions not satisfied
}

static uint8_t decipher(struct iso7816_response *r)
{
	uint16_t size;
	uint8_t *message = r->input;

	DPRINT("%s\n", __FUNCTION__);

// RSA decipher - P2 0x84 CT in data field, 0x86 padding + CT in data field
// P2 is already checked, (0x84 or 0x86 ) in security_operation()
	size = r->Nc;
	message += 5;

	DPRINT("All data available (%d bytes), running security OP\n", size);
	// ok all data concatenated, do real OP

// RSA decrypt, and optional padding remove
	card_io_start_null();
	size = rsa_raw(size, message, r->data, 0);

	if (size == 0) {
		DPRINT("decrypt fail\n");
		return S0x6985;	// command not satisfied
	}
// 0x0a UNWRAP, 0x02 decipher, in both cases remove PKCS#1 padding
	if ((sec_env_reference_algo & 2) == 2) {
		// return error for not correct padding
		// allowed padding is: 00 || 02 || random data[8+] || 00 || real data
		DPRINT("requested padding remove operation, (message len %d)\n", size);
		if (r->data[0] == 0 && r->data[1] == 2 && size > 11) {
			uint8_t *padd = r->data + 2;
			uint16_t s = size - 3;

			for (; s > 0; s--, padd++)
				if (*padd == 0) {
					if (padd < r->data + 10) {
						DPRINT
						    ("Wrong padding, below 8 bytes of random data\n");
						return S0x6985;	// command not satisfied
					}
					memcpy(r->data, padd + 1, s);
					size = s;
					DPRINT("padding removed, (message len %d)\n", size);
					break;
				}
			if (!s) {
				DPRINT("Wrong padding, no 0x00 found after random padding data\n");
				return S0x6985;	// command not satisfied
			}
		} else {
			DPRINT("Unknown padding, %02x %02x,\n", r->data[0], r->data[1]);
			return S0x6985;	// command not satisfied
		}
	}
	HPRINT("return message =\n", r->data, size);
	RESP_READY(size);
}

static uint8_t epass2003_security_operation_decrypt(struct iso7816_response *r)
{
	uint8_t ret;

	DPRINT("%s\n", __FUNCTION__);

	if ((sec_env_valid & (SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO))
	    == (SENV_ENCIPHER | SENV_FILE_REF | SENV_REF_ALGO)) {
		DPRINT("sec environment %02x valid sign algo = 0x%02x\n",
		       sec_env_valid, sec_env_reference_algo);
		DPRINT("security env not valid\n");
		return S0x6985;	//    Conditions not satisfied
	}
	if (!r->Nc)
		return S0x6700;
	ret = decipher(r);
	return ret;
}

/*
$ pkcs15-init --generate-key rsa/1024 --user-consent 1 --auth-id 1 --pin 11111111 --label UC1
FCI ..  85 02 11 00 - deauth PIN1
//$ pkcs15-init --generate-key rsa/1024 --user-consent 0 --auth-id 1 --pin 11111111 --label UC0
FCI ... 85 02 01 00 - no deauth
*/

static void select_back_and_deauth(uint16_t uuid)
{
	uint8_t auth_id;

	auth_id = (fs_get_file_proflag() >> 12);
	// if here is 0, do not call fs_deauth() - it would deauth all PINs
	if (auth_id)
		fs_deauth(auth_id);

	fs_select_uuid(uuid, NULL);	// select back old file
}

// EPASS2003  RSA DECRYPT (2048 bits):
// 00 2A 80 86         00 01 22  <-- Lc field 290 bytes (SM data), Lc for raw APDU = ??? 256 ??? bytes
//       ^  ^--- padding content indocator followed by cryptogram (plain cryptogram not BER TLV)
//       +------ output from PSO - plain data
//
// 00 2A 9E 9A  EC sign,  LC = 20 for SHA1 input, for any other input  LC = 32

uint8_t security_operation(uint8_t * message, struct iso7816_response *r)
{
	uint16_t uuid;
	uint8_t op, ret_data;
	uint8_t ret = S0x6a86;	// Incorrect parameters P1-P2

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	op = M_P1;
	ret_data = M_P2;
	uuid = fs_get_selected_uuid();	// save old selected file
	if (op == 0x80 && ret_data == 0x86) {
		fs_select_uuid(key_file_uuid, NULL);
		ret = epass2003_security_operation_decrypt(r);
	}

	if (op == 0x9E && ret_data == 0x9A) {
		fs_select_uuid(key_file_uuid, NULL);
		ret = security_operation_rsa_ec_sign(r);
		DPRINT("security_operation_rsa_ec_sign ret=%d (len=%d)\n", ret, r->len16);
	}
	select_back_and_deauth(uuid);
	DPRINT("security operation: return code %d (len=%d)\n", ret, r->len16);
	return ret;
}

/*
Epass2003 APDU:

SM APDU:
0C 46 00 00 1D 
   87 11 01    FF 5E 86 28 F1 B2 D1 E6 05 5D 10 92 67 AD D5 07	< encoded data field
   8E 08 12    98 B3 3E 7E E2 8B 05 00				< MAC

Decoded APDU:
 00 46 00 00 07         01              01 if len != 256, 02 if len = 256 (this seems to be EC key) 
                        08 00           len (2048)
                        29 00           file ID private key
                        30 00           file ID public key
// Le is missing

ISO/IEC 7816-8:219(E) Table 1:

INS = 46
P1 = 0, P2 = 0 no information is given, if Nc > 0 the data field contain proprietary data.
If Le is present, (Ne > 0), public key as sequence of data elements is returned.

TODO: This code does not return any data if Le is present!
*/

static uint8_t epass2003_store_rsa_key(rsa_num pq[2], uint16_t k_size, uint8_t flags)
{
// 0 = d
// 1 = dP
// 2 = dQ
// 3 = qInv
// 4 = inv P (half length)
// 5 = barret constant P
// 6 = inv Q (half length)
// 7 = barret constant Q
	struct {
		uint8_t type;
		uint8_t size;
#ifndef USE_P_Q_INV
		rsa_num crt_comp[4];
#else
		rsa_num crt_comp[8];
#endif
	} key_part;

	rsa_crt_components(pq, key_part.crt_comp, k_size);

#ifdef USE_P_Q_INV
	key_part.size = k_size / 2;
	key_part.type = KEY_RSA_p | 0x20 | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[4], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write P inv\n");
		return 1;
	}
	key_part.type = KEY_RSA_q | 0x20 | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[6], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write P inv\n");
		return 1;
	}
	key_part.size = k_size;
	key_part.type = KEY_RSA_p | 0x30 | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[5], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write P inv\n");
		return 1;
	}
	key_part.type = KEY_RSA_q | 0x30 | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[7], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write P inv\n");
		return 1;
	}
#else
	key_part.size = k_size;
#endif
	memcpy(&key_part.crt_comp[0], &pq[0], RSA_BYTES);
	key_part.type = KEY_RSA_p | flags;
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write P\n");
		return 1;
	}
	key_part.type = KEY_RSA_q | flags;
	memcpy(&key_part.crt_comp[0], &pq[1], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write Q\n");
		return 1;
	}
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[1], RSA_BYTES);
	key_part.type = KEY_RSA_dP | flags;
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write dP\n");
		return 1;
	}
	key_part.type = KEY_RSA_dQ | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[2], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write dQ\n");
		return 1;
	}
	key_part.type = KEY_RSA_qInv | flags;
	memcpy(&key_part.crt_comp[0], &key_part.crt_comp[3], RSA_BYTES);
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write qInv\n");
		return 1;
	}
	key_part.type = KEY_RSA_EXP_PUB;
	key_part.size = 3;
	if (S_RET_OK != fs_key_write_part((uint8_t *) & key_part)) {
		DPRINT("Unable to write public_exponent\n");
		return 1;
	}
	return 0;
}

uint8_t epass2003_generate_key(uint8_t * message, struct iso7816_response *r)
{
	uint16_t k_size;
	uint16_t old_uuid;
	uint16_t id, id_pub;
	uint16_t ret;
	struct rsa_crt_key key;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 0 || M_P2 != 0 || message[4] != 7)
		return S0x6a86;	//Incorrect parameters P1-P2

	old_uuid = fs_get_selected_uuid();
	id = (message[8] << 8) + message[9];
	id_pub = (message[10] << 8) + message[11];
	DPRINT("private key file: %04x public key file: %04x\n", id, id_pub);

	// EC key .. 
	k_size = (message[6] << 8) + message[7];
	if (message[5] == 2) {
		if (k_size != 256)
			return S0x6984;	//invalid data  

		struct pub_key {
			ec_point_t key;
			uint8_t type;
			uint8_t size;
			uint8_t ui;	// for 0x04 = indicate uncompressed key
			uint8_t key_bytes[2 * sizeof(bignum_t)];
		};

		fs_select_ef(id, NULL);
		// reuse r->data and message for ec param structure and for pub_key structure
#if MP_BYTES > 96
#error MP_BYTES over 96, check all reused RAM spaces
#endif
		struct pub_key *pub_key = (struct pub_key *)r->data;
#if MP_BYTES > 48
		struct ec_param *c = alloca(sizeof(struct ec_param));
#else
		struct ec_param *c = (struct ec_param *)(message);
#endif

		card_io_start_null();

		DPRINT("Generating key, selected file 0x%04x, key size %d bits\n",
		       fs_get_selected(), k_size);

		if (0 == prepare_ec_param(c, &(pub_key->key), (k_size + 7) / 8)) {
			DPRINT("Wrong EC parameteres\n");
			return S0x6985;	//    Conditions not satisfied
		}
		if (ec_key_gener(&(pub_key->key), c)) {
			DPRINT("Key wrong\n");
			return S0x6985;	//    Conditions not satisfied
		}
		HPRINT("key data\n", r->data, sizeof(struct pub_key));
		// reverse key
		reverse_string((uint8_t *) & (c->working_key), c->mp_size);

		c->curve_type = KEY_EC_PRIVATE | KEY_GENERATE;
		// warning, this depend on struct ec_param entries
		ret = fs_key_write_part((uint8_t *) & (c->curve_type));
		if (ret != S_RET_OK)
			return ret;
		DPRINT("private key OK\n");

		// file:
		// 0x58, len, X coordinate,  0x59 len, Y coordinate
		message[0] = 2 + 32 + 2 + 32;
		message[1] = 0x58;
		message[2] = 32;
		reverse_copy(message + 3, (uint8_t *) & (pub_key->key.X), 32);
		message[35] = 0x59;
		message[36] = 32;
		reverse_copy(message + 37, (uint8_t *) & (pub_key->key.Y), 32);

		fs_select_ef(id_pub, NULL);
		ret = fs_update_binary(message, 0);
		fs_select_uuid(old_uuid, NULL);
		return ret;
	}
	// RSA key
	switch (k_size) {
	case 1024:
	case 1536:
	case 2048:
		break;
	default:
		DPRINT("key size wrong (%d)\n", k_size);
		return S0x6984;	//invalid data
	}
	old_uuid = fs_get_selected_uuid();
	id = (message[8] << 8) + message[9];
	id_pub = (message[10] << 8) + message[11];
	DPRINT("private key %04x public key %04x\n", id, id_pub);
	// test 
	ret = S0x6a82;		// file not found ..
	if (!fs_select_ef(id_pub, NULL))
		goto err;

	if (!fs_select_ef(id, NULL))
		goto err;

	card_io_start_null();
	// generate RSA P,Q
	//         P,Q                in message
	//         modulus            in r->data
	ret = rsa_keygen(message + 4, r->data, &key, k_size);

	// save key parts into file
	if (epass2003_store_rsa_key((rsa_num *) (message + 4), ret, KEY_GENERATE)) {
		ret = S0x6984;	// invalid data
		goto err;
	}

	fs_select_ef(id_pub, NULL);

	// public key in r->data, prepare public key into message

	reverse_string(r->data, k_size / 8);

	DPRINT("writing public key\n");
	message[0] = k_size / 8;

	memcpy(message + 1, r->data, k_size / 8);
	HPRINT("key: ", message, k_size / 8 + 10);

	HPRINT("data for public key file: ", message, 160);
	fs_update_binary(message, 0);
	ret = S_RET_OK;
 err:
	fs_select_uuid(old_uuid, NULL);
	return ret;
}

/*
get/put data emulation of EPASS2003

*/
uint8_t epass2003_get_data(uint8_t * message, struct iso7816_response *r)
{
	uint8_t *response = r->data;

	DPRINT("%s %02x %02x\n", __FUNCTION__, M_P1, M_P2);

	if (M_P1 != 1)
		return S0x6a88;	//Referenced data (data objects) not found

	if (M_P2 == 0x86) {
/*
the response appears to be organized as a TLV
src/libopensc/card-epass2003.c  lines 1581

		if (memcmp(&data[32], "\x87\x01\x01", 3) == 0
		    && memcmp(&data[0], "\x80\x01\x01", 3) == 0) {
			exdata->bFipsCertification = 0x01;
		} else {
			exdata->bFipsCertification = 0x00;
		}

		if (0x01 == data[2])
			exdata->smtype = KEY_TYPE_AES;
		else
			exdata->smtype = KEY_TYPE_DES;

		if (0x84 == data[14]) {
			if (0x00 == data[16]) {
				exdata->sm = SM_PLAIN;
			}
		}

// tag 0x80  1 - AES, another value DES (for SM encipher/MAC)
// tag 0x81 ???
// tag 0x82 ???
// tag 0x83  0x09, 0x00    or  0x00, 0x00 ????
// tag 0x84  0 no  SM another value SM enabled
// tag 0x87  1 FIPS mode
// below several responses (from debug logs on internet)
*/
#if SM_CRYPT == C_AES
#if 1
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	// AES
			0x81, 0x02, 0x1D, 0xD5,	//
			0x82, 0x01, 0x03	//
		};

#elif 0
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	//
			0x81, 0x02, 0x01, 0xD5,	//
			0x82, 0x01, 0x03,	//
			0x83, 0x02, 0x00, 0x00
		};

#elif 0
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	//
			0x81, 0x02, 0x01, 0xD5,	//
			0x82, 0x01, 0x04,	//
			0x83, 0x02, 0x09, 0x00,	//
			0x84, 0x01, 0x01	//
		};
#elif 0
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	//
			0x81, 0x02, 0x01, 0xD5,	//
			0x82, 0x01, 0x03,	//
			0x83, 0x02, 0x00, 0x00,	//
			0x84, 0x01, 0x01	//
		};
#elif 0
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	//
			0x81, 0x02, 0x01, 0xD5,	//
			0x82, 0x01, 0x03,	//
			0x83, 0x02, 0x00, 0x00,	//
			0x84, 0x01, 0x01,	//
			0x85, 0x0a, 0x00, 0x24, 0x24, 0xed, 0x28, 0x8a, 0x80, 0x39, 0x00, 0x26,	//
			0x86, 0x01, 0x00,	//
		};
#else
#error enable one from above...
#endif
//
#elif SM_CRYPT == C_AES_FIPS
// same as above but manually added tag 08x87  for FIPS MAC tests
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x01,	//
			0x81, 0x02, 0x01, 0xD5,	//
			0x82, 0x01, 0x03,	//
			0x83, 0x02, 0x00, 0x00,	//
			0x84, 0x01, 0x01,	//
			0x85, 0x0a, 0x00, 0x24, 0x24, 0xed, 0x28, 0x8a, 0x80, 0x39, 0x00, 0x26,	//
			0x86, 0x01, 0x00,	//
			0x87, 0x01, 0x01,	// FIPS
		};
#elif SM_CRYPT == C_DES
		uint8_t epass_data1[] = {	//
			0x80, 0x01, 0x00,	// 3DES
			0x81, 0x02, 0x1D, 0xD5,	//
			0x82, 0x01, 0x03	//
		};
#else
#error Unknown crypto for SM
#endif
		memcpy(response, epass_data1, sizeof(epass_data1));
		RESP_READY(sizeof(epass_data1));
	}
	if (M_P2 == 0x80) {
		/* serial number */
		uint8_t epass_data_serial[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
		memcpy(response, epass_data_serial, sizeof(epass_data_serial));
		RESP_READY(sizeof(epass_data_serial));
	}
	return S0x6a88;		//Referenced data (data objects) not found
}

static uint8_t g_init_key_enc[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10
};

static uint8_t g_init_key_mac[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10
};

static uint8_t sk_enc[16];
static uint8_t sk_mac[16];
static uint8_t sm_card_random[8];
static uint8_t sm_host_random[8];
static uint8_t sm_mac_icv[16];
#if SM_CRYPT == C_DES
#define SM_BLOCKSIZE 8
#else
#define SM_BLOCKSIZE 16
#endif

#if SM_CRYPT == C_AES_FIPS

//https://www.rfc-editor.org/rfc/rfc4493
static void cmac_aes_128(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
{
	uint8_t l[16] = { 0 };
	uint8_t c;
	uint8_t i;
	uint8_t k = 0;

	// encipher {0, 0, 0....0} vector
	aes_run(l, key, 16, 0);
	// generate k1/k2
	if (size & 15 || !size)
		k = 1;
	do {
		if (l[0] & 0x80)
			c = 0x87;
		else
			c = 0;
		for (i = 0; i < 15; i++) {
			l[i] <<= 1;
			if (l[i + 1] & 0x80)
				l[i] |= 1;
		}
		l[15] <<= 1;
		l[15] ^= c;
	} while (k--);
	// padding byte
	c = 0x80;
	do {
		// mark last round in "k" (k=255 from previous code)
		if (size <= 16)
			k = 0;
		for (i = 0; i < 16; i++) {
			if (size) {
				mac[i] ^= *(data++);
				size--;
			} else {
				// padding
				mac[i] ^= c;
				c = 0;
			}
			// last round
			if (!k)
				mac[i] ^= l[i];
		}
		aes_run(mac, key, 16, 0);
	} while (size);
}

#if 0
void cmac_aes_128_test()
{
// CMAC test vectors
	uint8_t k[] = {		//
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,	//
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c	//
	};

	uint8_t m0[] = { };
	uint8_t r0[] = {	//
		0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,	//
		0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46	//
	};

	uint8_t m1[] = {	//
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,	//
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a	//
	};
	uint8_t r1[] = {	//
		0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,	//
		0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c	//
	};
	uint8_t m2[] = {	//
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,	//
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,	//
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,	//
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,	//
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11	//
	};
	uint8_t r2[] = {	//
		0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,	//
		0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27	//
	};

	uint8_t m3[] = {	//
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,	//
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,	//
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,	//
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,	//
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,	//
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,	//
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,	//
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10	//
	};
	uint8_t r3[] = {	//
		0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,	//
		0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe	//
	};
	uint8_t mac[16];

	memset(mac, 0, 16);
	cmac_aes_128(m0, sizeof(m0), k, mac);
	if (memcmp(mac, r0, 16)) {
		fprintf(stderr, "Fail r0\n");
		exit(1);
	}
	memset(mac, 0, 16);
	cmac_aes_128(m1, sizeof(m1), k, mac);
	if (memcmp(mac, r1, 16)) {
		fprintf(stderr, "Fail r1\n");
		exit(1);
	}
	memset(mac, 0, 16);
	cmac_aes_128(m2, sizeof(m2), k, mac);
	if (memcmp(mac, r2, 16)) {
		fprintf(stderr, "Fail r2\n");
		exit(1);
	}
	memset(mac, 0, 16);
	cmac_aes_128(m3, sizeof(m3), k, mac);
	if (memcmp(mac, r3, 16)) {
		fprintf(stderr, "Fail r3\n");
		exit(1);
	}
}
#endif

#endif
#if SM_CRYPT == C_DES
static void epass2003_compute_mac_header(uint8_t * data, uint8_t * mac)
{
	uint8_t i;

	HPRINT("MAC bytes (header): ", data, 4);
	for (i = 0; i < 4; i++)
		mac[i] ^= *(data++);
	mac[i] ^= 0x80;

	des_run(mac, sk_mac, DES_ENCRYPTION_MODE);
//      HPRINT("\nMAC calculator (header): ", mac, 8);
}

static void epass2003_compute_mac(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
{
	uint8_t i;
	DPRINT("MAC from %d bytes\n", size);
	HPRINT("MAC bytes: ", data, size);
	if (size) {

		size++;
		while (size) {
			for (i = 0; i < 8 && --size; i++)
				mac[i] ^= *(data++);
			if (!size)
				mac[i] ^= 0x80;

			des_run(mac, sk_mac, DES_ENCRYPTION_MODE);
//                      HPRINT("\nMAC calculator: ", mac, 8);
		}
	}
	des_run(mac, key + 8, DES_DECRYPTION_MODE);
//      HPRINT("\nMAC calculator: ", mac, 8);
	des_run(mac, key, DES_ENCRYPTION_MODE);
//      HPRINT("\nMAC calculator: ", mac, 8);
}

static void epass2003_compute_mac_auth(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
{
	uint8_t i;
	DPRINT("MAC from %d bytes\n", size);
	HPRINT("MAC bytes: ", data, size);
	if (!size)
		return;
	size++;
	while (size) {
		for (i = 0; i < 8 && --size; i++)
			mac[i] ^= *(data++);
		if (!size)
			mac[i] ^= 0x80;

		des_run(mac, key, DES_ENCRYPTION_MODE | DES_2DES);
//              HPRINT("\nMAC calculator: ", mac, 8);
	}
}

#elif SM_CRYPT == C_AES_FIPS
static void epass2003_compute_mac_auth(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
{
	memset(mac, 0, 16);
	cmac_aes_128(data, size, key, mac);
}

/*
static void epass2003_compute_mac_auth(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
    __attribute__((alias("epass2003_compute_mac")));
*/
#else
static void epass2003_compute_mac(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
{
	uint8_t i;
	DPRINT("MAC from %d bytes\n", size);
	HPRINT("MAC bytes: ", data, size);
	if (!size)
		return;
	size++;
	while (size) {
		for (i = 0; i < 16 && --size; i++)
			mac[i] ^= *(data++);
		if (!size)
			mac[i] ^= 0x80;

		aes_run(mac, key, 16, 0);
//              HPRINT("\nMAC calculator: ", mac, 16);
	}
}

static void epass2003_compute_mac_auth(uint8_t * data, uint16_t size, uint8_t * key, uint8_t * mac)
    __attribute__((alias("epass2003_compute_mac")));
#endif

uint8_t epass2003_mutual_auth(uint8_t * message, struct iso7816_response *r)
{
	uint8_t *response = r->data;
	uint8_t data[256] = { 0 };
	uint8_t mac[SM_BLOCKSIZE] = { 0 };
	// IN: P1 = 0, P2 = 0, read host random
	//      LE = 28 no fips
	//      LE = 29 fips
	// OUT: 30 bytes,  bytes 12..19  card random
	// initial response (unknown 13 bytes), the radnom 8 bytes, then MAC .. 

#if  SM_CRYPT == C_AES_FIPS
	uint8_t epass_data2[] =
	    { 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x17, 0x05, 0x12, 0x01, 0xFF, 0x01, 0 };
#else
	// this is copied from log of real epass2003 device
	uint8_t epass_data2[] =
	    { 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x17, 0x05, 0x12, 0x01, 0xFF, 0x01 };
#endif
#ifdef FIXED_RANDOM
	uint8_t sm_card_random_fix[] = { 0x4C, 0xEC, 0x8B, 0x98, 0x55, 0xE4, 0xB7, 0x3D };
	memcpy(sm_card_random, sm_card_random_fix, 8);
#else
	rnd_get(sm_card_random, 8);
#endif
	memcpy(sm_host_random, message + 5, 8);

#if SM_CRYPT == C_AES_FIPS
	memset(data, 0, 15);
	data[11] = 0x04;
	data[14] = 0x80;
	data[15] = 0x01;
	memcpy(data + 16, sm_host_random, 8);
	memcpy(data + 24, sm_card_random, 8);
	HPRINT("derivations data (FIPS mode): ", data, 32);

	memset(sk_enc, 0, 16);
	cmac_aes_128(data, 32, g_init_key_enc, sk_enc);
	data[11] = 6;

	memset(sk_mac, 0, 16);
	cmac_aes_128(data, 32, g_init_key_mac, sk_mac);
	data[11] = 0x00;
	data[14] = 0x40;

	memset(mac, 0, 16);
	cmac_aes_128(data, 32, sk_enc, mac);

	HPRINT("sk_enc (FIPS mode): ", sk_enc, 16);
	HPRINT("sk_mac (FIPS mode): ", sk_mac, 16);
#else
	/* Step 1 - Generate Derivation data */
	memcpy(data + 0, sm_card_random + 4, 4);	// card random
	memcpy(data + 4, message + 5 + 0, 4);	// host random
	memcpy(data + 8, sm_card_random + 0, 4);	// card random
	memcpy(data + 12, message + 5 + 4, 4);	// host random
	HPRINT("derivations data (non FIPS mode): ", data, 16);
	memcpy(sk_enc, data, 16);
	memcpy(sk_mac, data, 16);
#if SM_CRYPT == C_AES
	memcpy(sk_enc, data, 16);
	memcpy(sk_mac, data, 16);
	/* enc key */
	aes_run(sk_enc, g_init_key_enc, 16, 0);
	/* mac key */
	aes_run(sk_mac, g_init_key_mac, 16, 0);
#elif SM_CRYPT == C_DES
	/* enc key */
	des_run(sk_enc, g_init_key_enc, DES_ENCRYPTION_MODE | DES_2DES);
	des_run(sk_enc + 8, g_init_key_enc, DES_ENCRYPTION_MODE | DES_2DES);
	des_run(sk_mac, g_init_key_mac, DES_ENCRYPTION_MODE | DES_2DES);
	des_run(sk_mac + 8, g_init_key_mac, DES_ENCRYPTION_MODE | DES_2DES);
#else
#error wrong SM_CRYPT
#endif
	HPRINT("sk_enc: ", sk_enc, 16);
	HPRINT("sk_mac: ", sk_mac, 16);
	/* verification data */
	memcpy(data, message + 5, 8);
	memcpy(data + 8, sm_card_random, 8);

	HPRINT("source for cryptogram: ", data, 16);

	epass2003_compute_mac_auth(data, 16, sk_enc, mac);
#endif
	HPRINT("mac: ", mac, 8);

	memcpy(response, epass_data2, sizeof(epass_data2));	// ???
	memcpy(response + sizeof(epass_data2), sm_card_random, sizeof(sm_card_random));	// card random
	memcpy(response + sizeof(epass_data2) + sizeof(sm_card_random), mac, 8);	// verification data
	RESP_READY(sizeof(epass_data2) + sizeof(sm_card_random) + 8);
}

uint8_t epass2003_verify_key(uint8_t * message)
{
///     84 82 03 00 
//      10                      << length
//      FA 60 D2 03 BE 0A 6C 15 << host cryptogram
//      FC 78 73 3B A2 D1 89 73 <<  

	uint8_t data[32];
	uint8_t mac[16];

	if (M_P1 == 3 && M_P2 == 0 && M_P3 == 0x10) {
		HPRINT("input for verify key:", message, 5 + M_P3);
		// compute MAC from card/host random
		memset(mac, 0, 16);
#if SM_CRYPT == C_AES_FIPS
		memset(data, 0, 15);
		data[11] = 0x01;
		data[14] = 0x40;
		data[15] = 0x01;
		memcpy(data + 16, sm_host_random, 8);
		memcpy(data + 24, sm_card_random, 8);
		cmac_aes_128(data, 32, sk_enc, mac);
#else				// C_DES, C_AES
		memcpy(data, sm_card_random, 8);
		memcpy(data + 8, sm_host_random, 8);
		epass2003_compute_mac_auth(data, 16, sk_enc, mac);
#endif
		// same data if command APDU ?
		if (memcmp(message + 5, mac, 8)) {
			DPRINT("wrong data from host, random not match\n");
			return S0x6985;	//    Conditions not satisfied
		}
		// check message MAC
		memcpy(data, message, 5 + 8);

		/* calculate mac icv */
		memset(sm_mac_icv, 0, 16);
		epass2003_compute_mac_auth(data, 13, sk_mac, sm_mac_icv);
		memset(sm_mac_icv + 8, 0, 8);

		HPRINT("mac_icv=", sm_mac_icv, 16);

		if (0 == memcmp(message + 13, sm_mac_icv, 8))
			return (S_RET_OK);
	}
	return S0x6985;		//    Conditions not satisfied
}

struct tlv_parse {
	uint8_t *tlv_start;
	// pointer and length of data
	uint8_t *data;
	uint16_t data_len;
	// result of parsing:
	uint8_t tag;
	uint32_t len;
};

static uint8_t get_tlv_btag(struct tlv_parse *t)
{
	uint8_t *data = t->data;
	uint16_t data_len = t->data_len;
	uint8_t dl;
	uint32_t l = 0;

	t->tlv_start = data;
	if (data_len < 2) {
		DPRINT("Insuficient data len 1\n");
		return 1;
	}
	data_len--;
	t->tag = *(data++);
	if (*data & 0x80) {
		dl = *data - 0x80;
		DPRINT("data = %02x dl=%d\n", *data, dl);
		data++;
		data_len--;
		if (data_len < dl) {
			DPRINT("Insuficient data len 2\n");
			return 1;
		}
	} else {
		dl = 1;
	}
	if (dl > 4) {
		DPRINT("Oversized len field %d\n", dl);
		return 1;
	}
	while (dl--) {
		l <<= 8;
		l |= *(data++);
		data_len--;
	}
	if (data_len < l) {
		DPRINT("Not enough data for data field\n");
		return 1;
	}
	t->len = l;
	t->data = data;
	t->data_len = data_len;
	return 0;
}

// return SW (S_SM_OK if SM is correct and normal APDU processing can continue)
// return S_RET_OK if SM is OK and no normlal APDU processing is required
// any other value = error code
uint8_t sm_unwrap(struct iso7816_response *r, uint16_t input_len)
{
	struct tlv_parse t;
	uint16_t i;
	// Real Nc, Ne, (not from SM)
	uint16_t Nc;
	uint32_t Ne;
	uint8_t *command, *mac_start = NULL;
	uint8_t *data = r->input + 4;
	uint8_t *apdu_command;
	uint16_t Nc_ = 0;
	uint32_t Ne_ = 0;
	uint8_t padding_indikator = 0;
	uint8_t mac[16];

	DPRINT("Incoming SM APDU:");
	for (i = 0; i < input_len; i++)
		DPRINT("%02X ", r->input[i]);
	DPRINT("\n");

	if (input_len < 5) {
		DPRINT("APDU too short");
		return S0x6700;	// wrong length
	}
	input_len -= 5;
	// check APDU.. data is pointer to P3
	if (*data == 0) {
		data++;
		if (input_len < 2) {
			DPRINT("EXTENDED APDU too short, no bytes for Lc field");
			return S0x6700;	// wrong length
		}
		input_len -= 2;

		Nc = (*(data++) << 8);
		Nc += *(data++);
		DPRINT("EXTENDED APDU, Nc=%d\n", Nc);
		if (input_len - 2 == Nc) {
			DPRINT("Le bytes %02x %02x\n", data[input_len - 1], data[input_len - 2]);
			Ne = data[input_len - 1] + (data[input_len - 2] << 8);
			if (Ne == 0)
				Ne = 65536;
			input_len -= 2;
		} else if (input_len == Nc) {
			DPRINT("EXTENDED APDU, no Le field, Ne = 0 %d %d\n", input_len, Nc);
			Ne = 0;
		} else {
			DPRINT("EXTENDED APDU, incorrect length\n");
			return S0x6700;	// wrong length
		}
	} else {
		Nc = *(data++);
		if (input_len - 1 != Nc) {
			DPRINT("APDU SHORT: No Le field, Ne = 0\n");
			Ne = 0;
		} else {
			Ne = data[input_len - 1];
			input_len--;
		}
	}
	/* ISO 7816-4, ANNEX B, Le field should be always zero ? */
	if (Ne != 0 && Ne != 65536)
		DPRINT("Warning Le !=0\n");
	DPRINT("SM APDU, Nc=%d, command field len=%d, Ne=%d command start byte %02x\n", Nc,
	       input_len, Ne, *data);

	apdu_command = data;
	t.data = data;
	command = NULL;
	i = r->input[0] & 0x0c;
	if (i == 4) {
		DPRINT("Proprietary SM\n");
		// TODO
		if (r->input[1] == 0x82)
			return epass2003_verify_key(r->input);
		DPRINT("Propriettary SM (unprocessed, unknown) ignoring ..\n");
		return S_SM_OK;
	} else if (i == 0x08) {
		DPRINT("SM command header not processed\n");

	} else if (i != 0x0c) {
		DPRINT("Warning, this is not SM APDU\n");
		return S_SM_OK;
	}
	DPRINT("SM command header authentificated\n");
	t.tag = 0;
	for (t.data_len = input_len; t.data_len;) {
		if (get_tlv_btag(&t))
			return S0x6988;	// Incorrect SM data object
		switch (t.tag) {
		case 0x8e:
			break;
		case 0x87:
			padding_indikator = t.data[0];
			DPRINT("SM object 0x87 length=%d padding_indikator=%02x\n", t.len,
			       t.data[0]);
			if (padding_indikator != 1) {
				DPRINT("Wrong padding indikator\n");
				return S0x6988;	// Incorrect SM data object
			}
			command = t.data + 1;
			Nc_ = t.len - 1;
			break;
		case 0x96:
		case 0x97:
			// ISO7816-4, one or two bytes Ne value
			DPRINT("SM object 0x%02x, length=%d\n", t.tag, t.len);
			Ne_ = t.data[0];
			if (t.len == 2) {
				Ne_ <<= 8;
				Ne_ += t.data[1];
			} else if (t.len != 1) {
				DPRINT("Oversized Ne field\n");
				return S0x6988;	// Incorrect SM data object
			}
			// Le is present, change zero in Le to Ne value
			if (Ne_ == 0) {
				Ne_ = 256;
				if (t.len == 2)
					Ne_ = 65536;
			}
			DPRINT("SM object 0x97, Ne=%d\n", Ne_);
			break;
		default:
			DPRINT("SM object 0x%02x, length=%d  - skipping\n", t.tag, t.len);
		}
		t.data += t.len;
		t.data_len -= t.len;
	}
// MAC check
	if (t.tag != 0x8e)
		return S0x6988;	// Incorrect SM data object

	mac_start = t.tlv_start;
// increment IV
	HPRINT("IV=", sm_mac_icv, 16);
	for (i = SM_BLOCKSIZE; i > 0;) {
		i--;
		if (sm_mac_icv[i] == 0xff)
			sm_mac_icv[i] = 0;
		else {
			sm_mac_icv[i]++;
			break;
		}
	}
	HPRINT("Incremented IV=", sm_mac_icv, 16);
// apply IV
	memcpy(mac, sm_mac_icv, SM_BLOCKSIZE);
#if SM_CRYPT == C_DES
	epass2003_compute_mac_header(r->input, mac);
	epass2003_compute_mac(apdu_command, mac_start - apdu_command, sk_mac, mac);
#elif SM_CRYPT == C_AES
	epass2003_compute_mac(r->input, 4, sk_mac, mac);
	epass2003_compute_mac(apdu_command, mac_start - apdu_command, sk_mac, mac);
#elif SM_CRYPT == C_AES_FIPS
	// special APDU, P3=10 (tag 0x8e...)
	if (r->input[1] == 0x82 && r->input[2] == 1 && r->input[4] == 10) {
		DPRINT("Warning, non standard padding!\n");
		// IV is not used for this APDU
		memset(mac, 0, 16);
		cmac_aes_128(r->input, 4, sk_mac, mac);
	} else {
		// APDU header, and padding  XOR IV
		for (i = 0; i < 4; i++)
			mac[i] ^= r->input[i];
		mac[4] ^= 0x80;
		// initial part of CMAC (from ADPU header)
		aes_run(mac, sk_mac, 16, 0);
		// APDU data field
		cmac_aes_128(apdu_command, mac_start - apdu_command, sk_mac, mac);
	}
#endif
	HPRINT("MAC for test: ", mac, 16);
	HPRINT("MAC in message: ", t.tlv_start + 2, 16);
	if (memcmp(mac, t.tlv_start + 2, 8)) {
		DPRINT("MAC error\n");
		return S0x6988;	// Incorrect SM data object
	}

	input_len = 4;
	if (command) {
		// check blocksize..
		if (Nc_ & (SM_BLOCKSIZE - 1)) {
			DPRINT("data size in cryptogram does notmatch block size\n");
			return S0x6988;	// Incorrect SM data object
		}
		DPRINT("message decrypt:\n");
		for (apdu_command = command + Nc_ - SM_BLOCKSIZE;;) {
//                      DPRINT("aes run %p\n", apdu_command);
#if SM_CRYPT == C_AES || SM_CRYPT == C_AES_FIPS
			aes_run(apdu_command, sk_enc, 16, 1);
#else
			des_run(apdu_command, sk_enc, DES_DECRYPTION_MODE | DES_2DES);
#endif
			if (apdu_command == command)
				break;
			apdu_command -= SM_BLOCKSIZE;
			for (i = 0; i < SM_BLOCKSIZE; i++)
				apdu_command[i + SM_BLOCKSIZE] ^= apdu_command[i];
		}

		DPRINT("Nc=%d\n", Nc_);
		HPRINT("decoded message:", command, Nc_);
		// remove padding
		Nc_--;
		while (command[Nc_] == 0)
			Nc_--;

		if (command[Nc_] != 0x80) {
			DPRINT("wrong padding (%02x)\n", command[Nc_]);
			return S0x6988;	// Incorrect SM data object
		}

		if (Nc_ > 255 || Ne_ > 256) {
			r->input[4] = 0;
			r->input[5] = Nc_ >> 8;
			r->input[6] = Nc_ & 0xff;
			input_len += 3;
		} else {
			r->input[4] = Nc_;
			input_len++;
		}
		memcpy(r->input + input_len, command, Nc_);
		input_len += Nc_;
	}
	if (Ne_) {
		DPRINT("Appending Le field, Ne=%d\n", Ne_);
		if (command) {
			// CASE 4 EXTENDED
			if (Nc_ > 255 || Ne_ > 256)
				r->input[input_len++] = Ne_ >> 8;
		} else {
			// CASE 2 EXTENDED
			if (Ne_ > 256) {
				r->input[input_len++] = 0;
				r->input[input_len++] = Ne_ >> 8;
			}
		}
		// SHORT or EXTENDED (CASE 2 or 4)
		r->input[input_len++] = Ne_ & 0xff;
	}
	r->input_len = input_len;
	// remove SM bits from CLA
	r->input[0] &= 0xf3;
	HPRINT("unwrapped APDU:", r->input, r->input_len);
	return S_SM_OK;
}

uint16_t sm_wrap_response(struct iso7816_response *r, uint8_t * message, uint16_t input_len)
{
	uint8_t rresponse[APDU_RESP_LEN];
	uint8_t *data, *aes_data;
	uint16_t padding_len, aes_len;
	uint16_t ret = input_len;
	uint16_t i;
	uint8_t iv[16] = { 0 };

	HPRINT("response: ", message, input_len);

	if ((r->orig_cla & 0x0c) == 0)
		return ret;
	DPRINT("recoding response, input len = %d\n", input_len);
	data = rresponse;
	if (input_len < 2)
		return 0;

	// data field ISO7816-4:2013(E) chapter 10, table 49 (Tag 0x87)
	if (input_len > 2) {
		aes_len = input_len - 2;	// raw response (without SW1,SW2
		padding_len = aes_len;
		aes_len++;	// minimal padding 0x80
		aes_len = (aes_len + SM_BLOCKSIZE - 1) / SM_BLOCKSIZE;
		aes_len *= SM_BLOCKSIZE;
		// is enough free space in buffer ?
		// TLV (0x87), data, TLV SW, TLV MAC, SW
		if (4 + aes_len + 4 + 10 + 2 <= APDU_RESP_LEN) {
			DPRINT("Tag 0x87 OK, data len=%d of which padding length %d\n",
			       aes_len, padding_len);
			padding_len = aes_len - padding_len;
			*(data++) = 0x87;
			// we need ad here one byte as padding indicator
			aes_len++;
			if (aes_len < 128) {
				*(data++) = aes_len;
			} else if (aes_len < 256) {
				*(data++) = 0x81;
				*(data++) = aes_len;
			} else {
				*(data++) = 0x82;
				*(data++) = aes_len >> 8;
				*(data++) = aes_len & 0xff;
			}
			// return len back (one byte for padding indicator)
			aes_len--;

			// padding indikator
			*(data++) = 1;

			memcpy(data, message, input_len - 2);
			aes_data = data;
			data += (input_len - 2);
			// padding
			memset(data, 0, padding_len);
			*(data) = 0x80;
			data += padding_len;
			for (; aes_len;) {

#if SM_CRYPT == C_AES || SM_CRYPT == C_AES_FIPS
				aes_run(aes_data, sk_enc, 16, 0);
#else
				des_run(aes_data, sk_enc, DES_ENCRYPTION_MODE | DES_2DES);
#endif
				aes_len -= SM_BLOCKSIZE;
				if (aes_len) {
					for (i = 0; i < SM_BLOCKSIZE; i++, aes_data++)
						aes_data[SM_BLOCKSIZE] ^= aes_data[0];
				}
			}

		} else {
			DPRINT("Not enough space in buffer, only SW is returned\n");
		}
	}
	// ISO7816-4:2013(E) chapter 10, table 49 (Tag 0x99)
	*(data++) = 0x99;	//
	*(data++) = 2;		// LEN
	*(data++) = message[input_len - 2];
	*(data++) = message[input_len - 1];
	memcpy(iv, sm_mac_icv, 16);
#if SM_CRYPT == C_AES_FIPS
	cmac_aes_128(rresponse, data - rresponse, sk_mac, iv);
#else
	epass2003_compute_mac(rresponse, data - rresponse, sk_mac, iv);
#endif
	//  epass2003 driver in opensc (0.23) does not check MAC!
	// ISO7816-4:2013(E) chapter 10, table 49 (Tag 0x8e)
	*(data++) = 0x8e;
	*(data++) = 8;
	memcpy(data, iv, 8);	// copy MAC
	data += 8;

	*(data++) = message[input_len - 2];
	*(data++) = message[input_len - 1];
	ret = data - rresponse;
	HPRINT("encoded response and SW: ", rresponse, ret);
	memcpy(message, rresponse, ret);
	return ret;
}

// PIN is here not in filesystem (initial implementation)

struct epass2003_pin {
	uint8_t type;
	uint8_t size;
	uint8_t key[24];
};
static struct epass2003_pin epass2003_pins[14];

// 80 E3 00 00 22
//      04 01 90 96 98 98 00 06 FF 66 71 10 ED A4 D0 9E 06 2A A5 E4 A3 90 B0 A5 72 AC 0D 2C 02 20 00 00 00 04

uint8_t epass2003_install_secret_key(uint8_t * message
				     __attribute__((unused)), struct iso7816_response *r
				     __attribute__((unused)))
{
	uint8_t *data = message + 5;
	uint8_t size;
// data[0] => key type   4 = PIN, 1 - init key for ENC, 2 init key for MAC, 6 - normal PIn (not hashed)
// data[1] => kid  (for ENC and MAC 0)
// data[2] = useac
// data[3] = modifyac;
// data[4] = EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_SO;
// data[5] = EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_SO;
//
// data[7] = (kid == PIN_ID[0] ? EPASS2003_AC_USER : EPASS2003_AC_SO);
// data[8] = 0xFF;
//_data[9] = (EC << 4) | EC;
// data[10], data, dataLen);

	// 0x04 - 3DES key, 0x06 RAW PIN (for verify command)
	if (data[0] == 4 || data[0] == 6) {
		if (data[1] < 14) {
			epass2003_pins[data[1]].type = data[0];
			size = 24;
			if (r->Nc > 10 + 24)
				size = r->Nc - 10;
			epass2003_pins[data[1]].size = size;
			memset(&epass2003_pins[data[1]].key, 0, 24);
			memcpy(&epass2003_pins[data[1]].key, data + 10, size);
		}
	}
	return S_RET_OK;
}

/* compare data in APDU with chalenge encrypted by pin (pin id in P2) */

uint8_t epass2003_external_key_auth(uint8_t * message
				    __attribute__((unused)), struct iso7816_response *r)
{
	uint8_t data[8];
	uint8_t kid;

	if (message[2] != 1)
		return S0x6a86;	//Incorrect parameters P1-P2

	kid = message[3];
	if (kid & (0x80 != 0x80))
		return S0x6a86;	//Incorrect parameters P1-P2

	kid &= 0x7f;
	if (kid > 14)
		return S0x6a86;	//Incorrect parameters P1-P2

	// check retries .. ?
	if (r->Nc == 0)
		return S0x63c6;

	if (r->Nc != 8)
		return S0x6700;	// wrong length

	if (epass2003_pins[kid].type != 4)
		return S0x6983;	//no more verification retries

	memcpy(data, r->challenge, 8);
	des_run(data, epass2003_pins[kid].key, DES_ENCRYPTION_MODE | DES_3DES);
	if (memcmp(data, message + 5, 8))
		return S0x6983;	//no more verification retries
	return S_RET_OK;
}

// 80 B4 02 00 02 30 00 00 - RSA// 80 b4 00 00 02 30 00 00   EC// read file 3000
uint8_t epass2003_read_generated_public_key(uint8_t * message, struct iso7816_response *r)
{
	uint16_t old_uuid, id;
	uint8_t ret;
	if (M_P2 != 0 || M_P3 != 2)
		return S0x6981;
	if (M_P1 != 2 && M_P1 != 0)
		return S0x6981;
	old_uuid = fs_get_selected_uuid();
	id = (message[8] << 6) + message[5];
	fs_select_ef(id, NULL);
	// change Ne  to real  file size
	r->Ne = fs_get_file_size();
	ret = fs_read_binary(0, r);
	HPRINT("public key: ", r->data, r->Ne);
	fs_select_uuid(old_uuid, NULL);
	return ret;
}

uint8_t epass2003_import_key(uint8_t * message
			     __attribute__((unused)),
			     struct iso7816_response *r __attribute__((unused)))
{
	static uint8_t size;
	static uint8_t exponent[256];
	static uint8_t modulus[256];
	static uint16_t file_id;
	rsa_num pq[2];

	HPRINT("import key...", message, 5 + r->Nc);
	DPRINT("key length = %d\n", r->Nc - 2);

	size = r->Nc - 2;

	// In this project we have (yet) only 1024 bit multiplication!
	if (size > 128)
		return S0x6700;	// wrong length

	file_id = (message[5] << 8) + message[6];

	if (message[2] == 2)
		reverse_copy(modulus, message + 7, size);

	if (message[2] == 3) {
		reverse_copy(exponent, message + 7, size);
		rsa_factorize(exponent, modulus, pq, size * 8);
		fs_select_ef(file_id, NULL);
		epass2003_store_rsa_key((rsa_num *) (&pq), size / 2, 0);
		HPRINT("p=", &pq[0], size / 2);
		HPRINT("q=", &pq[1], size / 2);
	}
	return S_RET_OK;
}

uint8_t epass2003_list_files(uint8_t * message __attribute__((unused)), struct iso7816_response *r)
{
	return fs_list_files(0xa1, r);
}
