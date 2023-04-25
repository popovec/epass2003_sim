/*
    epass2003_emu.h

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

    myeid emulation header file

*/
#ifndef CS_EPASS2003_H
#define CS_EPASS2003_H

uint8_t security_env_set_reset(uint8_t * message, __attribute__((unused))
			       struct iso7816_response *r);

uint8_t security_operation(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_generate_key(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_get_data(uint8_t * message, struct iso7816_response *r);


uint8_t epass2003_mutual_auth(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_install_secret_key(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_read_generated_public_key(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_external_key_auth(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_import_key(uint8_t * message, struct iso7816_response *r);
uint8_t epass2003_list_files(uint8_t * message, struct iso7816_response *r);
uint8_t sm_unwrap(struct iso7816_response *r, uint16_t input_len);
uint16_t sm_wrap_response(struct iso7816_response *r, uint8_t * message, uint16_t len);

#endif
