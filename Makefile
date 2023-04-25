TARGET= targets/epass2003/
BUILD= build/epass2003/

# SECURE MESSAGING (EXTENDED APDU)
# 5(header) + 2(Lc) + 4(Tag,len) + 1(padding indicator) + 256(command) + 16(SM padding) +
# 4(TLV Le field) + (8+2)MAC + 2 bytes Lc
# RESPONSE:

# 5 TLV + padding indicator
# 272 response + padding
# 4 TLV  status word
# 2+8 MAC
# 2 status word

APDU_SIZE = -DAPDU_CMD_LEN=299 -DAPDU_RESP_LEN=293

#normal debug
#CFLAGS= -Wall -O2  -g -Wfatal-errors

CFLAGS= -Wall -Wstrict-prototypes -Wfatal-errors
CFLAGS+= -fstack-protector-strong -Wformat -Werror=format-security -Wextra
CFLAGS+= -O2 -g
CFLAGS+= -DRSA_BYTES=128 -DCARD_RESTART -I$(TARGET)

# this is used to generate statistics for RSA keygen code (or enable this in card_os/debug.h)
#CFLAGS+= -DRSA_GEN_DEBUG
#grep -v close rsa_gen_debug.stat |grep -v 0x| awk '{g+=$2;r+=$4}END{print g/NR" "r/NR}
#grep close rsa_gen_debug.stat |awk '{c+=$2;s+=$4}END{print s" "c}'
# to test prime generator:
#grep 0x rsa_gen_debug.stat|awk '{print "IsPrime("$1")"}' |genius|grep -v true

CC= gcc
##CFLAGS+= -D_FORTIFY_SOURCE=2
#CC= cgcc -Wsparse-all
#CC=afl-clang-fast
#ASAN_OPTIONS=symbolize=0 AFL_USE_ASAN=1


all:	epass2003_sim

#Tested without NIST_ONLY, but not set as default
#CFLAGS += -DNIST_ONLY

# exponentation window
CFLAGS += -DE_BITS=4

# ECC size (in bytes 24,32,48,72)
CFLAGS += -DMP_BYTES=72

# precalculate inverse P and Q into key file
CFLAGS += -DUSE_P_Q_INV

# enable exponent blinding
CFLAGS += -DRSA_EXP_BLINDING

# enable protection for single error in CRT
CFLAGS += -DPREVENT_CRT_SINGLE_ERROR

# MyEID does not support 56 bit des version, OsEID allow this if needed
#CFLAGS += -DENABLE_DES56

#CFLAGS += -DPROTOCOL_T0 -DPROTOCOL_T1
#CFLAGS += -DTRANSMISSION_PROTOCOL_MODE_NEGOTIABLE
CFLAGS += -DPROTOCOL_T1

CFLAGS += -DEPASS2003

CFLAGS += $(APDU_SIZE)
.PHONY:	builddir all

builddir:
	@rm -rf $(BUILD)
	@mkdir -p $(BUILD)

#-------------------------------------------------------------------
# target platform files
#-------------------------------------------------------------------
$(BUILD)card_io.o: $(TARGET)card_io.c
	$(CC) $(CFLAGS) -o $(BUILD)card_io.o -c $(TARGET)card_io.c -I$(TARGET) -Icard_os

$(BUILD)mem_device.o:	$(TARGET)mem_device.c
	$(CC) $(CFLAGS) -o $(BUILD)mem_device.o -c $(TARGET)mem_device.c -I$(TARGET) -Icard_os

$(BUILD)rnd.o:	$(TARGET)rnd.c
	$(CC) $(CFLAGS) -o $(BUILD)rnd.o -c $(TARGET)rnd.c -Icard_os

#-------------------------------------------------------------------
# Simulated reader
#-------------------------------------------------------------------
BUILD_P = build/pcscd/
TARGET_S = pcscd/sim_reader/
# undef for negotiable mode, or define 0, 1
PROTO = -DPROTO=1
card_reader:	$(BUILD_P)lib_sim_reader.so

card_reader_install:	card_reader
	mkdir -p /usr/lib/pcsc/drivers/sim/
	cp $(BUILD_P)/lib_sim_reader.so /usr/lib/pcsc/drivers/sim
	echo 'FRIENDLYNAME      "Simulated reader"' > /etc/reader.conf.d/sim_reader.conf
	echo 'LIBPATH           /usr/lib/pcsc/drivers/sim/lib_sim_reader.so' >> /etc/reader.conf.d/sim_reader.conf
	echo 'CHANNELID         0' >> /etc/reader.conf.d/sim_reader.conf
	systemctl restart pcscd.service

card_reader_uninstall:
	rm -f /etc/reader.conf.d/sim_reader.conf
	rm -f /usr/lib/pcsc/drivers/sim/lib_sim_reader.so
	systemctl restart pcscd.service
	

sim_version="0.0.1"

$(BUILD_P)lib_sim_reader.so:	$(TARGET_S)ifdhandler.c $(TARGET_S)reader_socket.c $(TARGET_S)hex2bytes.c
	mkdir -p $(BUILD_P)
	$(CC) -shared -O2 -g -Wall -fPIC -I. `pkg-config libpcsclite --cflags` $(PROTO) -o $(BUILD_P)lib_sim_reader.so $(TARGET_S)ifdhandler.c $(TARGET_S)reader_socket.c $(TARGET_S)hex2bytes.c
	chmod -x $(BUILD_P)lib_sim_reader.so
	(cd  $(BUILD_P); ln -fs lib_sim_reader.so lib_sim_reader.so.$(sim_version))

.PHONY: all clean test card_reader_install card_reader_uninstall

#-------------------------------------------------------------------
# card_os files
#-------------------------------------------------------------------

include card_os/Makefile

	
epass2003_sim:	builddir $(COMMON_TARGETS) $(BUILD)card_io.o $(BUILD)mem_device.o $(BUILD)rnd.o
	$(CC) $(CFLAGS) -o epass2003_sim $(COMMON_TARGETS) $(BUILD)card_io.o $(BUILD)mem_device.o $(BUILD)rnd.o
	mkdir -p tmp

test:	epass2003_sim
	-pkcs15-tool -D && pkill epass2003_sim
	./epass2003_sim &
	sleep 1
	tests/test.sh
	-pkill epass2003_sim

clean:
	rm -f *~
	rm -f card_os/*~
	rm -f epass2003_doc/*~
	rm -f tests/*~
	rm -f targets/epass2003/*~
	rm -f pcscd/sim_reader/*~
	rm -f ./lib/generic/*~
	rm -f epass2003_sim
	rm -f card_mem
	rm -rf tmp
	rm -rf build

