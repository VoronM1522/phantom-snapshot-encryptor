TARGET = encryptor
SRC_CC = encryptor.cc
LIBS   += tresor posix libcrypto libm

CXX_OPT += -Wno-error=conversion -Wno-error=unused-parameter 


# TARGET = encryptor

# SRC_CC = encryptor.cc

# LIBS = base heap block vfs tresor libcrypto

# INC_DIR += $(REP_DIR)/src/lib/tresor/include
