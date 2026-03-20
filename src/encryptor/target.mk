TARGET = encryptor
SRC_CC = encryptor.cc
LIBS   += posix libcrypto libm

CXX_OPT += -Wno-error=conversion -Wno-error=unused-parameter 
