UNTRUSTED_SRC_FILES := ../ocall/net_ocalls.c ../ocall/std_ocalls.c
UNTRUSTED_OBJECTS := $(UNTRUSTED_SRC_FILES:.c=.u.o)
SGX_SDK ?= /opt/intel/sgxsdk

libmbedtls_SGX_u.a:	$(UNTRUSTED_OBJECTS)
	@ar rcs $@ $^
	@echo "LD => $@"

%.u.o: %.c
	@echo "hello"
	@echo "$(CC) -I../trusted/mbedtls-2.6.0/include -I$(SGX_SDK)/include -c -o $@ $<"
	@$(CC) -I../trusted/mbedtls-2.6.0/include -I$(SGX_SDK)/include -c -o $@ $<
	@echo "CC <= $<"

.PHONY: clean

clean:
	@rm -f $(UNTRUSTED_OBJECTS) $(PROJECT_NAME)_u.*

