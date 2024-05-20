CC=gcc
CFLAGS=-I. -Ideps/micro-ecc -Ideps/b64.c -Ideps/sha-2 \
	   -DuECC_ENABLE_VLI_API=1 \
	   -DuECC_SUPPORT_secp160r1=0 \
	   -DuECC_SUPPORT_secp192r1=0 \
	   -DuECC_SUPPORT_secp224r1=1 \
	   -DuECC_SUPPORT_secp256r1=0 \
	   -DuECC_SUPPORT_secp256k1=0 \
	   -DuECC_SUPPORT_COMPRESSED_POINT=0

ODIR=build
DEPS =

_OBJ = main.o \
	haystack-derived.o \
	deps/micro-ecc/uECC.o \
	deps/b64.c/decode.o \
	deps/b64.c/encode.o \
	deps/b64.c/buffer.o \
	deps/sha-2/sha-256.o

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/haystack-derived: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean run all

all: $(ODIR)/haystack-derived

clean:
	rm -rf $(ODIR)

run: $(ODIR)/haystack-derived
	$(ODIR)/haystack-derived