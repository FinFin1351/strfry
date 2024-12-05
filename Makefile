CFLAGS += -g -fsanitize=address
CXXFLAGS += -g -fsanitize=address
LDFLAGS += -fsanitize=address
BIN  ?= strfry
APPS ?= dbutils relay mesh
OPT  ?= -O1 -g

include golpe/rules.mk

LDLIBS += -lsecp256k1 -lzstd
INCS += -Iexternal/negentropy/cpp

build/StrfryTemplates.h: $(shell find src/tmpls/ -type f -name '*.tmpl')
	PERL5LIB=golpe/vendor/ perl golpe/external/templar/templar.pl src/tmpls/ strfrytmpl $@

src/apps/relay/RelayWebsocket.o: build/StrfryTemplates.h

export ASAN_OPTIONS=abort_on_error=1:log_path=/tmp/asan.log:verbosity=1
