
## Build the securepass module
##


ifneq ($(shell which apxs2),)
APXS_PATH = apxs2
else
APXS_PATH = apxs
endif

APACHE_PATH = $(shell $(APXS_PATH) -q progname)
ifneq ($(shell $(APACHE_PATH) -v | grep 2\.4\.),)
APACHE_2_4=1
else 
APACHE_2_4=0
endif

# Note that gcc flags are passed through apxs, so preface with -Wc
MY_LDFLAGS=-lcurl
MY_CFLAGS=-Wc,-I. -Wc,-Wall -DAPACHE_2_4=$(APACHE_2_4)
SRCS=mod_authz_securepass.c jsmn.c
HDRS=jsmn.h
BUILDDIR := build

.SUFFIXES: .c .o .la

all:  build/.libs/mod_authz_securepass.so

.PHONY: builddir
builddir: build

$(BUILDDIR):
	@mkdir -p $@

$(BUILDDIR)/.libs/mod_authz_securepass.so: $(SRCS) $(HDRS) | $(BUILDDIR)
	@cd $(BUILDDIR) && for file in $(SRCS) $(HDRS) ; do ln -sf ../$$file . ; done
	@cd $(BUILDDIR) && $(APXS_PATH) $(MY_LDFLAGS) $(MY_CFLAGS) -c $(subst src/,,$(SRCS))

install: all
	$(APXS_PATH) -i $(BUILDDIR)/mod_authz_securepass.la

clean:
	-rm -rf $(BUILDDIR)

