
## Build the securepass module
##


ifneq ($(shell which apxs2),)
APXS_PATH = apxs2
else
APXS_PATH = apxs
endif

# Note that gcc flags are passed through apxs, so preface with -Wc
MY_LDFLAGS=-lcurl
MY_CFLAGS=-Wc,-I. -Wc,-Wall
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

install_debian: mod_authz_securepass.c jsmn.c
	apxs2 -c -l curl mod_authz_securepass.c jsmn.c
	#apxs2 -i -a mod_authz_securepass.la
	install -m 644 .libs/mod_authz_securepass.so /usr/lib/apache2/modules/
	install -m 644 securepass.load /etc/apache2/mods-available


install_redhat: mod_authz_securepass.c
	apxs -c -l curl mod_authz_securepass.c jsmn.c
	apxs -i -a mod_authz_securepass.la
	#echo "LoadModule authz_securepass_module /etc/httpd/modules/mod_authz_securepass.so" > /etc/httpd/conf.d/mod_authz_securepass.conf

clean:
	-rm -rf $(BUILDDIR)

