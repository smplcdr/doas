
CAT?=cat
SED?=sed
CC?=gcc
YACC=yacc
AWK?=awk
# Force use the US locale for reliable behaviour of locale-dependent programs
SORT?=env LC_ALL=C sort
DATE?=env LC_ALL=C date
PREFIX?=/usr/local
MANDIR?=$(DESTDIR)$(PREFIX)/man
SYSCONFDIR?=$(DESTDIR)$(PREFIX)/etc
OPT?=-std=gnu99 -O2 -fPIE -pipe -ffunction-sections -fdata-sections -Wl,-z,now -Wl,-z,relro -fstack-protector-all -Wl,--gc-sections -pie

DOAS=doas
VIDOAS=vidoas
DOAS_CONF=$(SYSCONFDIR)/doas.conf
DOAS_OBJECTS=doas.o env.o timestamp.o y.tab.o
DOAS_COMPAT_OBJECTS=compat/full-rw.o compat/strtounum.o
VIDOAS_OBJECTS=env.o vidoas.o y.tab.o
VIDOAS_COMPAT_OBJECTS=compat/full-rw.o compat/strtounum.o
CLEANUP=

# Can set GLOBAL_PATH here to set PATH for target user.
# TARGETPATH=-DGLOBAL_PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\"
WARN_CFLAGS = -Wall -Wno-missing-profile -Wextra -Warith-conversion -Wdate-time -Wdisabled-optimization -Wdouble-promotion -Wduplicated-cond -Wextra -Wformat-signedness -Winit-self -Winvalid-pch -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wmissing-prototypes -Wnested-externs -Wnull-dereference -Wold-style-definition -Wopenmp-simd -Wpacked -Wpointer-arith -Wstrict-prototypes -Wsuggest-attribute=format -Wsuggest-attribute=noreturn -Wsuggest-final-methods -Wsuggest-final-types -Wtrampolines -Wuninitialized -Wunknown-pragmas -Wvariadic-macros -Wvector-operation-performance -Wwrite-strings -Warray-bounds=2 -Wattribute-alias=2 -Wformat=2 -Wformat-truncation=2 -Wimplicit-fallthrough=5 -Wshift-overflow=2 -Wvla-larger-than=4031 -Wredundant-decls -Wno-unused-macros -Wno-nested-externs -Wno-redundant-decls -Wno-sign-compare -Wno-missing-field-initializers -Wno-override-init -Wno-sign-compare -Wno-type-limits -Wno-unused-parameter -Wno-format-nonliteral -Wno-missing-field-initializers -Wno-pointer-sign -Wno-missing-prototypes -Wno-missing-declarations

CFLAGS+=-Wall -Wextra $(WARN_CFLAGS) $(OPT) -D_FORTIFY_SOURCE=2 -static -Wno-unused-result
CPPFLAGS+=-I. -DDOAS_CONF=\"$(DOAS_CONF)\" $(TARGETPATH) -D_POSIX_C_SOURCE=200112L -DUSE_TIMESTAMP=1
UNAME_S:=$(shell uname -s 2>/dev/null || echo "unknown")

# PAM, SHADOW, BSD_AUTH
AUTH_MODULE=PAM

ifeq ($(UNAME_S),Linux)
    CPPFLAGS+=-Icompat
    CFLAGS+=-D_GNU_SOURCE=1
    DOAS_COMPAT+=closefrom.o errc.o explicit_bzero.o getprogname.o setprogname.o strlcat.o strlcpy.o strtonum.o reallocarray.o verrc.o vwarnc.o warnc.o
    VIDOAS_COMPAT+=closefrom.o errc.o getprogname.o setprogname.o strtonum.o reallocarray.o verrc.o vwarnc.o warnc.o
endif
ifeq ($(UNAME_S),FreeBSD)
    CFLAGS+=-DHAVE_LOGIN_CAP_H=1 -D__BSD_VISIBLE=1
    CPPFLAGS+=-Icompat
    DOAS_COMPAT+=execvpe.o
    LDFLAGS+=-lutil
endif
ifeq ($(UNAME_S),NetBSD)
    CFLAGS+=-DHAVE_LOGIN_CAP_H=1 -D_OPENBSD_SOURCE=1
    LDFLAGS+=-lutil
endif
ifeq ($(UNAME_S),SunOS)
    SAFE_PATH?=/bin:/sbin:/usr/bin:/usr/sbin:$(PREFIX)/bin:$(PREFIX)/sbin
    GLOBAL_PATH?=/bin:/sbin:/usr/bin:/usr/sbin:$(PREFIX)/bin:$(PREFIX)/sbin
    CPPFLAGS+=-Icompat
    CFLAGS+=-DSOLARIS_PAM=1 -DSAFE_PATH=\"$(SAFE_PATH)\" -DGLOBAL_PATH=\"$(GLOBAL_PATH)\"
    DOAS_COMPAT=errc.o pm_pam_conv.o setresuid.o verrc.o vwarnc.o warnc.o
    VIDOAS_COMPAT=errc.o verrc.o vwarnc.o warnc.o
endif
ifeq ($(UNAME_S),Darwin)
    CPPFLAGS+=-Icompat
    DOAS_COMPAT+=bsd-closefrom.o
    # On MacOS the default man page path is /usr/local/share/man
    MANDIR=$(DESTDIR)$(PREFIX)/share/man
endif

INSTALL_PAM_CONF=
UNINSTALL_PAM_CONF=
ifeq ($(AUTH_MODULE),PAM)
    ifeq ($(UNAME_S),SunOS)
        CFLAGS+=-DSOLARIS_PAM=1
        DOAS_COMPAT+=pm_pam_conv.o
    endif
    ifeq ($(UNAME_S),Linux)
        INSTALL_PAM_CONF+=cp compat/pam.conf.linux /etc/pam.d/doas
        UNINSTALL_PAM_CONF=rm -f /etc/pam.d/doas
    endif
    ifeq ($(UNAME_S),FreeBSD)
        INSTALL_PAM_CONF+=cp compat/pam.conf.freebsd /etc/pam.d/doas
        UNINSTALL_PAM_CONF+=rm -f /etc/pam.d/doas
    endif
    LDFLAGS+=-lpam
    CPPFLAGS+=-DUSE_PAM=1
    DOAS_OBJECTS+=pam.o
    DOAS_COMPAT_OBJECTS+=compat/readpassphrase.o
endif
ifeq ($(AUTH_MODULE),SHADOW)
    CPPFLAGS+=-DUSE_SHADOW=1
    LDFLAGS+=-lcrypt
    DOAS_OBJECTS+=shadow.o
    DOAS_COMPAT_OBJECTS+=compat/readpassphrase.o
endif
ifeq ($(AUTH_MODULE),BSD_AUTH)
    CPPFLAGS+=-DUSE_BSD_AUTH=1
    LDFLAGS+=
    DOAS_OBJECTS+=bsd-auth.o
    DOAS_COMPAT_OBJECTS+=compat/readpassphrase.o
endif

FLEX:=$(shell which flex 2> /dev/null)
LEX:=$(shell which lex 2> /dev/null)
ifneq ($(FLEX),)
    LFLAGS+=--batch --warn -8 --never-interactive -Cfaer --noyywrap --stack
    CPPFLAGS+=-DHAVE_FLEX=1 -DHAVE_LEX=0
else
    ifneq ($(LEX),)
        CPPFLAGS+=-DHAVE_FLEX=0 -DHAVE_LEX=1
    else
        CPPFLAGS+=-DHAVE_FLEX=0 -DHAVE_LEX=0
    endif
endif

ifneq ($(LEX)$(FLEX),)
    CLEANUP+=lex.yy.c
    PARSER_DEPENDENCE+=lex.yy.c
    DOAS_OBJECTS+=lex.yy.o
    VIDOAS_OBJECTS+=lex.yy.o
else
    GPERF:=$(shell which gperf 2> /dev/null)
    ifneq ($(GPERF),)
        CPPFLAGS+=-DHAVE_GPERF=1
        AWKFLAGS=-v HAVE_GPERF=1
        CLEANUP+=get-keyword-by-word.c token-table.gperf
        PARSER_DEPENDENCE=get-keyword-by-word.c
    else
        CPPFLAGS+=-DHAVE_GPERF=0
        AWKFLAGS=-v HAVE_GPERF=0
        CLEANUP+=token-table.c
        PARSER_DEPENDENCE=token-table.c
    endif
endif

DOAS_COMPAT_OBJECTS+=$(DOAS_COMPAT:%.o=compat/%.o)
VIDOAS_COMPAT_OBJECTS+=$(VIDOAS_COMPAT:%.o=compat/%.o)
FINALS=doas.1.final doas.conf.5.final vidoas.8.final

CLEANUP+=$(DOAS) $(DOAS_OBJECTS) $(DOAS_COMPAT_OBJECTS)
CLEANUP+=$(VIDOAS) $(VIDOAS_OBJECTS) $(VIDOAS_COMPAT_OBJECTS)
CLEANUP+=$(FINALS)

all: $(DOAS) $(VIDOAS) $(FINALS)

$(DOAS): $(DOAS_OBJECTS) $(DOAS_COMPAT_OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(VIDOAS): $(VIDOAS_OBJECTS) $(VIDOAS_COMPAT_OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

sort.token-table.def: token-table.def
	cp $< $<-
	$(SORT) $<- > $<
	rm $<-
token-table.gperf: token-table.awk token-table.def token-table.gperf.in
	$(AWK) $(AWKFLAGS) -F: -f token-table.awk token-table.def | cat token-table.gperf.in - > $@
get-keyword-by-word.c: token-table.gperf
	gperf --output-file=$@ $<

token-table.c: token-table.awk sort.token-table.def
	$(AWK) $(AWKFLAGS) -F: -f token-table.awk token-table.def > $@

lex.yy.c: scan.l
	$(FLEX) $(LFLAGS) scan.l

CLEANUP+=y.tab.c
y.tab.c: parse.y $(PARSER_DEPENDENCE)
	$(YACC) -d parse.y

install: $(DOAS) $(FINALS)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $(DOAS) $(DESTDIR)$(PREFIX)/bin/
	chmod 4755 $(DESTDIR)$(PREFIX)/bin/$(DOAS)
	cp $(VIDOAS) $(DESTDIR)$(PREFIX)/bin/
	chmod 755 $(DESTDIR)$(PREFIX)/bin/$(VIDOAS)
	mkdir -p $(MANDIR)/man1
	cp doas.1.final $(MANDIR)/man1/doas.1
	mkdir -p $(MANDIR)/man5
	cp doas.conf.5.final $(MANDIR)/man5/doas.conf.5
	mkdir -p $(MANDIR)/man8
	cp vidoas.8.final $(MANDIR)/man8/vidoas.8
	$(INSTALL_PAM_CONF)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(DOAS)
	rm -f $(DESTDIR)$(PREFIX)/bin/$(VIDOAS)
	rm -f $(MANDIR)/man1/doas.1
	rm -f $(MANDIR)/man5/doas.conf.5
	rm -f $(MANDIR)/man8/vidoas.8
	$(UNINSTALL_PAM_CONF)

clean:
	rm -f $(CLEANUP)

.PHONY: all install uninstall clean

# Doing it this way allows to change the original files
# only partially instead of renaming them.
doas.1.final: doas.1
doas.conf.5.final: doas.conf.5
vidoas.8.final: vidoas.8
$(FINALS):
	$(CAT) $^ | $(SED) 's,@DOAS_CONF@,$(DOAS_CONF),g;s,@ATIME@,$(shell $(DATE) -r $^ -u +"%B the %d %Y"),g' > $@
