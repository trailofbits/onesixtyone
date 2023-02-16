CC ?= gcc
DESTDIR ?= /
prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
datarootdir ?= $(prefix)/share
datadir ?= $(datarootdir)
mandir ?= $(datarootdir)/man
man1dir ?= $(mandir)/man1

onesixtyone: onesixtyone.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o onesixtyone onesixtyone.c

solaris: onesixtyone.c
	cc -o onesixtyone onesixtyone.c -lsocket -lnsl

clean:
	rm -rf onesixtyone

install:
	install -D onesixtyone $(DESTDIR)$(bindir)/onesixtyone
	install -D -m 0644 dict.txt $(DESTDIR)$(datadir)/onesixtyone/dict.txt
	install -m 0644 -pD onesixtyone.1 $(DESTDIR)$(man1dir)/onesixtyone.1


.PHONY: solaris clean
