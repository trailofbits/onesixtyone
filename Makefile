onesixtyone: onesixtyone.c
	gcc $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o onesixtyone onesixtyone.c

solaris: onesixtyone.c
	cc -o onesixtyone onesixtyone.c -lsocket -lnsl

clean:
	rm -rf onesixtyone

.PHONY: solaris clean
