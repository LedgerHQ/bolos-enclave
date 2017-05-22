%.o : %.S
	moxiebox-as -c -o $@ $<

libbolos.a : crt0.o bolos_stub.o 
	rm -f libbolos.a
	moxiebox-ar cr libbolos.a crt0.o bolos_stub.o 

clean :
	rm -rf libbolos.a
	rm -rf *.o

		
