all:MYELF

MYELF:task1.c
	gcc -m32 -g -c -o myELF.o task1.c
	gcc -m32 -g -o myELF myELF.o

.PHONY:clean

clean:
	rm *.o myELF