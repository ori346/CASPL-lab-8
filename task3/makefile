all:MYELF

MYELF:task3.c
	gcc -m32 -g -c -o myELF.o task3.c
	gcc -m32 -g -o myELF myELF.o

.PHONY:clean

clean:
	rm *.o myELF