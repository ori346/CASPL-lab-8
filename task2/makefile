all:MYELF

MYELF:task2.c
	gcc -m32 -g -c -o myELF.o task2.c
	gcc -m32 -g -o myELF myELF.o

.PHONY:clean

clean:
	rm *.o myELF