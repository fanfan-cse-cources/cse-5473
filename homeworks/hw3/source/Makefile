all: task-4_1 task-4_2

task-4_1: task-4_1.o
	gcc task-4_1.o -o task-4_1 -lcrypto

task-4_1.o: task-4.c
	gcc -D FIRST -g -c -o task-4_1.o task-4.c

task-4_2: task-4_2.o
	gcc task-4_2.o -o task-4_2 -lcrypto

task-4_2.o: task-4.c
	gcc -D SECOND -g -c -o task-4_2.o task-4.c

clean:
	rm -rf *.o task-4_1 task-4_2
