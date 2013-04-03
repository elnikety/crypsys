bin_PROGRAMS = test

SOURCES=test.c multi_exp.c ../utils/bi_gmp.c ../utils/bi.c ../utils/list.c \
	../include/bi.h ../include/bi_gmp.h
	
OBJECTS= test.o multi_exp.o ../utils/bi_gmp.o ../utils/bi.o ../utils/list.o

LIBS= -lgmp

FLAGS=$(GCC_FLAGS)

all: $(OBJECTS)
	gcc $(OBJECTS) -g $(FLAGS) $(LIBS) -o bi_test

%.o: %.c
	gcc -c $*.c -o $*.o


