.PHONY: all clean run

CFLAGS = -O2 -g -Wall -Wno-unused -Werror -std=gnu99 -DDEBUG -I../../../../include -I./include

DIR = obj

OBJS = obj/main.o obj/sadb.o obj/rwlock.o obj/sa.o obj/sad.o obj/sp.o obj/spd.o obj/sapd.o
LIB_DIR = ../lib/
LIBS = ../../../../lib/libumpn.a

all: sad_accessor

sad_accessor: $(OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LIBS)

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $< $(LIBS)

clean:
	rm -rf obj
	rm -f sad_accessor

run:
	sudo ./sad_accessor
