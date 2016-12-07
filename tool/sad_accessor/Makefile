.PHONY: all clean run

CFLAGS = -O2 -g -Wall -Wno-unused -Werror -std=gnu99 -DDEBUG

DIR = obj

OBJS = obj/main.o obj/sadb.o

all: sad_accessor

sad_accessor: $(OBJS)
	gcc $(CFLAGS) -o $@ $^

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f sad_accessor

run:
	sudo ./sad_accessor
