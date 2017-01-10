.PHONY: run all depend clean
#-nostdinc 
CFLAGS = -I./include -I ../../include -O2 -Wall -g -m64 -ffreestanding -std=gnu99 -Werror -fno-stack-protector 
DIR = obj 

OBJS = obj/crypto.o obj/auth.o obj/main.o obj/sapd.o obj/sa.o obj/sp.o obj/sad.o obj/spd.o\
       obj/ipsec.o obj/rwlock.o obj/route.o

LIBS = --start-group /home/sungho/Project/penguin/lib/libpacketngin.a /home/sungho/Project/penguin/lib/libcrypto.a --end-group

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o ipsec $^ $(LIBS) 

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f ipsec
