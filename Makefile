CFLAGS = -g  -I../lazyusf2/usf -I../lazyusf2 -pthread $(shell pkg-config --cflags libpulse libpulse-simple)
LDFLAGS = -g -lm -lz -lncurses -L../lazyusf2 -llazyusf -lpthread $(shell pkg-config --libs libpulse libpulse-simple)

all: usf_ripper

usf_ripper.o: usf_ripper.c
	gcc $(CFLAGS) -c -o $@ $<

usf_ripper: usf_ripper.o
	gcc -o $@ $< $(LDFLAGS) 

clean: 
	rm -f usf_ripper usf_ripper.o
