CC		= gcc
CFLAGS  = -Wall -g -shared -fPIC
LDFLAGS = -ldl
PROGS   = sandbox.so

.PHONY: $(PROGS) clean

all: $(PROGS)

$(PROGS): sandbox.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

clean:
	rm -f *.html sandbox.so *.log *.html.*

	
