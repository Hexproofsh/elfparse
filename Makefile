AS = as
FLAGS = --64
LD = ld

all: elfparse

elfparse: elfparse.o
	$(LD) -o $@ $<

%.o: %.s
	$(AS) $(FLAGS) $< -o $@

clean:
	rm -rf *.o elfparse a.out
