CC=gcc
DBG=valgrind
SRC=src/main
DEPS=src/headers
BUILD=build
SRS=$(SRC)/pilot.c

$(BUILD)/pilot: $(SRS) $(BUILD)
	$(CC) -o $@ $(SRS) -I $(DEPS) -g
$(BUILD):
	if ! [ -d $@ ]; then		\
		mkdir $@;		\
	fi
debug: $(BUILD)/pilot
	$(DBG) --leak-check=full --show-leak-kinds=all --track-origins=yes -s $^ a
clean:
	rm -rf $(BUILD)
	rm -f hexdumps
	rm -rf vgcore.*
	rm -rf *.html
	rm -rf *.html.*
