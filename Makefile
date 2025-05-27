CC=gcc
DBG=valgrind
SRC=src/main
DEPS=src/headers
BUILD=build
SRS=$(SRC)/pilot.c $(SRC)/funcs.c

$(BUILD)/pilot: $(SRS) $(BUILD)
	$(CC) -o $@ $(SRS) -I $(DEPS) -g
$(BUILD):
	if ! [ -d $@ ]; then		\
		mkdir $@;		\
	fi
clean:
	rm -rf $(BUILD)
	rm -rf vgcore.*
	rm -rf *.html
	rm -rf *.html.*
