CC=gcc
DBG=valgrind
SRC=src/main
DEPS=src/headers
BUILD=build
BIN=bin
CURRENTVERSION=anteater-alpha-v1.1
CLONE=$(CURRENTVERSION)
ZIP=tar
SRS=$(SRC)/pilot.c $(SRC)/recv.c $(SRC)/print.c $(SRC)/process.c

$(BUILD)/pilot: $(SRS) $(BUILD)
	$(CC) -o $@ $(SRS) -I $(DEPS) -g
prod: $(SRS) $(BUILD) $(BIN) $(CLONE)
	$(CC) -o $(BUILD)/anteater $(SRS) -I $(DEPS)
	mv $(BUILD)/anteater $(BIN)/
	rm -rf $(BUILD)
	- cp -r * $(CLONE)/
	rm -rf $(CLONE)/$(CLONE)
	$(ZIP) -cvzf $(CURRENTVERSION).tar.gz $(CLONE)
	rm -rf $(BIN)
	rm -rf $(CLONE)
debug: $(BUILD)/pilot
	$(DBG) --leak-check=full --show-leak-kinds=all --track-origins=yes -s $^ -all
clean:
	rm -rf $(BUILD)
	rm -rf $(BIN)
	rm -rf $(CLONE)
	rm -f hexdumps
	rm -rf vgcore.*
	rm -rf *.tar
	rm -rf *.gz
$(BUILD):
	if ! [ -d $@ ]; then		\
		mkdir $@;		\
	fi
$(BIN):
	if ! [ -d $@ ]; then		\
		mkdir $@;		\
	fi
$(CLONE):
	if ! [ -d $@ ]; then		\
		mkdir $@;		\
	fi
