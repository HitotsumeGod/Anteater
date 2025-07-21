CC=gcc
WCC=x86_64-w64-mingw32-gcc
DBG=valgrind
SRC=src/linux/main
WSRC=src/windows/main
DEPS=src/linux/headers
WDEPS=src/windows/headers
BUILD=build
BIN=bin
CURRENTVERSION=anteater-beta-v1.0
CLONE=$(CURRENTVERSION)
ZIP=tar
SRS=$(SRC)/pilot.c $(SRC)/recv.c $(SRC)/print.c $(SRC)/process.c
WSRS=$(WSRC)/pilot.c $(WSRC)/recv.c $(WSRC)/print.c $(WSRC)/process.c

linux: $(BUILD)/pilot
win: $(BUILD)/pilot.exe
$(BUILD)/pilot: $(SRS) $(BUILD)
	$(CC) -o $@ $(SRS) -I $(DEPS) -g
$(BUILD)/pilot.exe: $(WSRS) $(BUILD)
	$(WCC) -o $@ $(WSRS) -I $(WDEPS) -g
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
