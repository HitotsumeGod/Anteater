#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "anteater.h"

bool dump_hex(FILE *fp, char *buf, size_t dumpsz) {

	int counter = 0;
	
	if (!fp || !buf) {
		errno = BAD_ARGS_ERR;
		return false;
	}
	for (int i = 0; i < dumpsz; i++) {
		if (counter == i - PAYLOAD_SPACING) {
			fprintf(fp, "\n");
			counter = i;
		}
		fprintf(fp, "%02X ", (unsigned char) *(buf + i));
	}
	return true;

}

bool dump_text(FILE *fp, char *buf, size_t dumpsz) {

	if (!fp || !buf) {
		errno = BAD_ARGS_ERR;
		return false;
	}
	fprintf(fp, "\t");
	for (int i = 0; i < dumpsz; i++) 
		fprintf(fp, "%c", *(buf + i));
	fprintf(fp, "\n");
	return true;

}