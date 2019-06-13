#pragma once

#pragma warning(disable: 4996)

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<Windows.h>

#define DOS_HEADER_SIZE 0x40

typedef struct _PE_HEADER {
	IMAGE_DOS_HEADER DOS_HEADER;
	BYTE * DOS_STUB;
	IMAGE_NT_HEADERS NT_HEADERS;
	DWORD DOS_STUB_SIZE;
	IMAGE_SECTION_HEADER* SECTION_HEADER_PTR;
	//IMAGE_IMPORT_DESCRIPTOR* IMPORT_DESCRIPTOR_PTR;
}PE_HEADER;

typedef unsigned char BYTE;

int isFileValid(char * filename) {
	FILE * fp = fopen(filename, "r");
	char * sig = (char*)malloc(2);
	fread(sig, 1, 2, fp);
	if (!memcmp(sig, "MZ", 2)) {
		printf("[+]Valid PE File!\n");
		fclose(fp);
		return 1;
	}
	else {
		fclose(fp);
		return 0;
	}
}

DWORD* getRVA(FILE* fp) {
	DWORD* offset = malloc(sizeof(DWORD));
	fread(offset, sizeof(DWORD), 1, fp);
	return offset;
}

char* getContents(FILE* fp, int size) {
	char* contents = malloc(sizeof(char) * size);
	fread(contents, 1, size, fp);
	return contents;
}

char* getFunctionName(FILE* fp) {
	char ch;
	int function_name_size = 1;
	while (1) {
		ch = fgetc(fp);
		if (ch == '\0')
			break;
		function_name_size++;
	}
	fseek(fp, -function_name_size, SEEK_CUR);
	char* function_name = malloc(sizeof(char) * function_name_size);
	memset(function_name, '\0', function_name_size);
	fread(function_name, 1, function_name_size, fp);
	return function_name;
}

char* getFunctionCode(FILE* fp) {
	BYTE ch;
	int function_size = 0;
	while (1) {
		ch = fgetc(fp);
		if (ch == 0xcc)
			break;
		function_size++;
	}
	fseek(fp, -(function_size+1), SEEK_CUR);
	BYTE* function_code = malloc(sizeof(BYTE) * function_size);
	fread(function_code, 1, function_size, fp);
	return function_code;
}

int getSectionNumber(PE_HEADER pe_header, DWORD RVA) {
	for (int i = 0; i < pe_header.NT_HEADERS.FileHeader.NumberOfSections; i++) {
		if (RVA < pe_header.SECTION_HEADER_PTR[i].VirtualAddress)
			return i - 1;
	}
	return pe_header.NT_HEADERS.FileHeader.NumberOfSections - 1;
}

/* offset = RVA - SectionVirtualAddress + SectionPointerToRawData */
DWORD* getOffset(PE_HEADER pe_header, DWORD RVA) {
	int section_number = getSectionNumber(pe_header, RVA);
	DWORD* offset = malloc(sizeof(DWORD));
	if (section_number == -1) {
		*offset = RVA;
		return offset;
	}

	*offset = RVA - pe_header.SECTION_HEADER_PTR[section_number].VirtualAddress + pe_header.SECTION_HEADER_PTR[section_number].PointerToRawData;
	return offset;
}