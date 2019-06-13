#include "PEParser.h"

FILE* fr;
FILE* fw;
PE_HEADER pe_header;

/* parse DOS_HEADER */
int parseDOSHeader(FILE* fp) {
	// check Magic number
	if (!memcmp(getContents(fp, 2), "MZ", 2)) {
		printf("[+]Valid Magic Number!\n");
	}
	else {
		fclose(fp);
		return 0;
	}
	// assign NT_HEADER_ADDRRESS to buffer
	fseek(fp, 0x40 - 4, SEEK_SET);
	memcpy(&pe_header.DOS_HEADER.e_lfanew, getRVA(fp), 4);
	
	return 1;
}

/* parse NT_HEADERS */
int parseNTHeader(FILE* fp) {
	// check PE Signature
	fseek(fp, pe_header.DOS_HEADER.e_lfanew, SEEK_SET);
	if (!memcmp(getContents(fp, 4), "PE", 4)) {
		printf("[+]Valid PE Signature!\n");
	}
	else {
		fclose(fp);
		return 0;
	}
	// parse FILE HEADER
	memcpy(&pe_header.NT_HEADERS.FileHeader.Machine, getContents(fp, 2), 2);
	memcpy(&pe_header.NT_HEADERS.FileHeader.NumberOfSections, getContents(fp, 2), 2);
	fseek(fp, 12, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.FileHeader.SizeOfOptionalHeader, getContents(fp, 2), 2);
	memcpy(&pe_header.NT_HEADERS.FileHeader.Characteristics, getContents(fp, 2), 2);
	// assign OPTIONAL HEADER
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.Magic, getContents(fp, 2), 2);
	fseek(fp, 14, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.AddressOfEntryPoint, getContents(fp, 4), 4);
	fseek(fp, 8, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.ImageBase, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SectionAlignment, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.FileAlignment, getContents(fp, 4), 4);
	fseek(fp, 16, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SizeOfImage, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SizeOfHeaders, getContents(fp, 4), 4);
	fseek(fp, 4, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.Subsystem, getContents(fp, 2), 2);
	fseek(fp, 22, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes, getContents(fp, 4), 4);
	for (int i = 0; i < 16; i++) {
		memcpy(&pe_header.NT_HEADERS.OptionalHeader.DataDirectory[i].VirtualAddress, getContents(fp, 4), 4);
		memcpy(&pe_header.NT_HEADERS.OptionalHeader.DataDirectory[i].Size, getContents(fp, 4), 4);
	}
	printf("NT_HEADER size : 0x%X\n", ftell(fp) - pe_header.DOS_HEADER.e_lfanew);

	return 1;
}

/* parse SECTION_HEADER */
int parseSectionHeader(FILE* fp) {
	//BYTE *a = getContents(fp, 8);
	pe_header.SECTION_HEADER_PTR = malloc(sizeof(IMAGE_SECTION_HEADER) * pe_header.NT_HEADERS.FileHeader.NumberOfSections);
	for (int i = 0; i < pe_header.NT_HEADERS.FileHeader.NumberOfSections; i++) {
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Name, getContents(fp, 8), sizeof(BYTE) * 8);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Misc.VirtualSize, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].VirtualAddress, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].SizeOfRawData, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToRawData, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToRelocations, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToLinenumbers, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].NumberOfRelocations, getContents(fp, 2), 2);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].NumberOfLinenumbers, getContents(fp, 2), 2);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Characteristics, getContents(fp, 4), 4);
	}

	return 1;
}

/* parse IMAGE_EXPORT_DIRECTORY */
int parseExportTable(FILE* fp) {
	IMAGE_EXPORT_DIRECTORY ied;
	// build IMAGE_EXPORT_DIRECTORY
	DWORD RAW = *getOffset(pe_header, pe_header.NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (RAW) {
		fseek(fp, RAW, SEEK_SET);
		memcpy(&ied.Characteristics, getContents(fp, 4), 4);
		memcpy(&ied.TimeDateStamp, getContents(fp, 4), 4);
		memcpy(&ied.MajorVersion, getContents(fp, 2), 2);
		memcpy(&ied.MinorVersion, getContents(fp, 2), 2);
		memcpy(&ied.Name, getContents(fp, 4), 4);
		memcpy(&ied.Base, getContents(fp, 4), 4);
		memcpy(&ied.NumberOfFunctions, getContents(fp, 4), 4);
		memcpy(&ied.NumberOfNames, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfFunctions, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfNames, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfNameOrdinals, getContents(fp, 4), 4);

		DWORD *EAT_offset;
		DWORD *ENPT_offset;
		DWORD *EOT_offset;
		DWORD *Name_offset;
		EAT_offset = getOffset(pe_header, ied.AddressOfFunctions);
		ENPT_offset = getOffset(pe_header, ied.AddressOfNames);
		EOT_offset = getOffset(pe_header, ied.AddressOfNameOrdinals);
		for (int i = 0; i < ied.NumberOfNames; i++) {
			fseek(fp, *ENPT_offset, SEEK_SET);
			Name_offset = getOffset(pe_header, *getRVA(fp));
			*ENPT_offset = ftell(fp);

			fseek(fp, *Name_offset, SEEK_SET);
			char* function_name = getFunctionName(fp);
			//printf("%s\n", getContents(fp, 50));

			fseek(fp, *EOT_offset, SEEK_SET);
			WORD ordinal;
			memcpy(&ordinal, getContents(fp, 2), 2);
			//printf("0x%X\n", ordinal);
			*EOT_offset = ftell(fp);

			fseek(fp, *EAT_offset + ordinal * 4, SEEK_SET);
			DWORD function_rva;
			DWORD function_offset;
			memcpy(&function_rva, getContents(fp, 4), 4);
			memcpy(&function_offset, getOffset(pe_header, function_rva), 4);
			//printf("0x%X\n", function_offset);

			fseek(fp, *getOffset(pe_header, function_rva), SEEK_SET);
			BYTE* function_code;
			function_code = getFunctionCode(fp);
			//printf("%X\n", _msize(function));

			fprintf(fw, "%s,0x%X,0x%X,", function_name, function_rva, function_offset, function_code);
			for (int j = 0; j < _msize(function_code); j++) {
				fprintf(fw, "%02X", function_code[j]);
			}
			fprintf(fw, "\n");
		}
	}

	return 1;
}

/* Not Used */
int parseImportTable(FILE* fp) {

}

int main(int argc, char *argv[]) {
	if (argc<2) {
		printf("No Args!\n");
		exit(1);
	}

	// PE_HEADER pe_header;
	FILE * fp = fopen(argv[1], "rb");

	FILE * fw = fopen("./export_func_info.csv", "wb");
	fprintf(fw, "%s,%s,%s,%s\n", "function", "RVA", "offset", "code");

	/* parse DOS_HEADER */
	// check Magic number
	if (!memcmp(getContents(fp, 2), "MZ", 2)) {
		printf("[+]Valid Magic Number!\n");
	}
	else {
		fclose(fp);
		return 0;
	}
	// assign NT_HEADER_ADDRRESS to buffer
	fseek(fp, 0x40 - 4, SEEK_SET);
	memcpy(&pe_header.DOS_HEADER.e_lfanew, getRVA(fp), 4);

	/* parse NT_HEADER */
	// check PE Signature
	fseek(fp, pe_header.DOS_HEADER.e_lfanew, SEEK_SET);
	if (!memcmp(getContents(fp, 4), "PE", 4)) {
		printf("[+]Valid PE Signature!\n");
	}
	else {
		fclose(fp);
		return 0;
	}
	// parse FILE HEADER
	memcpy(&pe_header.NT_HEADERS.FileHeader.Machine, getContents(fp, 2), 2);
	memcpy(&pe_header.NT_HEADERS.FileHeader.NumberOfSections, getContents(fp, 2), 2);
	fseek(fp, 12, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.FileHeader.SizeOfOptionalHeader, getContents(fp, 2), 2);
	memcpy(&pe_header.NT_HEADERS.FileHeader.Characteristics, getContents(fp, 2), 2);
	// assign OPTIONAL HEADER
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.Magic, getContents(fp, 2), 2);
	fseek(fp, 14, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.AddressOfEntryPoint, getContents(fp, 4), 4);
	fseek(fp, 8, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.ImageBase, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SectionAlignment, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.FileAlignment, getContents(fp, 4), 4);
	fseek(fp, 16, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SizeOfImage, getContents(fp, 4), 4);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.SizeOfHeaders, getContents(fp, 4), 4);
	fseek(fp, 4, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.Subsystem, getContents(fp, 2), 2);
	fseek(fp, 22, SEEK_CUR);
	memcpy(&pe_header.NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes, getContents(fp, 4), 4);
	for (int i = 0; i < 16; i++) {
		memcpy(&pe_header.NT_HEADERS.OptionalHeader.DataDirectory[i].VirtualAddress, getContents(fp, 4), 4);
		memcpy(&pe_header.NT_HEADERS.OptionalHeader.DataDirectory[i].Size, getContents(fp, 4), 4);
	}
	printf("NT_HEADER size : 0x%X\n", ftell(fp) - pe_header.DOS_HEADER.e_lfanew);
	
	/* parse SECTION_HEADER */
	//BYTE *a = getContents(fp, 8);
	pe_header.SECTION_HEADER_PTR = malloc(sizeof(IMAGE_SECTION_HEADER) * pe_header.NT_HEADERS.FileHeader.NumberOfSections);
	for (int i = 0; i < pe_header.NT_HEADERS.FileHeader.NumberOfSections; i++) {
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Name, getContents(fp, 8), sizeof(BYTE) * 8);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Misc.VirtualSize, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].VirtualAddress, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].SizeOfRawData, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToRawData, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToRelocations, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].PointerToLinenumbers, getContents(fp, 4), 4);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].NumberOfRelocations, getContents(fp, 2), 2);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].NumberOfLinenumbers, getContents(fp, 2), 2);
		memcpy(&pe_header.SECTION_HEADER_PTR[i].Characteristics, getContents(fp, 4), 4);
	}
	
	/* parse IMAGE_EXPORT_DIRECTORY */
	IMAGE_EXPORT_DIRECTORY ied;
	// build IMAGE_EXPORT_DIRECTORY
	DWORD RAW = *getOffset(pe_header, pe_header.NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (RAW) {
		fseek(fp, RAW, SEEK_SET);
		memcpy(&ied.Characteristics, getContents(fp, 4), 4);
		memcpy(&ied.TimeDateStamp, getContents(fp, 4), 4);
		memcpy(&ied.MajorVersion, getContents(fp, 2), 2);
		memcpy(&ied.MinorVersion, getContents(fp, 2), 2);
		memcpy(&ied.Name, getContents(fp, 4), 4);
		memcpy(&ied.Base, getContents(fp, 4), 4);
		memcpy(&ied.NumberOfFunctions, getContents(fp, 4), 4);
		memcpy(&ied.NumberOfNames, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfFunctions, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfNames, getContents(fp, 4), 4);
		memcpy(&ied.AddressOfNameOrdinals, getContents(fp, 4), 4);

		DWORD *EAT_offset;
		DWORD *ENPT_offset;
		DWORD *EOT_offset;
		DWORD *Name_offset;
		EAT_offset = getOffset(pe_header, ied.AddressOfFunctions);
		ENPT_offset = getOffset(pe_header, ied.AddressOfNames);
		EOT_offset = getOffset(pe_header, ied.AddressOfNameOrdinals);
		for (int i = 0; i < ied.NumberOfNames; i++) {
			fseek(fp, *ENPT_offset, SEEK_SET);
			Name_offset = getOffset(pe_header, *getRVA(fp));
			*ENPT_offset = ftell(fp);

			fseek(fp, *Name_offset, SEEK_SET);
			char* function_name = getFunctionName(fp);
			//printf("%s\n", getContents(fp, 50));

			fseek(fp, *EOT_offset, SEEK_SET);
			WORD ordinal;
			memcpy(&ordinal, getContents(fp, 2), 2);
			//printf("0x%X\n", ordinal);
			*EOT_offset = ftell(fp);

			fseek(fp, *EAT_offset + ordinal * 4, SEEK_SET);
			DWORD function_rva;
			DWORD function_offset;
			memcpy(&function_rva, getContents(fp, 4), 4);
			memcpy(&function_offset, getOffset(pe_header, function_rva), 4);
			//printf("0x%X\n", function_offset);

			fseek(fp, *getOffset(pe_header, function_rva), SEEK_SET);
			BYTE* function_code;
			function_code = getFunctionCode(fp);
			//printf("%X\n", _msize(function));

			fprintf(fw, "%s,0x%X,0x%X,", function_name, function_rva, function_offset, function_code);
			for (int j = 0; j < _msize(function_code); j++) {
				fprintf(fw, "%02X", function_code[j]);
			}
			fprintf(fw, "\n");
		}
	}

	/* parse IMPORT Directory Table */
	/*
	IMAGE_IMPORT_DESCRIPTOR idt;
	// build IMAGE_IMPORT_DISCRIPTOR
	RAW = *getOffset(pe_header, pe_header.NT_HEADERS.OptionalHeader.DataDirectory[1].VirtualAddress);
	if (RAW) {
	}
	*/

	fclose(fp);
	fclose(fw);

	return 1;
}