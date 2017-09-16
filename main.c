#include <stdio.h>
#include <Windows.h>
#include <time.h>

int main(int argc, char* argv[]) {
	FILE *file;
	file = fopen(argv[1], "rb"); //Name of PE is passed via command line arguements
	fseek(file, 0, SEEK_END);
	int num = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *buffer = (char*)malloc(num);
	fread(buffer, 1, num, file);

	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS* NtHeader;

	DOSHeader = PIMAGE_DOS_HEADER(buffer);
	NtHeader = PIMAGE_NT_HEADERS(DWORD(buffer) + DOSHeader->e_lfanew);

	IMAGE_FILE_HEADER FileHeader;
	
	FileHeader = NtHeader->FileHeader;
	time_t aye = (time_t)FileHeader.TimeDateStamp;
	char *time= ctime(&aye);
	printf("This file was compiled on %s", time);
	fclose(file);
}   
