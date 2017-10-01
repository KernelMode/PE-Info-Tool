#include <stdio.h>
#include <Windows.h>
#include <time.h>

int main(int argc, char* argv[]) {
	if(argc < 2){
		printf("\nEnter the name of Executable as an arguement\n");
		return 0;
	}
	FILE *file;
	file = fopen(argv[1], "rb"); //Name of PE is passed via command line arguements
	fseek(file, 0, SEEK_END);
	int num = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *buffer = (char*)malloc(num * sizeof(char));
	fread(buffer, 1, num, file);

	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS* NtHeader;

	DOSHeader = PIMAGE_DOS_HEADER(buffer);
	NtHeader = PIMAGE_NT_HEADERS(DWORD(buffer) + DOSHeader->e_lfanew);

	IMAGE_FILE_HEADER FileHeader;
	
	FileHeader = NtHeader->FileHeader;
	time_t aye = (time_t)FileHeader.TimeDateStamp;
	char *time= ctime(&aye);
	printf("\nCompile Date       : %s", time);
	
	int numofsections = FileHeader.NumberOfSections;
	printf("Number of sections : %d\n", numofsections);

	IMAGE_OPTIONAL_HEADER OptionalHeader;
	OptionalHeader = NtHeader->OptionalHeader;

	int RelativeEntry,Baseofcode,Baseofdata,Imagebase,checksum,subsystem;

	Imagebase = OptionalHeader.ImageBase;
	RelativeEntry = OptionalHeader.AddressOfEntryPoint;
	Baseofcode = OptionalHeader.BaseOfCode;
	Baseofdata = OptionalHeader.BaseOfData;
	checksum = OptionalHeader.CheckSum;
	subsystem = OptionalHeader.Subsystem;

	printf("Image Base         : %08x\n", Imagebase);
	printf("Relative Entry Add.: %08x\n", RelativeEntry);
	printf("Base Of Code       : %08x\n", Baseofcode);
	printf("Base Of Data       : %08x\n", Baseofdata);
	printf("Checksum           : %08x\n", checksum);
	printf("SubSystem          : ");

	if (subsystem == 0) {
		printf("Unknown Subsystem\n");
	}
	else if (subsystem == 1) {
		printf("No Subsystem Required\n");
	}
	else if (subsystem == 2) {
		printf("Windows graphical user interface (GUI) subsystem\n");
	}
	else if (subsystem == 3) {
		printf("Windows character-mode user interface (CUI) subsystem(Console Application)\n");
	}
	else if (subsystem == 5) {
		printf("OS/2 CUI subsystem\n");
	}
	else if (subsystem == 7) {
		printf("POSIX CUI subsystem\n");
	}
	else if (subsystem == 9) {
		printf("Windows CE System\n");
	}
	else if (subsystem == 16) {
		printf("Boot Application\n");
	}
	
	IMAGE_SECTION_HEADER *ImageSection;
	BYTE *Name;
	DWORD RelVirtualAdd,PtoRaw,SofRaw,VirtualS;
	for (int i = 0; i < numofsections; i++) {
		ImageSection = PIMAGE_SECTION_HEADER(buffer + DOSHeader->e_lfanew + 248 + (i * 40));
		Name = ImageSection->Name;
		RelVirtualAdd = ImageSection->VirtualAddress;
		PtoRaw = ImageSection->PointerToRawData;
		SofRaw = ImageSection->SizeOfRawData;
		VirtualS = ImageSection->Misc.VirtualSize;

		printf("\nSection - %d\n", i+1);
		printf("Name of Section : %s\n", Name);
		printf("Virtual Size    : %08x\n", VirtualS);
		printf("Relative Virtual Add. : %08x\n", RelVirtualAdd);
		printf("Pointer to RawData : %08x\n", PtoRaw);
		printf("Size of RawData : %08x\n", SofRaw);
	}
	
	fclose(file);
}   
