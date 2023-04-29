#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s executable(.exe)\n", argv[0]);
        return 1;
    }
    // Open the input file
    HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file\n");
        return 1;
    }
    //calculate size
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        printf("Error getting file size\n");
        CloseHandle(hFile);
        return 1;
    }
    //read file
    LPBYTE lpFileData = (LPBYTE)malloc(dwFileSize);
    DWORD dwBytesRead;
    if (!ReadFile(hFile, lpFileData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) {
        printf("Error reading file\n");
        CloseHandle(hFile);
        free(lpFileData);
        return 1;
    }
    //locate PE header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Not a valid DOS executable\n");
        CloseHandle(hFile);
        free(lpFileData);
        return 1;
    }
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpFileData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Not a valid PE file\n");
        CloseHandle(hFile);
        free(lpFileData);
        return 1;
    }
    //locate .text
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (strcmp((const char*)pSectionHeader->Name, ".text") == 0) {
            break;
        }
    }
    if (strcmp((const char*)pSectionHeader->Name, ".text") != 0) {
        printf("Error: .text section not found\n");
        CloseHandle(hFile);
        free(lpFileData);
        return 1;
    }
    printf("unsigned char shellcode[] = \n\"");
    size_t i;
    DWORD shellcode_len = pSectionHeader->SizeOfRawData;
    for (i = 0; i < shellcode_len; i++) {
        printf("\\x%02x", lpFileData[pSectionHeader->PointerToRawData + i]);
        if ((i+1) % 20 == 0) { // break line every 20 bytes
            printf("\"\n\"");
        }
    }
    printf("\";\n");
    CloseHandle(hFile);
    free(lpFileData);
    return 0;
}
