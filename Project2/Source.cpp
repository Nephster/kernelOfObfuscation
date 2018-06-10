
#include <windows.h>

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_AES_128
#define ENCRYPT_BLOCK_SIZE 16

#pragma optimize("s", on) // for deactive SSE instruction from compiler
#pragma intrinsic(memset)
#pragma function(memset)

extern "C" void * __cdecl memset(void *, int, size_t);

long translateAddrFun(int addr);
int binary_search(int array[], int first, int last, int search_key);
static inline int my_isupper(char c);
static inline int my_isalpha(char c);
static inline int my_isdigit(char c);
static inline int my_isspace(char c);

unsigned long my_strtoul(const char * nptr, char ** endptr, register int base);
long my_strtol(const char * nptr, char ** endptr, register int  base);
FARPROC getFunction(char api_Fun[], DWORD api_len);
DWORD PeSectionEnum(LPVOID lpBase);
void* my_memcpy(void* destination, void* source, size_t num);
void  *my_memset(void *b, int c, int len);
DWORD MyDecryptFile(BYTE * password, char * ReadBuffer, DWORD FileSize, FARPROC lpfnVirtualAlloc, FARPROC lpfnCreateFile, FARPROC lpfnReadFile, FARPROC lpfnlstrcatA, HANDLE hFile, FARPROC lpfnLoadLibrary, FARPROC lpfnGetProcess, FARPROC lpfnstrlen);

typedef LPTSTR(__stdcall	* plstrcatA)(LPTSTR, LPTSTR);
typedef int(__stdcall		* plstrlenA)(LPCTSTR);
typedef DWORD(__stdcall		* pGetCurrentDirectoryA)(DWORD, LPSTR);
typedef DWORD(__stdcall		* pCloseHandle)(HANDLE);
typedef DWORD(__stdcall		* pGetFileSize)(HANDLE, LPDWORD);
typedef LPVOID(__stdcall	* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(__cdecl		* pmemcpy)(PVOID, PVOID, SIZE_T);
typedef SIZE_T(__stdcall	* pRtlCompareMemory)(LPVOID, LPVOID, SIZE_T);
typedef HMODULE(__stdcall	* pLoadLibrary)(LPCTSTR);
typedef HMODULE(__stdcall	* pGetModuleHandle)(LPCTSTR);
typedef FARPROC(__stdcall	* pGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(__stdcall	* pCreateFileA)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(__stdcall	* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(__stdcall		* pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(__stdcall		* pCryptAcquireContext)(HCRYPTPROV*, LPCTSTR, LPCTSTR, DWORD, DWORD);
typedef BOOL(__stdcall		* pCryptImportKey)(HCRYPTPROV, BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
typedef BOOL(__stdcall		* pCryptHashData)(HCRYPTHASH, PBYTE, DWORD, DWORD);
typedef BOOL(__stdcall		* pCryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
typedef BOOL(__stdcall		* pCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, PBYTE,DWORD*);
typedef BOOL(__stdcall		* pCryptDestroyHash)(HCRYPTHASH);
typedef BOOL(__stdcall      * pCryptDestroyKey)(HCRYPTKEY);
typedef BOOL(__stdcall      * pCryptReleaseContext)(HCRYPTPROV,DWORD);

void __declspec(naked) main()
{
	
	__asm
	{			
		
		    push 0                      ;creates space in stack
			pushad                      ;save the state of all registers
			pushfd                      ; save the state of all flags
			push ebp
			mov ebp, esp
			mov ebx, [ebp + 44]         ;pick calling address and save to stack
			sub ebx, 5
			push ebx
			call translateAddrFun
			add esp, 8
			mov[ebp + 40], eax          ;in stack is saving a pointer to function
			popfd
			popad
			add esp, 4
			jmp DWORD PTR SS : [esp - 4];jump to real function address

			nop

			push 0                      
			pushad                      
			pushfd                      
			push ebp
			mov ebp, esp
			mov ebx, [ebp + 44]         
			sub ebx, 5
			push ebx
			call translateAddrFun
			add esp, 8
			mov ebx, [eax]
			mov[ebp + 40], ebx          
			popfd
			popad
			add esp, 4
			jmp DWORD PTR SS : [esp - 4]


	}


}
long __cdecl translateAddrFun(int addr)
{
	HANDLE hFile;
	DWORD  dwBytesRead = 0;
	OVERLAPPED ol = { 0 };
	char tmp_array[9] = { 0 };
	char tmp_array2[7] = { 0 };
	DWORD NumberOfCall = 0;
	DWORD *ArrayOfaddressesComeFrom;
	DWORD *ArrayOfaddressesToCall;
	LPVOID allocMemForAddressComeFrom;
	LPVOID allocMemForAddressToCall;
	LPVOID number;
	
	char GetProcAddress[15] = { 'G', 'e', 't','P','r','o','c','A','d','d','r','e','s','s','\0'};
	char Loadlibrary[12] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y' ,'\0' };
	char kernel[13] = { 'k', 'e', 'r', 'n', 'e', 'l','3','2','.', 'd', 'l', 'l', '\0' };
	char ntdll[11] = { 'N', 't', 'D', 'l', 'l', '.', 'd', 'l', 'l', '\0' };



		
	FARPROC lpfnLoadLibrary = getFunction(Loadlibrary, 11);		//get address of LoadLibrary
	FARPROC lpfnGetProcess = getFunction(GetProcAddress, 14);	//get address of GetProcAddress
	
	pGetProcAddress MyGetProcess;
	MyGetProcess = pGetProcAddress(lpfnGetProcess);
	pLoadLibrary MyLoadLibrary;
	MyLoadLibrary = pLoadLibrary(lpfnLoadLibrary);
		

	HMODULE hKernel = MyLoadLibrary(kernel);
	HMODULE hNtdll = MyLoadLibrary(ntdll);
		
		
	FARPROC   lpfnGetModuleHandle = MyGetProcess(hKernel, (LPCSTR) 534);		//GetModuleHandleA
	FARPROC	  lpfnGetFileSize = MyGetProcess(hKernel, (LPCSTR)497);				//getfilesize
	FARPROC	  lpfnCloseHandle = MyGetProcess(hKernel, (LPCSTR)85);				//cloasehandle
	FARPROC	  lpfnGetCurrentDirectoryA = MyGetProcess(hKernel, (LPCSTR) 449);	//GetCurrentDirectory
	FARPROC   lpfnVirtualAlloc = MyGetProcess(hKernel, (LPCSTR) 1264);			//virtualalloc
	FARPROC   lpfnCreateFile = MyGetProcess(hKernel, (LPCSTR)139);				//createfile
	FARPROC   lpfnReadFile = MyGetProcess(hKernel, (LPCSTR) 961);				//readfile
	FARPROC   lpfnWriteFile = MyGetProcess(hKernel, (LPCSTR) 1324);				//writefile
	FARPROC   lpfnlstrcatA = MyGetProcess(hKernel, (LPCSTR) 1349);				//strcat
	FARPROC   lpfnRtlCompareMemory = MyGetProcess(hNtdll, (LPCSTR) 687);		//rtrlcomaprememory

	FARPROC   lpfnlstrlenA = MyGetProcess(hKernel, (LPCSTR) 1364);

	plstrlenA MylstrlenA;
	MylstrlenA = plstrlenA(lpfnlstrlenA);

	pGetModuleHandle MyGetModuleHandle;
	MyGetModuleHandle = pGetModuleHandle(lpfnGetModuleHandle);

	plstrcatA MylstrcatA;
	MylstrcatA = plstrcatA(lpfnlstrcatA);

	pGetCurrentDirectoryA MyGetCurrentDirectoryA;
	MyGetCurrentDirectoryA = pGetCurrentDirectoryA(lpfnGetCurrentDirectoryA);

	pWriteFile MyWriteFile;
	MyWriteFile = pWriteFile(lpfnWriteFile);

	pCloseHandle MyCloseHandle;
	MyCloseHandle = pCloseHandle(lpfnCloseHandle);

	pRtlCompareMemory MyRtlCompareMemory;
	MyRtlCompareMemory = pRtlCompareMemory(lpfnRtlCompareMemory);

	pGetFileSize MyGetFileSize;
	MyGetFileSize = pGetFileSize(lpfnGetFileSize);

	pReadFile MyReadFile;
	MyReadFile = pReadFile(lpfnReadFile);

	pCreateFileA MyCreateFileA;
	MyCreateFileA = pCreateFileA(lpfnCreateFile);
	
	pVirtualAlloc MyVirtualAlloc;
	MyVirtualAlloc = pVirtualAlloc(lpfnVirtualAlloc);

	HANDLE tmp=MyGetModuleHandle(NULL);
	

	LPVOID address = (LPVOID ) PeSectionEnum(tmp);
		
		if (*(DWORD *)address != NULL && ((DWORD *) address) + sizeof(char) != NULL)
		{					
			allocMemForAddressComeFrom = *(LPVOID *)address;
			allocMemForAddressToCall = *((LPVOID *)address + sizeof(char));
			number = (LPVOID *)address + sizeof(char) + sizeof(char);
			DWORD tmp = (*((DWORD *) number));
			NumberOfCall = (*(DWORD *)tmp);
			ArrayOfaddressesComeFrom = (DWORD *)allocMemForAddressComeFrom;
			ArrayOfaddressesToCall = (DWORD *)allocMemForAddressToCall;

			return ArrayOfaddressesToCall[binary_search((int *)ArrayOfaddressesComeFrom, 0, NumberOfCall, addr)];
		}

		char nameOffile[12]		= { '\\', 'C', 'A', 'L', 'L','e','n','.', 't', 'x', 't', '\0' };
		char nameOfKeyFile[9]	= { '\\', 'k', 'e', 'y', '.', 't', 'x', 't', '\0' };
		char CALLpath[100]		= { 0 };
		char Keypath[100]		= { 0 };

		MyGetCurrentDirectoryA(300, CALLpath);
		MylstrcatA(CALLpath, nameOffile);

		MyGetCurrentDirectoryA(300,Keypath);
		MylstrcatA(Keypath, nameOfKeyFile);

		
		HANDLE hKeyFile = MyCreateFileA(Keypath,               // file to open
										GENERIC_READ,          // open for reading
										FILE_SHARE_READ,       // share for reading
										NULL,                  // default security
										OPEN_EXISTING,         // existing file only
										FILE_ATTRIBUTE_NORMAL, // normal file
										NULL);                 // no attr. template

		if (hKeyFile == INVALID_HANDLE_VALUE)
		{
			 return -1;
		}
		
		DWORD keyFileSize= MyGetFileSize(hKeyFile, 0);
		DWORD dwReaded = 0;
		BYTE *password = (BYTE *)MyVirtualAlloc(NULL, keyFileSize, MEM_COMMIT, PAGE_READWRITE);
		MyReadFile(hKeyFile ,password, keyFileSize, &dwReaded, 0);

		hFile = MyCreateFileA(CALLpath,					// file to open
							  GENERIC_READ,				// open for reading
							  FILE_SHARE_READ,			// share for reading
							  NULL,						// default security
							  OPEN_EXISTING,			// existing file only
				              FILE_ATTRIBUTE_NORMAL ,	// normal file
				              NULL);					// no attr. template

			if (hFile == INVALID_HANDLE_VALUE)
			{
				return -1;
			}


			DWORD fileSize = MyGetFileSize(hFile, NULL);

		

			char* ReadBuffer = (char *)MyVirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
			DWORD file = MyDecryptFile(password, ReadBuffer, fileSize, lpfnVirtualAlloc, lpfnCreateFile, lpfnReadFile, lpfnlstrcatA, hFile, lpfnLoadLibrary, lpfnGetProcess, lpfnlstrlenA);
			
			MyCloseHandle(hFile);
			
			for (unsigned int j = 0; j <= fileSize; j++)		//count the lines in file
			{		
				if ('\n' == ReadBuffer[j])
					++NumberOfCall;
			}
			number = MyVirtualAlloc(NULL, sizeof(DWORD), MEM_COMMIT, PAGE_READWRITE);
			allocMemForAddressComeFrom = MyVirtualAlloc(NULL, NumberOfCall * sizeof(int), MEM_COMMIT, PAGE_READWRITE);
			allocMemForAddressToCall = MyVirtualAlloc(NULL, NumberOfCall * sizeof(int), MEM_COMMIT, PAGE_READWRITE);


			
			*(LPVOID *)address = allocMemForAddressComeFrom;
			address = ((char *)address + sizeof(DWORD));
			*(LPVOID *)address = allocMemForAddressToCall;
			address = ((char *)address + sizeof(DWORD));
			*(LPVOID *)address = number;

			ArrayOfaddressesComeFrom = (DWORD *)allocMemForAddressComeFrom;
			ArrayOfaddressesToCall   = (DWORD *)allocMemForAddressToCall;
			*((DWORD *) number) = NumberOfCall;
			
			char nulaX[3] = { '0', 'x', '\0' };
			char nnula[2] = { '0', '\0' };		//here I change from { '0', '0', '\0' } to { '0','\0' }
			char newline[3] = { '\n', '\r', '\0' };

			for (int i = 0;; i++)
			{

				if (MyRtlCompareMemory(nnula, ReadBuffer, 1) != 1)// and here from MyRtlCompareMemory(nnula, ReadBuffer, 2) != 2) to (MyRtlCompareMemory(nnula, ReadBuffer, 1) != 1)
					break;


				my_memcpy(tmp_array, ReadBuffer, 8);
				tmp_array[8] = '\0';
				
				ArrayOfaddressesComeFrom[i] = (long)my_strtol(tmp_array, NULL, 16);
				
				while (1)
				{
					ReadBuffer++;
					if (MyRtlCompareMemory(nulaX, ReadBuffer, 2) == 2)
					{
						ReadBuffer += 2;
						my_memcpy(tmp_array2, ReadBuffer, 6);
						tmp_array2[6] = '\0';
						ArrayOfaddressesToCall[i] = (long)my_strtol(tmp_array2, NULL, 16);


						while (1)
						{
							ReadBuffer++;
							if (MyRtlCompareMemory(newline, ReadBuffer, 1) == 1)
							{
								ReadBuffer++;
								break;
							}
						}
						break;
					}
				}

			}

		
		
			


	return ArrayOfaddressesToCall[binary_search((int *)ArrayOfaddressesComeFrom, 0, NumberOfCall, addr)];//binary search finds right address of function and return right address of function
			
}


FARPROC __cdecl getFunction(char api_Fun[],DWORD api_len)
{
	DWORD dwKernelBase;
	DWORD dwExportDirecotry;
	DWORD address;

	

	__asm{


			mov ebx, FS:[0x30]; get a pointer to the PEB
			mov ebx, [ebx + 0x0C]		; get PEB->Ldr
			mov ebx, [ebx + 0x14]		; get PEB->Ldr.InMemoryOrderModuleList.Flink(1st entry) containing infomartion about loaded modules for the process
			mov ebx, [ebx]				; 2nd Entry
			mov ebx, [ebx]				; 3rd Entry
			mov ebx, [ebx + 0x10]		; Get Kernel32 Base
			mov dwKernelBase, ebx		; kernel base
			add ebx, [ebx + 0x3C]		; Start of PE header
			mov ebx, [ebx + 0x78]		; RVA of export dir
			add ebx, dwKernelBase		; VA of export dir
			mov dwExportDirecotry, ebx

			mov edx, api_Fun
			mov ecx, api_len
			call GetFunctionAddress
			mov address,eax
			mov	esp, ebp
			pop	ebp
			ret

			


		GetFunctionAddress :
		push ebx
			push esi
			push edi

			mov esi, dwExportDirecotry
			mov esi, [esi + 0x20]; RVA of ENT
			add esi, dwKernelBase; VA of ENT
			xor ebx, ebx
			cld

		looper :
		inc ebx
			lodsd
			add eax, dwKernelBase; eax now points to the string of a function
			push esi; preserve it for the outer loop
			mov esi, eax
			mov edi, edx
			cld
			push ecx
			repe cmpsb
			pop ecx
			pop esi
			jne looper

			dec ebx
			mov eax, dwExportDirecotry
			mov eax, [eax + 0x24]; RVA of EOT
			add eax, dwKernelBase; VA of EOT
			movzx eax, word ptr ss : [ebx * 2 + eax]; eax now holds the ordinal of our function
			mov ebx, dwExportDirecotry
			mov ebx, [ebx + 0x1C]; RVA of EAT
			add ebx, dwKernelBase; VA of EAT
			mov ebx, [eax * 4 + ebx]
			add ebx, dwKernelBase
			mov eax, ebx

			pop edi
			pop esi
			pop ebx
			ret

	}


}

void * __cdecl memset(void *pTarget, int value, size_t cbTarget) {
	unsigned char *p = static_cast<unsigned char *>(pTarget);
	while (cbTarget-- > 0) {
		*p++ = static_cast<unsigned char>(value);
	}
	return pTarget;
}
int binary_search(int array[], int first, int last, int search_key)
{
	int index;

	if (first > last)
		index = -1;

	else
	{
		int mid = (first + last) / 2;

		if (search_key == array[mid])
			index = mid;
		else

			if (search_key < array[mid])
				index = binary_search(array, first, mid - 1, search_key);
			else
				index = binary_search(array, mid + 1, last, search_key);

	} // end if
	return index;
}// end binarySearch
DWORD PeSectionEnum(LPVOID lpBase)
{
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	PIMAGE_SECTION_HEADER	pSectionHeader;
	DWORD VirtualAddressOfSection;
	IMAGE_OPTIONAL_HEADER optionalHeader = { 0 };
	DWORD dwImageBase = 0;

	
	//const LPVOID lpBase = GetModuleHandle(NULL);


	pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{

		DWORD dwOffsetPEheader = (pDosHeader->e_lfanew);
		LPVOID lpAddressOfPEheader = (LPVOID *)(lpBase)+dwOffsetPEheader / 4;												// deleno 4 lebo 4 byti
		pNtHeaders = (PIMAGE_NT_HEADERS)lpAddressOfPEheader;
		optionalHeader = pNtHeaders->OptionalHeader;
		dwImageBase = optionalHeader.ImageBase;

		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return -1;

		pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);		
		DWORD lastSection = pNtHeaders->FileHeader.NumberOfSections;
		VirtualAddressOfSection = (dwImageBase + pSectionHeader[lastSection-1].VirtualAddress);
			
			
		
	}
	return VirtualAddressOfSection + 0xA16;
}
static inline int my_isupper(char c)
{
	return (c >= 'A' && c <= 'Z');
}

static inline int my_isalpha(char c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}


static inline int my_isspace(char c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int my_isdigit(char c)
{
	return (c >= '0' && c <= '9');
}

long my_strtol(const char * nptr, char ** endptr, register int  base)
{
	register const char *s = nptr;
	register signed long acc;
	register int c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;

	do {
		c = *s++;
	} while (my_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	}
	else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
		c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	else if ((base == 0 || base == 2) &&
		c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = neg ? - (signed long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (my_isdigit(c))
			c -= '0';
		else if (my_isalpha(c))
			c -= my_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
		//		errno = ERANGE;
	}
	else if (neg)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (acc);
}

unsigned long my_strtoul(const char * nptr, char ** endptr, register int base)
{
	register const char *s = nptr;
	register signed long acc;
	register int c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;

	/*
	* See strtol for comments as to the logic used.
	*/
	do {
		c = *s++;
	} while (my_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	}
	else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
		c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	else if ((base == 0 || base == 2) &&
		c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
	cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (my_isdigit(c))
			c -= '0';
		else if (my_isalpha(c))
			c -= my_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = ULONG_MAX;
		//		errno = ERANGE;
	}
	else if (neg)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (acc);
}

void* my_memcpy(void* destination, void* source, size_t num)
{
	unsigned int i;
	char* d = (char *)destination;
	char* s = (char *)source;
	for (i = 0; i < num; i++) {
		d[i] = s[i];
	}
	return destination;
}
DWORD MyDecryptFile(BYTE * password,
	char * ReadBuffer,
	DWORD FileSize,
	FARPROC lpfnVirtualAlloc,
	FARPROC lpfnCreateFile,
	FARPROC lpfnReadFile,
	FARPROC lpfnlstrcatA,
	HANDLE hFile,
	FARPROC lpfnLoadLibrary,
	FARPROC lpfnGetProcess,
	FARPROC lpfnlstrlenA)
{
	//---------------------------------------------------------------
	// Declare and initialize local variables.
	bool fReturn = false;
	
	HCRYPTKEY hKey = 0;
	HCRYPTHASH hHash = 0;


	HCRYPTPROV hProvider = 0;
	DWORD dwCount = 0;
	PBYTE pbBuffer = 0;
	char advapi[13] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', '\0' };

	pGetProcAddress MyGetProcess;
	MyGetProcess = pGetProcAddress(lpfnGetProcess);
	pLoadLibrary MyLoadLibrary;
	MyLoadLibrary = pLoadLibrary(lpfnLoadLibrary);

	HMODULE hAdvapi = MyLoadLibrary(advapi);
	FARPROC   lpfnCryptAcquireContext = MyGetProcess(hAdvapi,(LPCSTR) 1178);
	//FARPROC   lpfnCryptAcquireContext = MyGetProcess(hAdvapi, cryptacquirecontext);
	//FARPROC   lpfnCryptDecrypt = MyGetProcess(hAdvapi, "CryptDecrypt");
	FARPROC   lpfnCryptDecrypt = MyGetProcess(hAdvapi, (LPCSTR) 1182);
//	FARPROC   lpfnCryptImportKey = MyGetProcess(hAdvapi, "CryptImportKey");Cryc
	FARPROC   lpfnCryptImportKey = MyGetProcess(hAdvapi, (LPCSTR) 1204);
	FARPROC   lpfnCryptDestroyKey = MyGetProcess(hAdvapi, (LPCSTR) 1185);
	FARPROC   lpfnCryptReleaseContext = MyGetProcess(hAdvapi, (LPCSTR)1205);

	plstrlenA MylstrlenA;
	MylstrlenA = plstrlenA(lpfnlstrlenA);

	pCryptAcquireContext MyCryptAcquireContext;
	MyCryptAcquireContext = pCryptAcquireContext(lpfnCryptAcquireContext);


	pCryptImportKey MyCryptImportKey;
	MyCryptImportKey = pCryptImportKey(lpfnCryptImportKey);

	pCryptDecrypt MyCryptDecrypt;
	MyCryptDecrypt = pCryptDecrypt(lpfnCryptDecrypt);

	pCryptDestroyKey MyCryptDestroyKey;
	MyCryptDestroyKey = pCryptDestroyKey(lpfnCryptDestroyKey);

	pCryptReleaseContext MyCryptReleaseContext;
	MyCryptReleaseContext = pCryptReleaseContext(lpfnCryptReleaseContext);

	pReadFile MyReadFile;
	MyReadFile = pReadFile(lpfnReadFile);

	pCreateFileA MyCreateFileA;
	MyCreateFileA = pCreateFileA(lpfnCreateFile);

	pVirtualAlloc MyVirtualAlloc;
	MyVirtualAlloc = pVirtualAlloc(lpfnVirtualAlloc);

	plstrcatA MylstrcatA;
	MylstrcatA = plstrcatA(lpfnlstrcatA);

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (!MyCryptAcquireContext(&hProvider, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
		return -1;



	if (!MyCryptImportKey(
		hProvider,
		password,
		16,
		0,
		0,
		&hKey))
	{
			return -4;
	}




	DWORD dwBlockLen = FileSize - FileSize % ENCRYPT_BLOCK_SIZE;
	DWORD dwBufferLen = dwBlockLen;

	if (!(pbBuffer = (PBYTE)MyVirtualAlloc(NULL, dwBufferLen, MEM_COMMIT, PAGE_READWRITE)))
	{
		return - 5;
	}



	bool fEOF = false;
	do
	{

		if (!MyReadFile(
			hFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			return -6;
		}

		if (dwCount <= dwBlockLen)
		{
			fEOF = TRUE;
		}


		if (!MyCryptDecrypt(
			hKey,
			0,
			fEOF,
			0,
			pbBuffer,
			&dwCount))
		{
			return -7;
		}


		MylstrcatA(ReadBuffer, (LPSTR) pbBuffer);
	} while (!fEOF);

	fReturn = true;



	//---------------------------------------------------------------
	// Close files.


	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(MyCryptDestroyKey(hKey)))
		{
			return false;
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hProvider)
	{
		if (!(MyCryptReleaseContext(hProvider, 0)))
		{
			return 0;
		}
	}

	return  0;
}


