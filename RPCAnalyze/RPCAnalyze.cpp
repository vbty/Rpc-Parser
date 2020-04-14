#include "RPCAnalyze.h"

RPCAnalyze::RPCAnalyze(LPCSTR FileName,LPCSTR SymbolPath)
{
	RtlCopyMemory(TargetImagePath, FileName, MAX_PATH);
	RtlCopyMemory(this->SymbolPath, SymbolPath, MAX_PATH);
}

RPCAnalyze::RPCAnalyze(LPCSTR FileName)
{
	RtlCopyMemory(TargetImagePath, FileName, MAX_PATH);
}

RPCAnalyze::~RPCAnalyze()
{
	UnmapViewOfFile(this->ImageBase);
}

BOOLEAN RPCAnalyze::MapTargetImage(VOID)
{
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	PVOID MapStartAddr = NULL;

	FileHandle = CreateFileA(TargetImagePath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_ALWAYS,
		0,
		NULL);
	if (!FileHandle)
	{
		this->LastError = GetLastError();
		return FALSE;
	}

	SectionHandle = CreateFileMapping(FileHandle,
		NULL,
		SEC_IMAGE | PAGE_READONLY,
		0,
		0,
		NULL);
	if (!SectionHandle)
	{
		this->LastError = GetLastError();
		return FALSE;
	}

	MapStartAddr = MapViewOfFile(SectionHandle,
		FILE_MAP_READ,
		0,
		0,
		0);
	if (!MapStartAddr)
	{
		this->LastError = GetLastError();
		return FALSE;
	}

	this->ImageBase = MapStartAddr;
	CloseHandle(FileHandle);
	CloseHandle(SectionHandle);
	return TRUE;
}

BOOLEAN RPCAnalyze::ParseRpcStruct(VOID)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSecHeader = NULL;
	PIMAGE_SECTION_HEADER pSecHeaderTmp = NULL;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
	PRPC_DISPATCH_TABLE RpcDispatchTable = NULL;
	MIDL_SERVER_INFO* ServerInfo = NULL;
	MIDL_STUBLESS_PROXY_INFO* ClientInfo = NULL;
	PINT64 ServerDispatchTable = NULL;
	
	PVOID FindStart = NULL;
	PVOID FindEnd = NULL;

	if (!ImageBase)
		return FALSE;

	pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pNtHeader = (PIMAGE_NT_HEADERS)((INT64)ImageBase + pDosHeader->e_lfanew);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	if (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		ImageType = IS_DLL_MODULE;
	else if (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		ImageType = IS_EXE_MODULE;
	else
		return FALSE;

	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((INT64)ImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (!this->IsRpcImage(ImportDescriptor))
		return FALSE;
	this->ImageSize = pNtHeader->OptionalHeader.SizeOfImage;

	pSecHeader = (PIMAGE_SECTION_HEADER)& pNtHeader[1];
	for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		pSecHeaderTmp = &pSecHeader[i];
		if ((pSecHeaderTmp->Characteristics | IMAGE_SCN_MEM_WRITE) == 0 )
			continue;
		FindStart = (PVOID)((INT64)ImageBase + pSecHeader[i].VirtualAddress);
		FindEnd = (PVOID)((INT64)ImageBase + pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData);
		this->FindInterfaceStruct(FindStart, FindEnd);
	}

	for (size_t InterfaceIndex = 0; InterfaceIndex < this->RpcInterfaceNumber; InterfaceIndex++)
	{		
		this->RpcInterfaceUUID[InterfaceIndex] = this->RpcInterfaceBase[InterfaceIndex]->InterfaceId.SyntaxGUID;
		
		// Servers usually has interpreter info
		if (this->RpcInterfaceBase[InterfaceIndex]->Flags == 0x4000000)
		{
			ServerInfo = (MIDL_SERVER_INFO*)this->RpcInterfaceBase[InterfaceIndex]->InterpreterInfo;
			this->RpcInterfaceType[InterfaceIndex] = IS_SERVER_INFO;
			ServerDispatchTable = (PINT64)ServerInfo->DispatchTable;
			for (size_t j = 0; ServerDispatchTable[j]; j++)
			{
				this->RpcRoutineOffset[InterfaceIndex][this->RpcRoutineNumber[InterfaceIndex]] = (PVOID)ServerDispatchTable[j];
				this->RpcRoutineNumber[InterfaceIndex]++;
			}
		}
		// Clients has proxy info
		else if (this->RpcInterfaceBase[InterfaceIndex]->Flags == 0x2000000)
		{
			ClientInfo = (MIDL_STUBLESS_PROXY_INFO*)this->RpcInterfaceBase[InterfaceIndex]->InterpreterInfo;
			this->RpcInterfaceType[InterfaceIndex] = IS_CLIENT_INFO;
		}
		else if (this->RpcInterfaceBase[InterfaceIndex]->Flags == 0x6000000)
		{
			ServerInfo = (MIDL_SERVER_INFO*)this->RpcInterfaceBase[InterfaceIndex]->InterpreterInfo;
			this->RpcInterfaceType[InterfaceIndex] = IS_STUBLESS_SERVER_INFO;
			ServerDispatchTable = (PINT64)ServerInfo->DispatchTable;
			for (size_t j = 0; ServerDispatchTable[j]; j++)
			{
				this->RpcRoutineOffset[InterfaceIndex][this->RpcRoutineNumber[InterfaceIndex]] = (PVOID)ServerDispatchTable[j];
				this->RpcRoutineNumber[InterfaceIndex]++;
			}
		}
	}

	return TRUE;
}

PVOID RPCAnalyze::FindInterfaceStruct(PVOID StartAddr, PVOID EndAddr)
{
	INT64 SearchBegin = (INT64)StartAddr;
	INT64 SearchEnd = (INT64)EndAddr;
	RPC_SERVER_INTERFACE* RpcDataTmp = NULL;
	PRPC_DISPATCH_TABLE RpcDispatchTableTmp = NULL;
	PVOID InterInfoTmp = NULL;

	for (; SearchBegin < SearchEnd; SearchBegin += sizeof(PVOID))
	{
		if (*(PINT32)SearchBegin == sizeof(RPC_SERVER_INTERFACE))
		{
			RpcDataTmp = (RPC_SERVER_INTERFACE*)SearchBegin;

			RpcDispatchTableTmp = RpcDataTmp->DispatchTable;
			if (RpcDispatchTableTmp > EndAddr ||
				RpcDispatchTableTmp < StartAddr)
				continue;

			InterInfoTmp = (PVOID)RpcDataTmp->InterpreterInfo;
			if (InterInfoTmp > EndAddr ||
				InterInfoTmp < StartAddr)
				continue;

			this->RpcInterfaceBase[this->RpcInterfaceNumber] = (RPC_SERVER_INTERFACE*)SearchBegin;
			this->RpcInterfaceNumber++;
		}
	}
	return NULL;
}

BOOLEAN RPCAnalyze::IsRpcImage(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
{
	PIMAGE_IMPORT_DESCRIPTOR FirstImportDescriptor = ImportDescriptor;
	LPCSTR TargetName = "RPCRT4.dll";
	LPSTR ImportModuleName = NULL;

	while (FirstImportDescriptor->Characteristics)
	{
		ImportModuleName = (LPSTR)((INT64)this->ImageBase + FirstImportDescriptor->Name);
		if (!lstrcmpA(ImportModuleName, TargetName))
		{
			return TRUE;
		}
		FirstImportDescriptor++;
	}
	return FALSE;
}

BOOLEAN RPCAnalyze::InitSymbolLoad(VOID)
{
	CHAR PdbFilePath[MAX_PATH] = "";
	SYMBOL_INFO* symInfo = NULL;
	SYMSRV_INDEX_INFO syminfo;

	if (lstrlenA(this->SymbolPath))
	{
		syminfo.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);

		if (!SymInitialize((HANDLE)1, this->SymbolPath, FALSE))
			return NULL;

		if (!SymSrvGetFileIndexInfo(this->TargetImagePath, &syminfo, 0))
			return NULL;

		if (!SymFindFileInPath((HANDLE)1, NULL, syminfo.pdbfile, reinterpret_cast<PVOID>(&syminfo.guid), syminfo.age, 0, SSRVOPT_GUIDPTR, PdbFilePath, NULL, NULL))
			return NULL;

		if (!SymLoadModule64((HANDLE)1, NULL, this->TargetImagePath, NULL, (DWORD64)1000, 0))
			return NULL;

		this->SymbolInfo = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_PATH);
		lstrcpyA(this->PDBPath, PdbFilePath);
		return TRUE;
	}
	return FALSE;
}


BOOLEAN RPCAnalyze::ViewResults(VOID)
{
	INT64 RoutineOffset;
	DWORD64 disp;
	PCSTR NameStr;
	UUID uuid;

	this->InitSymbolLoad();

	puts("******************************************");
	printf("[*]Image Name: %s\n", this->GetImageName());
	printf("[*]Image Path:%s\n", this->TargetImagePath);
	printf("[*]PDB Path:%s\n",this->SymbolInfo ? this->PDBPath :"N/A");
	printf("[*]RPC Interface Num: %d\n", this->RpcInterfaceNumber);

	for (size_t InterfaceIndex = 0; InterfaceIndex < this->RpcInterfaceNumber; InterfaceIndex++)
	{
		printf("\n\n===== Interface %zd=====\n", InterfaceIndex);

		if (this->RpcInterfaceType[InterfaceIndex] == IS_SERVER_INFO)
			printf("[*]RPC Type: Server\n");
		else if (this->RpcInterfaceType[InterfaceIndex] == IS_CLIENT_INFO)
			printf("[*]RPC Type: Client\n");
		else if (this->RpcInterfaceType[InterfaceIndex] == IS_STUBLESS_SERVER_INFO)
			printf("[*]RPC Type: Stubless Server\n");

		uuid = this->RpcInterfaceUUID[InterfaceIndex];

		printf("[*]UUID: {% 08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
			uuid.Data1, uuid.Data2, uuid.Data3,
			uuid.Data4[0], uuid.Data4[1], uuid.Data4[2], uuid.Data4[3],
			uuid.Data4[4], uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);

		printf("[*]RPC Routine Numbers:%ld\n",this->RpcRoutineNumber[InterfaceIndex]);
		printf("[*]RPC Routine List (offset):\n");

		for (size_t RoutineIndex = 0; RoutineIndex < this->RpcRoutineNumber[InterfaceIndex]; RoutineIndex++)
		{
			RoutineOffset = (INT64)this->RpcRoutineOffset[InterfaceIndex][RoutineIndex] - (INT64)this->ImageBase;

			if (this->SymbolInfo)
			{
				this->SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
				this->SymbolInfo->MaxNameLen = sizeof(SYMBOL_INFO) + MAX_PATH;
				if (!SymFromAddr((HANDLE)1, (DWORD64)RoutineOffset + 1000, &disp, this->SymbolInfo))
					NameStr = "No Symbol";
				else
					NameStr = this->SymbolInfo->Name;
				printf("(%02zd) 0x%05llx [%s]\n", RoutineIndex, RoutineOffset, NameStr);
			}
			else
			{
				printf("(%02zd) 0x%05llx\n", RoutineIndex, RoutineOffset);
			}

		}
		puts("\n");
		for (size_t RoutineIndex = 0; RoutineIndex < this->RpcRoutineNumber[InterfaceIndex]; RoutineIndex++)
		{
			printf("0x%llx;", (INT64)this->RpcRoutineOffset[InterfaceIndex][RoutineIndex] - (INT64)this->ImageBase);
		}
	}

	if (this->SymbolInfo)
		SymCleanup((HANDLE)1);
		free(this->SymbolInfo);
	puts("\n");
	return TRUE;
}

LPSTR RPCAnalyze::GetImageName(VOID)
{
	PCHAR PathStr = this->TargetImagePath;
	ULONG PathStrLength = 0;
	PCHAR PathStrEnd = NULL;
	PCHAR NameStr = PathStr;

	PathStrLength = lstrlenA(PathStr);
	PathStrEnd = PathStr + PathStrLength;
	for (; PathStr < PathStrEnd; PathStrEnd--)
	{
		if (*PathStrEnd == '\\')
		{
			NameStr = PathStrEnd + 1;
			break;
		}
	}

	return NameStr;
}