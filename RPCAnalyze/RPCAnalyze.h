#pragma once
#include <Windows.h>
#include <Rpc.h>
#include <stdio.h>
#include <intrin.h>
#include <DbgHelp.h>

#define IS_SERVER_INFO 1
#define IS_CLIENT_INFO 2
#define IS_STUBLESS_SERVER_INFO 3

#define IS_EXE_MODULE 1
#define IS_DLL_MODULE 2

#define MAX_INTERFACE_NUM 10
#define MAX_ROUTINE_NUM 0x200

class RPCAnalyze
{
public:
	BOOLEAN MapTargetImage(VOID);

	BOOLEAN ParseRpcStruct(VOID);

	BOOLEAN ViewResults(VOID);

	RPCAnalyze(LPCSTR FileName, LPCSTR SymbolPath);

	RPCAnalyze(LPCSTR FileName);

	~RPCAnalyze();

private:
	BOOLEAN IsRpcImage(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);

	PVOID FindInterfaceStruct(PVOID StartAddr, PVOID EndAddr);

	LPSTR GetImageName(VOID);

	BOOLEAN InitSymbolLoad(VOID);

	DWORD LastError = 0;

	PSYMBOL_INFO SymbolInfo = NULL;

	CHAR TargetImagePath[MAX_PATH] = "";

	CHAR SymbolPath[MAX_PATH] = "";

	CHAR PDBPath[MAX_PATH] = "";

	PVOID ImageBase = NULL;

	ULONG ImageSize = 0;

	CHAR ImageType = 0; 

	UUID RpcInterfaceUUID[MAX_INTERFACE_NUM] = { 0 };

	CHAR RpcInterfaceType[MAX_INTERFACE_NUM] = { 0 };

	ULONG RpcInterfaceNumber = 0;

	RPC_SERVER_INTERFACE* RpcInterfaceBase[MAX_INTERFACE_NUM] = { 0 };

	ULONG RpcRoutineNumber[MAX_INTERFACE_NUM] = { 0 };

	PVOID RpcRoutineOffset[MAX_INTERFACE_NUM][MAX_ROUTINE_NUM] = { 0 };

};

