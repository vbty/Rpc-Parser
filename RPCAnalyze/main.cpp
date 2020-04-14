#include "RPCAnalyze.h"

int main(void)
{
	LPCSTR FileName = "C:\\Users\\vbtyqin\\Desktop\\logic_last\\OpcServices.dll";
	LPCSTR SymbolPath = "f:\\symbols";

	LPCSTR RemoteSymbolPath = "srv*f:\\symbols*http://msdl.microsoft.com/download/symbols";

	RPCAnalyze* AnalyzeObject;
	
	AnalyzeObject = new RPCAnalyze(FileName, RemoteSymbolPath);
	AnalyzeObject->MapTargetImage();
	AnalyzeObject->ParseRpcStruct();
	AnalyzeObject->ViewResults();

	system("pause");
}