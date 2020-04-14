#include <Windows.h>
#include <stdio.h>
#include "SampleRpc_h.h"

void HelloProc(
	/* [in] */ handle_t IDL_handle,
	/* [string][in] */ unsigned char* pszString)
{
	printf("%s/n", pszString);
}


int main()
{
	RPC_STATUS status;

	status = RpcServerUseProtseqEpW(
		(RPC_WSTR)L"ncalrpc",
		RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
		(RPC_WSTR)L"RPC-ALPC-Server",
		NULL);

	if (status)
	{
		printf("Error RpcServerUseProtseqEpW: %d\n", status);
		exit(status);
	}

	status = RpcServerRegisterIf(
		hello_v1_0_s_ifspec,
		NULL,
		NULL);


	if (status)
	{
		printf("Error RpcServerRegisterIf: %d\n", status);
		exit(status);
	}

	status = RpcServerListen(
		1,
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,
		FALSE);


	if (status) {
		printf("Error RpcServerListen: %d\n", status);
		exit(status);
	}
	else
		puts("Server is OK");
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
	free(ptr);
}