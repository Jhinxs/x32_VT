#include "guestentry.h"


VOID _declspec(naked)Guest_Entry()
{
	//vmx_call();
	__asm
	{  
		mov esp, ret_esp
		jmp ret_eip
	}
}
