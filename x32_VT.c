#include "common.h"

ULONG gdtbase;
ULONG gdtlimit;
GDT g_GDT[64];

NTSTATUS DrvUnLoad(PDRIVER_OBJECT pDriver)
{
	
	StopVT();
	RecoverGDT();
	DbgPrint("[+] Driver Unload Success!\n");
	return STATUS_SUCCESS;

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pPath) 
{
	DbgPrint("[+] Driver load Success!\n");
	pDriver->DriverUnload = DrvUnLoad;
	SaveGDT();
	StartVT();
	DbgPrint("vm-over\n");
	return STATUS_SUCCESS;
}
VOID RecoverGDT()
{
	CHAR buffer[6];

	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));
		ULONG Cpunumber = KeGetCurrentProcessorNumber();
		*(ULONG*)(buffer + 2) = g_GDT[Cpunumber].gdtbase;
		*(USHORT*)buffer = g_GDT[Cpunumber].gdtlimit;
		vmx_lgdt((ULONG*)buffer);
		KeRevertToUserAffinityThread();
		DbgPrint("Recover gdt at cpu[%d]\n", Cpunumber);
	}
}

VOID SaveGDT()
{
	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << i));
		ULONG Cpunumber = KeGetCurrentProcessorNumber();
		g_GDT[Cpunumber].gdtbase = Asm_GetGdtBase();
		g_GDT[Cpunumber].gdtlimit = Asm_GetGdtLimit();;
		KeRevertToUserAffinityThread();
		DbgPrint("save gdt at cpu[%d]\n", Cpunumber);
	}
}