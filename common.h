#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>



#define X86_CR4_VMXE 0x2000  /* enable VMX */
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_BASIC              0x480
#define MSR_IA32_VMX_PINBASED_CTLS 0x481
#define MSR_IA32_VMX_PROCBASED_CTLS 0x482
#define MSR_IA32_VMX_SECPROCBASED_CTLS2 0X48B
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484
#define MSR_IA32_SYSENTER_CS 0X174
#define MSR_IA32_SYSENTER_ESP 0X175
#define MSR_IA32_SYSENTER_EIP 0X176
#define MSR_IA32_DEBUGCTL 0X1D9

#define VMCS_PIN_BASE_CONTROL 0x4000
#define VMCS_PROCESSOR_BASE_CONTTOL 0x4002
#define VMCS_VM_EXIT_CONTROL 0x400C
#define VMCS_VM_ENTRY_CONTROL 0X4012


#define VM_EXIT_REASON  0x00004402
#define VMCS_INSTRUCTION_LENGH 0X440C
#define VMCS_EXIT_QUALIFICTION 0X6400

#define VM_INSTRUCTION_ERROR  0x4400


#define VMCS_HOSTAREA_CR0 0x6C00
#define VMCS_HOSTAREA_CR3 0x6C02
#define VMCS_HOSTAREA_CR4 0x6C04
#define VMCS_HOSTAREA_RSP 0X6C14
#define VMCS_HOSTAREA_RIP 0X6C16
#define VMCS_HOSTAREA_CS 0XC02
#define VMCS_HOSTAREA_SS 0XC04
#define VMCS_HOSTAREA_DS 0XC06
#define VMCS_HOSTAREA_ES 0XC00
#define VMCS_HOSTAREA_FS 0XC08
#define VMCS_HOSTAREA_GS 0XC0A
#define VMCS_HOSTAREA_TR 0XC0C
#define VMCS_HOSTAREA_FS_BASE 0X6C06
#define VMCS_HOSTAREA_GS_BASE 0X6C08
#define VMCS_HOSTAREA_TR_BASE 0X6C0A
#define VMCS_HOSTAREA_GDTR_BASE 0X6C0C
#define VMCS_HOSTAREA_IDTR_BASE 0X6C0E
#define VMCS_HOSTAREA_SYSENTER_CS 0X4C00
#define VMCS_HOSTAREA_SYSENTER_ESP 0X6C10
#define VMCS_HOSTAREA_SYSENTER_EIP 0X6C12

#define VMCS_GUSTAREA_CR0 0X6800
#define VMCS_GUSTAREA_CR3 0X6802
#define VMCS_GUSTAREA_CR4 0X6804

#define VMCS_GUSTAREA_CS_BASE 0x6808
#define VMCS_GUSTAREA_SS_BASE 0x680A
#define VMCS_GUSTAREA_DS_BASE 0X680C
#define VMCS_GUSTAREA_ES_BASE 0X6806
#define VMCS_GUSTAREA_FS_BASE 0x680E
#define VMCS_GUSTAREA_GS_BASE 0x6810
#define VMCS_GUSTAREA_LDTR_BASE 0x6812
#define VMCS_GUSTAREA_TR_BASE 0x6814
#define VMCS_GUSTAREA_GDTR_BASE 0x6816
#define VMCS_GUSTAREA_IDTR_BASE 0x6818

#define VMCS_GUSTAREA_CS 0X802
#define VMCS_GUSTAREA_SS 0X804
#define VMCS_GUSTAREA_DS 0X806
#define VMCS_GUSTAREA_ES 0X800
#define VMCS_GUSTAREA_FS 0X808
#define VMCS_GUSTAREA_GS 0X80A
#define VMCS_GUSTAREA_LDTR 0X80C
#define VMCS_GUSTAREA_TR 0X80E

#define VMCS_GUSTAREA_CS_LIMT 0X4802
#define VMCS_GUSTAREA_SS_LIMT 0X4804
#define VMCS_GUSTAREA_DS_LIMT 0X4806
#define VMCS_GUSTAREA_ES_LIMT 0X4800
#define VMCS_GUSTAREA_FS_LIMT 0X4808
#define VMCS_GUSTAREA_GS_LIMT 0X480A
#define VMCS_GUSTAREA_LDTR_LIMT 0X480C
#define VMCS_GUSTAREA_TR_LIMT 0X480E
#define VMCS_GUSTAREA_GDTR_LIMT 0X4810
#define VMCS_GUSTAREA_IDTR_LIMT 0X4812

#define VMCS_GUSTAREA_DEBUGCTL_FULL 0X2802
#define VMCS_GUSTAREA_DEBUGCTL_HIGH 0X2803

#define VMCS_GUSTAREA_DR7 0X681A
#define VMCS_GUSTAREA_RSP 0X681C
#define VMCS_GUSTAREA_RIP 0X681E
#define VMCS_GUSTAREA_RFLAGS 0X6820
#define VMCS_GUSTAREA_SYSENTER_ESP 0X6824
#define VMCS_GUSTAREA_SYSENTER_EIP 0X6826
#define VMCS_GUSTAREA_SYSENTER_CS 0X482A

#define VMCS_GUSTAREA_CS_ACCR 0X4816
#define VMCS_GUSTAREA_SS_ACCR 0X4818
#define VMCS_GUSTAREA_DS_ACCR 0X481A
#define VMCS_GUSTAREA_ES_ACCR 0X4814
#define VMCS_GUSTAREA_FS_ACCR 0X481C
#define VMCS_GUSTAREA_GS_ACCR 0X481E
#define VMCS_GUSTAREA_LDTR_ACCR 0X4820
#define VMCS_GUSTAREA_TR_ACCR 0X4822

#define VMCS_GUSTAREA_LINKPOINT_FULL 0X2800
#define VMCS_GUSTAREA_LINKPOINT_HIGH 0X2801
#define VMCS_GUSTAREA_INTERRUPTIBILITY_INFO  0x00004824
#define VMCS_GUSTAREA_ACTIVITY_STATE  0X00004826

#define GUEST_RSP 0x0000681c
#define GUEST_RIP 0x0000681e


typedef struct _VMX_CPU
{
    PVOID VMX_Region;
    PHYSICAL_ADDRESS VMXONRegion_PA;
    PVOID VMXCS_Region;
    PHYSICAL_ADDRESS VMCSRegion_PA;
    PVOID vmhost_Stack;
    PVOID vmguest_Stack;
}VMX_CPU, * PVMX_CPU;

typedef struct _GUEST_REGS
{
    ULONG  edi;
    ULONG  esi;
    ULONG  ebp;
    ULONG  esp;
    ULONG  ebx;
    ULONG  edx;
    ULONG  ecx;
    ULONG  eax;

}GUEST_REGS, *PGUEST_REGS;

typedef struct _GDT 
{
    ULONG gdtbase;
    USHORT gdtlimit;

}GDT,*PGDT;


EXTERN_C vm_launch();
EXTERN_C vmx_vmread();
EXTERN_C ULONG readcs();
EXTERN_C ULONG readds();
EXTERN_C ULONG reades();
EXTERN_C ULONG readfs();
EXTERN_C ULONG readgs();
EXTERN_C ULONG readtr();
EXTERN_C ULONG readss();
EXTERN_C ULONG Asm_GetGdtBase();
EXTERN_C ULONG Asm_GetIdtBase();
EXTERN_C ULONG Asm_GetGdtLimit();
EXTERN_C ULONG Asm_GetIdtLimit();
EXTERN_C ULONG Asm_GetLdtr();
EXTERN_C ULONG getRflags();
EXTERN_C get_cr4();
EXTERN_C get_cpuid_info(DWORD32);
EXTERN_C set_cr4(DWORD32);
EXTERN_C clear_cr4(DWORD32);
EXTERN_C vmx_on(DWORD32 LowPart, DWORD32 HighPart);
EXTERN_C vmx_off();
EXTERN_C vmxcs_clear(DWORD32 LowPart, DWORD32 HighPart);
EXTERN_C vmx_vmptrld(DWORD32 LowPart, DWORD32 HighPart);
EXTERN_C vmx_vmwrite(DWORD32 Field, DWORD32 value);
EXTERN_C vmx_call();
EXTERN_C vmx_lgdt();
EXTERN_C vmx_invd();
EXTERN_C vmx_wrmsr();
EXTERN_C VTenable_before();
EXTERN_C VTenable_after();
EXTERN_C VTdisable_before();
EXTERN_C VTdisable_after();
EXTERN_C vmx_GuestEsp();
EXTERN_C vmx_GuestReturn();
EXTERN_C vmx_vmoffreturn();
EXTERN_C vmx_vmmhostentry();
EXTERN_C DriverReturn;
EXTERN_C DriverESP;

ULONG AdjustControlBit(ULONG uRetVaule, ULONG msr);
VOID SaveGDT();
VOID RecoverGDT();

BOOLEAN SupportVT();
NTSTATUS VT_Enable();
NTSTATUS VT_Disable();
NTSTATUS StartVMXCS();
NTSTATUS StartVT();
NTSTATUS StopVT();


VMX_CPU g_VMXCPU[64];
KMUTEX g_GlobalMutex;

PHYSICAL_ADDRESS vmxcs_ph;
ULONG vmcall_arg;
