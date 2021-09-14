#pragma once
#include "common.h"
#include "vmexitEntry.h"
#include "guestentry.h"
#include "selector.h"

NTSTATUS VT_Enable()
{  
    ULONG cr4;
    ULONG bit5;
    DWORD32 eflags;
    ULONG64 vmx_basic_msr;
    ULONG Cpunumber = KeGetCurrentProcessorNumber();
    cr4	= get_cr4();       
    if (!SupportVT())                          //1.检查CPU是否支持VT
    {
        DbgPrint("UnSupport VT\n");
        return STATUS_UNSUCCESSFUL;
    } 
    if ((cr4 & X86_CR4_VMXE) == X86_CR4_VMXE)              //2.CR4.VMXE 是否已开启被占用
    {
        
        DbgPrint("VT is occupied by other\n");
        return STATUS_UNSUCCESSFUL;
    }
    set_cr4(X86_CR4_VMXE);                                 //3.设置CR4.VMXE
    cr4 = get_cr4(); 
    if ((cr4 & X86_CR4_VMXE) != X86_CR4_VMXE)
    {
        DbgPrint("CR4_VMXE set Error \n");
        return STATUS_UNSUCCESSFUL;
    }
    ULONG64 msr =  __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(msr & 4))                                              //4.VT 指令是否被锁定
    {
        DbgPrint("MSR_IA32_FEATURE_CONTROL VMXON Locked \n");
        return STATUS_UNSUCCESSFUL;
    }

    vmx_basic_msr = __readmsr(MSR_IA32_VMX_BASIC);                 //获取vmcs identifier
    g_VMXCPU[Cpunumber].VMX_Region = ExAllocatePoolWithTag(NonPagedPool, 4096, 'vmx');             //5.vmx_region 分配内存初始化  用于host
    DbgPrint("vmx_region: %x\n", g_VMXCPU[Cpunumber].VMX_Region);
    RtlZeroMemory(g_VMXCPU[Cpunumber].VMX_Region, 4096);
    *(ULONG*)g_VMXCPU[Cpunumber].VMX_Region = (vmx_basic_msr & 0x7ffffff);
    g_VMXCPU[Cpunumber].VMXONRegion_PA = MmGetPhysicalAddress(g_VMXCPU[Cpunumber].VMX_Region);
    vmx_on(g_VMXCPU[Cpunumber].VMXONRegion_PA.LowPart, g_VMXCPU[Cpunumber].VMXONRegion_PA.HighPart);

    eflags = __readeflags();
    if ((eflags&0x1)!=0)
    {
        DbgPrint("VMX ERROR\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("In VMX-root operation\n");
   
    g_VMXCPU[Cpunumber].VMXCS_Region = ExAllocatePoolWithTag(NonPagedPool, 4096,'vmcs');              //6.vmxcs_region 分配内存初始化  用于VM
    DbgPrint("VMXCS_Region: %x\n", g_VMXCPU[Cpunumber].VMXCS_Region);
    RtlZeroMemory(g_VMXCPU[Cpunumber].VMXCS_Region, 4096);
    vmx_basic_msr = __readmsr(MSR_IA32_VMX_BASIC);
    *(ULONG*)g_VMXCPU[Cpunumber].VMXCS_Region = (vmx_basic_msr & 0x7ffffff);
    g_VMXCPU[Cpunumber].VMCSRegion_PA = MmGetPhysicalAddress(g_VMXCPU[Cpunumber].VMXCS_Region);
    vmxcs_clear(g_VMXCPU[Cpunumber].VMCSRegion_PA.LowPart, g_VMXCPU[Cpunumber].VMCSRegion_PA.HighPart);                       //7.设置vmxcs区域为清楚状态
    eflags = __readeflags();
    if ((eflags & 0x41) != 0)
    {
        DbgPrint("vmxcs_clear ERROR\n");
        ExFreePoolWithTag(g_VMXCPU[Cpunumber].VMX_Region, 'vmx');
        return STATUS_UNSUCCESSFUL;
    }

    vmx_vmptrld(g_VMXCPU[Cpunumber].VMCSRegion_PA.LowPart, g_VMXCPU[Cpunumber].VMCSRegion_PA.HighPart);                    //8.初始化vmxcs working-pointer
    g_VMXCPU[Cpunumber].vmhost_Stack = ExAllocatePoolWithTag(NonPagedPool, 4096, 'hesp');    //9.分配vmexit时，返回host需要的栈
    RtlZeroMemory(g_VMXCPU[Cpunumber].vmhost_Stack, 4096);
    DbgPrint("vmhost_Stack %x\n", g_VMXCPU[Cpunumber].vmhost_Stack);

    g_VMXCPU[Cpunumber].vmguest_Stack = ExAllocatePoolWithTag(NonPagedPool, 4096, 'gesp');
    RtlZeroMemory(g_VMXCPU[Cpunumber].vmguest_Stack, 4096);
    DbgPrint("vmguest_Stack %x\n", g_VMXCPU[Cpunumber].vmguest_Stack);
    VTenable_before();
    StartVMXCS();                                                        //10 分配各种vm域    
    VTenable_after();
    return STATUS_SUCCESS;

}
NTSTATUS VT_Disable()
{
    ULONG Cpunumber = KeGetCurrentProcessorNumber();

    vmcall_arg = 'exit';
    VTdisable_before();
    vmx_call();
    VTdisable_after();
    clear_cr4(X86_CR4_VMXE);
    ExFreePoolWithTag(g_VMXCPU[Cpunumber].VMX_Region, 'vmx');
    ExFreePoolWithTag(g_VMXCPU[Cpunumber].VMXCS_Region,'vmcs');
    ExFreePoolWithTag(g_VMXCPU[Cpunumber].vmhost_Stack, 'hesp');
    ExFreePoolWithTag(g_VMXCPU[Cpunumber].vmguest_Stack, 'gesp');
    return STATUS_SUCCESS;

}

BOOLEAN SupportVT()
{
    ULONG ret_ecx;
    get_cpuid_info(&ret_ecx);
    if ((ret_ecx & 0X20) == 0)
    {
        return FALSE;
    }
    DWORD32 cr0 = __readcr0();
    if ((cr0&0x80000001) ==0)
    {
        return FALSE;
    }
    return TRUE;
}
NTSTATUS StartVMXCS() 
{
    ULONG Cpunumber = KeGetCurrentProcessorNumber();
    ULONG GdtBase;
    SEGMENT_SELECTOR SegmentSelector;

    GdtBase = Asm_GetGdtBase();
    //1. vmwrite host area
    vmx_vmwrite(VMCS_HOSTAREA_CR0, __readcr0());
    vmx_vmwrite(VMCS_HOSTAREA_CR3, __readcr3());
    vmx_vmwrite(VMCS_HOSTAREA_CR4, __readcr4());
    vmx_vmwrite(VMCS_HOSTAREA_CS, readcs() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_DS, readds() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_ES, reades() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_SS, readss() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_FS, readfs() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_GS, readgs() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_TR, readtr() & 0xfff8);
    vmx_vmwrite(VMCS_HOSTAREA_GDTR_BASE, Asm_GetGdtBase());
    vmx_vmwrite(VMCS_HOSTAREA_IDTR_BASE, Asm_GetIdtBase());
    vmx_vmwrite(VMCS_HOSTAREA_FS_BASE, __readfsdword(0x1c));
    vmx_vmwrite(VMCS_HOSTAREA_TR_BASE, __readfsdword(0x40));
    vmx_vmwrite(VMCS_HOSTAREA_GS_BASE,0);

    vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_CS,__readmsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);


    vmx_vmwrite(VMCS_HOSTAREA_RSP, ((ULONG)g_VMXCPU[Cpunumber].vmhost_Stack)+0x1000);
    vmx_vmwrite(VMCS_HOSTAREA_RIP, (ULONG)vmx_vmmhostentry);
    //vmx_vmwrite(VMCS_HOSTAREA_RIP, (ULONG)VmHostEntry);

    //2. vmwrite guest area
    vmx_vmwrite(VMCS_GUSTAREA_CR0, __readcr0());
    vmx_vmwrite(VMCS_GUSTAREA_CR3, __readcr3());
    vmx_vmwrite(VMCS_GUSTAREA_CR4, __readcr4());
    vmx_vmwrite(VMCS_GUSTAREA_DR7, 0x400);
    vmx_vmwrite(VMCS_GUSTAREA_RSP, ((ULONG)g_VMXCPU[Cpunumber].vmguest_Stack) + 0x1000);
   // vmx_vmwrite(VMCS_GUSTAREA_RSP, ((ULONG)vmx_GuestEsp));
    vmx_vmwrite(VMCS_GUSTAREA_RIP, (ULONG)vmx_GuestReturn);
    vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, getRflags());
    //GdtBase = Asm_GetGdtBase();
    FillGuestSelectorData(GdtBase, CS, readcs());
    FillGuestSelectorData(GdtBase, DS, readds());
    FillGuestSelectorData(GdtBase, ES, reades());
    FillGuestSelectorData(GdtBase, FS, readfs());
    FillGuestSelectorData(GdtBase, GS, readgs());
    FillGuestSelectorData(GdtBase, SS, readss());
    FillGuestSelectorData(GdtBase, TR, readtr());
    FillGuestSelectorData(GdtBase, LDTR, Asm_GetLdtr());

    vmx_vmwrite(VMCS_GUSTAREA_LINKPOINT_FULL, 0XFFFFFFFF);
    vmx_vmwrite(VMCS_GUSTAREA_LINKPOINT_HIGH, 0XFFFFFFFF);

    vmx_vmwrite(VMCS_GUSTAREA_GDTR_BASE, Asm_GetGdtBase());
    vmx_vmwrite(VMCS_GUSTAREA_IDTR_BASE, Asm_GetIdtBase());
    vmx_vmwrite(VMCS_GUSTAREA_IDTR_LIMT, Asm_GetIdtLimit());
    vmx_vmwrite(VMCS_GUSTAREA_GDTR_LIMT, Asm_GetGdtLimit());

    vmx_vmwrite(VMCS_GUSTAREA_DEBUGCTL_FULL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_GUSTAREA_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
    vmx_vmwrite(VMCS_GUSTAREA_ACTIVITY_STATE, 0);
    vmx_vmwrite(VMCS_GUSTAREA_INTERRUPTIBILITY_INFO, 0);
    ////3. vmwrite control area
    //   //3.1  vm-execution controle fields
    vmx_vmwrite(VMCS_PIN_BASE_CONTROL, AdjustControlBit(0, MSR_IA32_VMX_PINBASED_CTLS));
    vmx_vmwrite(VMCS_PROCESSOR_BASE_CONTTOL, AdjustControlBit(0, MSR_IA32_VMX_PROCBASED_CTLS));
    //   //3.2  vm-entry controle fields 
    vmx_vmwrite(VMCS_VM_ENTRY_CONTROL, AdjustControlBit(0, MSR_IA32_VMX_ENTRY_CTLS));
       //3.2  vm-exit controle fields  
    vmx_vmwrite(VMCS_VM_EXIT_CONTROL, AdjustControlBit(0, MSR_IA32_VMX_EXIT_CTLS));
    //4. vmwrite exit information area
    vm_launch();                                                         //11.进入VT
    DbgPrint("vm launch error: %x\n", vmx_vmread(VM_INSTRUCTION_ERROR));
    return STATUS_SUCCESS;
}

ULONG AdjustControlBit(ULONG uRetVaule, ULONG msr)
{

    LARGE_INTEGER MsrVaule;
    MsrVaule.QuadPart = __readmsr(msr);
    uRetVaule &= MsrVaule.HighPart;
    uRetVaule |= MsrVaule.LowPart;
    return uRetVaule;
}

NTSTATUS StartVT() 
{
    //KeInitializeMutex(&g_GlobalMutex, 0);
  //  KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode,FALSE,0);
    for (int i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread((KAFFINITY)(1 << i));
        //KeRaiseIrqlToDpcLevel();
        VT_Enable();
       // KeLowerIrql(0);
        KeRevertToUserAffinityThread();
        DbgPrint("start vt on cpu [%d]...\n", i);
    }
    //KeReleaseMutex(&g_GlobalMutex,FALSE);
    
    return STATUS_SUCCESS;
}
NTSTATUS StopVT() 
{
    for (int i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread((KAFFINITY)(1 << i));
       // KeRaiseIrqlToDpcLevel();
        VT_Disable();
       // KeLowerIrql(0);
        KeRevertToUserAffinityThread();
        DbgPrint("stop vt on cpu [%d]...\n", i);
    }
    
    return STATUS_SUCCESS;

}
