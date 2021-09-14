#include "vmexitEntry.h"

VOID DealRDMSR(PGUEST_REGS g_GUEST_REGS)
{
	ULONG swapeax = g_GUEST_REGS->eax;
	switch (g_GUEST_REGS->ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		g_GUEST_REGS->eax = vmx_vmread(VMCS_GUSTAREA_SYSENTER_CS);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:
	{
		g_GUEST_REGS->eax = vmx_vmread(VMCS_GUSTAREA_SYSENTER_EIP);
		break;
	}
	case MSR_IA32_SYSENTER_ESP: 
	{
		g_GUEST_REGS->eax = vmx_vmread(VMCS_GUSTAREA_SYSENTER_ESP);
		break;
	}
	default:
		g_GUEST_REGS->eax = __readmsr(g_GUEST_REGS->ecx);
		break;
	}
	g_GUEST_REGS->eax = swapeax;
}
VOID DealWRMSR(PGUEST_REGS g_GUEST_REGS)
{
	switch (g_GUEST_REGS->ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_CS, g_GUEST_REGS->eax);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:
	{
		vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_ESP, g_GUEST_REGS->eax);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_EIP, g_GUEST_REGS->eax);
		break;
	}
	default:
		//__writemsr(g_GUEST_REGS->ecx, g_GUEST_REGS->eax, g_GUEST_REGS->edx);
		vmx_wrmsr();
		break;
	}

}
VOID DealCrReg(PGUEST_REGS g_GUEST_REGS)
{
	ULONG CRNumber;
	ULONG Accesstype;
	ULONG operandtype;
	ULONG MovrCRPurposeReg;
	ULONG CrQulification;
	CrQulification = vmx_vmread(VMCS_EXIT_QUALIFICTION);
    CRNumber = (CrQulification & 0x0000000f);
	Accesstype = ((CrQulification & 0x00000030) >> 4);
	operandtype = ((CrQulification & 0x00000040) >> 6);
	MovrCRPurposeReg = ((CrQulification & 0x00000F00) >> 8);
	if (Accesstype == 0)
	{
		
		switch (MovrCRPurposeReg)
		{
		case 0:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->eax);
			break;
		}
		case 1:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->ecx);
			break;
		}
		case 2:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->edx);
			break;
		}
		case 3:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->ebx);
			break;
		}
		case 4:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->esp);
			break;
		}
		case 5:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->ebp);
			break;
		}
		case 6:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->esi);
			break;
		}
		case 7:
		{
			vmx_vmwrite(VMCS_GUSTAREA_CR3, g_GUEST_REGS->edi);
			break;
		}
		default:
			break;
		}
		
	}
	else
	{
		switch (MovrCRPurposeReg)
		{
		case 0:
		{
			g_GUEST_REGS->eax = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 1:
		{
			g_GUEST_REGS->ecx = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 2:
		{
			g_GUEST_REGS->edx = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 3:
		{
			g_GUEST_REGS->ebx = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 4:
		{
			g_GUEST_REGS->esp = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 5:
		{
			g_GUEST_REGS->ebp = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 6:
		{
			g_GUEST_REGS->esi = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		case 7:
		{
			g_GUEST_REGS->edi = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		}
		default:
			break;
		}
	}
}
VOID DealCPUID(PGUEST_REGS g_GUEST_REGS)
{
	ULONG uCPUinfo[4] = { 0 };
	__cpuid(uCPUinfo, g_GUEST_REGS->eax);
	g_GUEST_REGS->eax = uCPUinfo[0];
	g_GUEST_REGS->ebx = uCPUinfo[1];
	g_GUEST_REGS->ecx = uCPUinfo[2];
	g_GUEST_REGS->edx = uCPUinfo[3];
}

VOID DealVmoff() 
{
	if (vmcall_arg = 'exit') 
	{
		vmxcs_clear(vmxcs_ph.LowPart, vmxcs_ph.HighPart);
		vmx_off();
		vmx_vmoffreturn();
	}

}
VOID DealINVD() 
{
	vmx_invd();
}

VOID VmhostEntrydbg(PGUEST_REGS g_GUEST_REGS)
{   
	
	ULONG exitreason = vmx_vmread(VM_EXIT_REASON);
	ULONG instructionlen = vmx_vmread(VMCS_INSTRUCTION_LENGH);
	ULONG gesp = vmx_vmread(GUEST_RSP);
	ULONG geip = vmx_vmread(GUEST_RIP);
	ULONG grflags = vmx_vmread(VMCS_GUSTAREA_RFLAGS);
	switch (exitreason)
	{
	case 0x1c:
		DealCrReg(g_GUEST_REGS);       //cr access
		break;
	case 0xa:             //cpuid
		
		DealCPUID(g_GUEST_REGS);
		break;
	//case 0x1a:            //vmoff
	//	DealVmoff();
	//	break;
	case 0x12:           //vmcall
		DealVmoff();
		break;
	case 0x1f:            //rdmsr
		DealRDMSR(g_GUEST_REGS);
		break;
	case 0x20:             //writemsr
		DealWRMSR(g_GUEST_REGS);
		break;
	case 0xd:
		vmx_invd();
		break;
	default:
		DbgPrint("exitreason: %x\n", exitreason);
		__asm int 3
		break;
	}
	ULONG guestnexteip = geip + instructionlen;
	vmx_vmwrite(VMCS_GUSTAREA_RIP, guestnexteip);
	vmx_vmwrite(VMCS_GUSTAREA_RSP, gesp);
	vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, grflags);

}