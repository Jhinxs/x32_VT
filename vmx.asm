.686P
.model flat,StdCall

StartVMXCS proto
VmhostEntrydbg proto,regs:dword 
Get_g_GUEST_REGS proto

.data
GuestReturn dword ?
DriverReturna dword ?
DriverReturnb dword ?
GuestESP dword  ?

DriverEAX dword ?
DriverECX dword ?
DriverEDX dword ?
DriverEBX dword ?
DriverEBP dword ?
DriverESP dword ?
DriverESI dword ?
DriverEDI dword ?
DriverEFL dword ?


.code
get_cr4 proc
        mov eax,cr4
        ret
get_cr4 endp

get_cpuid_info proc,_para:dword
        pushad
        mov eax,1H
        cpuid
        mov esi,_para
        mov [esi],ecx
        popad
        ret

get_cpuid_info endp

set_cr4 proc,_para:dword
       
        mov eax, _para
        mov ecx,cr4
        or ecx,eax
        mov cr4,ecx
        ret
set_cr4 endp

clear_cr4 proc,_para:dword
       
        mov eax,_para
        mov ecx,cr4
        not eax
        and ecx,eax
        mov cr4,ecx
        ret
 
clear_cr4 endp

vmx_on proc,LowPart:dword,HighPart:dword

        push HighPart
        push LowPart
        vmxon qword ptr [esp]
        add esp,8
        ret

vmx_on endp

vmxcs_clear PROC,LowPart:dword,HighPart:dword

        push HighPart
        push LowPart
        vmclear  qword ptr [esp]
        add esp,8
        ret

vmxcs_clear endp

vmx_vmptrld PROC,LowPart:dword,HighPart:dword
        
        push HighPart
        push LowPart
        vmptrld  qword ptr [esp]
        add esp,8
        ret
vmx_vmptrld endp


vmx_vmwrite proc uses ecx Field:dword,Value:dword
        mov eax,Field
        mov ecx,Value
        vmwrite eax,ecx
        ret
vmx_vmwrite endp

vm_launch proc

       vmlaunch
       ret

vm_launch endp

vmx_vmread proc uses ecx Field:dword

        mov eax,Field
        vmread ecx,eax
        mov eax,ecx
        ret

vmx_vmread ENDP


readcs proc

     mov eax,cs
     ret

readcs endp

readds proc

     mov eax,ds
     ret

readds endp

reades proc

     mov eax,es
     ret

reades endp


readfs proc

     mov eax,fs
     ret

readfs endp

readgs proc

     mov eax,gs
     ret

readgs endp


readss proc

     mov eax,ss
     ret

readss endp

readtr proc

     str eax
     ret

readtr endp

Asm_GetGdtBase PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov		eax, dword PTR gdtr[2]
        ret
Asm_GetGdtBase ENDP

Asm_GetIdtBase PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        mov		eax, dword PTR idtr[2]
        ret
Asm_GetIdtBase ENDP

Asm_GetIdtLimit PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        xor     eax,eax
        mov		ax, WORD PTR idtr[0]
        ret
Asm_GetIdtLimit ENDP

Asm_GetGdtLimit PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        xor     eax,eax
        mov		ax, WORD PTR gdtr[0]
        ret
Asm_GetGdtLimit ENDP

Asm_GetLdtr PROC
	    sldt	eax
	    ret
Asm_GetLdtr ENDP

getRflags proc
        
        xor eax,eax
        cli
        pushfd
        sti
        pop eax
        ret


getRflags endp

vmx_call proc

       vmcall
       ret

vmx_call endp

vmx_lgdt proc _para:dword

       push _para
       mov eax,ds:[_para]
       lgdt fword ptr ds:[eax]
       add esp,4
       ret 

vmx_lgdt endp

vmx_invd proc

       invd
       ret

vmx_invd endp

vmx_wrmsr proc
        
        wrmsr
        ret

vmx_wrmsr endp


vmx_off PROC 
	    vmxoff
	    ret
vmx_off ENDP


VTenable_after proc
        cli
        push DriverEFL
        popfd
        mov eax,DriverEAX
	    mov ecx,DriverECX
	    mov edx,DriverEDX
	    mov ebx,DriverEBX
	    mov esp,DriverESP
	    mov ebp,DriverEBP
	    mov esi,DriverESI
	    mov edi,DriverEDI

        sti
        ret
VTenable_after endp

VTenable_before proc
        cli
        mov DriverEAX,eax
	    mov DriverECX,ecx
	    mov DriverEDX,edx
	    mov DriverEBX,ebx
	    mov DriverESP,esp
	    mov DriverEBP,ebp
	    mov DriverESI,esi
	    mov DriverEDI,edi
        pushfd
        pop DriverEFL
        sti
        ret

VTenable_before endp

VTdisable_before proc
        cli
        mov DriverEAX,eax
	    mov DriverECX,ecx
	    mov DriverEDX,edx
	    mov DriverEBX,ebx
	    mov DriverESP,esp
	    mov DriverEBP,ebp
	    mov DriverESI,esi
	    mov DriverEDI,edi
        pushfd
        pop DriverEFL
        sti
        ret

VTdisable_before endp

VTdisable_after proc
        cli
        push DriverEFL
        popfd
        mov eax,DriverEAX
	    mov ecx,DriverECX
	    mov edx,DriverEDX
	    mov ebx,DriverEBX
	    mov esp,DriverESP
	    mov ebp,DriverEBP
	    mov esi,DriverESI
	    mov edi,DriverEDI

        sti
        ret

VTdisable_after endp

vmx_GuestReturn proc
         CALL VTenable_after
         ret
vmx_GuestReturn endp

vmx_vmoffreturn proc

         call VTdisable_after
         ret
vmx_vmoffreturn endp

vmx_vmmhostentry proc
        
        pushad
        push esp
        call VmhostEntrydbg
        popad
        vmresume
        
vmx_vmmhostentry endp


end