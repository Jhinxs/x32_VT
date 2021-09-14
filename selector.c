//https://github.com/haidragon/newbluepill    ��Ҫ���ڶ�̬������������
#include "selector.h"

NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, ULONG GdtBase)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;

	if (!SegmentSelector)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//
	// �����ѡ���ӵ�T1 = 1��ʾ����LDT�е���, ����û��ʵ���������
	//
	if (Selector & 0x4)
	{

		return STATUS_INVALID_PARAMETER;
	}

	//
	// ��GDT��ȡ��ԭʼ�Ķ�������
	//
	SegDesc = (PSEGMENT_DESCRIPTOR2)((PUCHAR)GdtBase + (Selector & ~0x7));

	//
	// ��ѡ����
	//
	SegmentSelector->sel = Selector;

	//
	// �λ�ַ15-39λ 55-63λ
	//
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;

	//
	// ���޳�0-15λ  47-51λ, ������ȡ��
	//
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;

	//
	// ������39-47 51-55 ע��۲�ȡ��
	//
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	//
	// �����ж����Ե�DTλ, �ж��Ƿ���ϵͳ�����������Ǵ������ݶ�������
	//
	if (!(SegDesc->attr0 & LA_STANDARD))
	{
		ULONG64 tmp;

		//
		// �����ʾ��ϵͳ��������������������, �о�����Ϊ64λ׼���İ�,
		// 32λ����λ�ַֻ��32λ��. �ѵ�64λ������ʲô������?
		//
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));

		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	//
	// ���Ƕν��޵�����λ, 1Ϊ4K. 0Ϊ1BYTE
	//
	if (SegmentSelector->attributes.fields.g)
	{
		//
		// �������λΪ1, ��ô�ͳ���4K. ���ƶ�12λ
		//
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}




NTSTATUS FillGuestSelectorData(ULONG GdtBase, ULONG Segreg, USHORT
	Selector)
{
	
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)&SegmentSelector.attributes)[0] + (((PUCHAR)&
		SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	vmx_vmwrite(VMCS_GUSTAREA_ES + Segreg * 2, Selector & 0xFFF8);
	vmx_vmwrite(VMCS_GUSTAREA_ES_BASE + Segreg * 2, SegmentSelector.base);
	vmx_vmwrite(VMCS_GUSTAREA_ES_LIMT + Segreg * 2, SegmentSelector.limit);
	vmx_vmwrite(VMCS_GUSTAREA_ES_ACCR + Segreg * 2, uAccessRights);

	return STATUS_SUCCESS;
}

void CmSetBit32(ULONG32* dword, UCHAR bit)
{
	ULONG32 mask = (1 << bit);
	*dword = *dword | mask;
}

void CmClearBit32(ULONG* dword, ULONG bit)
{
	ULONG mask = 0xFFFFFFFF;
	ULONG sub = (1 << bit);
	mask = mask - sub;
	*dword = *dword & mask;
}

NTSTATUS NTAPI CmInitializeSegmentSelector(
	SEGMENT_SELECTOR* SegmentSelector,
	USHORT Selector,
	PUCHAR GdtBase
)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return STATUS_INVALID_PARAMETER;
	//
	// �����ѡ���ӵ�T1 = 1��ʾ����LDT�е���, ����û��ʵ���������
	//
	if (Selector & 0x4) {
		return STATUS_INVALID_PARAMETER;
	}
	//
	// ��GDT��ȡ��ԭʼ�Ķ�������
	//
	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));
	//
	// ��ѡ����
	//
	SegmentSelector->sel = Selector;
	// �λ�ַ15-39λ 55-63λ
	//
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;

	// ���޳�0-15λ  47-51λ, ������ȡ��


	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;

	// ������39-47 51-55 ע��۲�ȡ��
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;
	// �����ж����Ե�DTλ, �ж��Ƿ���ϵͳ�����������Ǵ������ݶ�������
	if (!(SegDesc->attr0 & LA_STANDARD)) {
		ULONG64 tmp;
		// �����ʾ��ϵͳ��������������������, �о�����Ϊ64λ׼���İ�,
		// 32λ����λ�ַֻ��32λ��. �ѵ�64λ������ʲô������?

		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}
	//
	// ���Ƕν��޵�����λ, 1Ϊ4K. 0Ϊ1BYTE
	//
	if (SegmentSelector->attributes.fields.g) {
		// �������λΪ1, ��ô�ͳ���4K. ���ƶ�12λ
		//
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}

BOOLEAN CmIsBitSet(
	ULONG64 v,
	UCHAR bitNo
)
{
	ULONG64 mask = (ULONG64)1 << bitNo;

	return (BOOLEAN)((v & mask) != 0);
}