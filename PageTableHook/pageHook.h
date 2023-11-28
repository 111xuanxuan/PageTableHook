#pragma once
#ifndef PAGETABLE_PAGEHOOK_H
#define PAGETABLE_PAGEHOOK_H

#include "Base.h"
#include "IA32/ia32_defines_only.h"

#define MAX_HOOK_COUNT 0x64

//����hook��Ϣ
typedef struct _HOOK_INFO_
{
	//������ڴ��¼
	struct MemRecord {
		PVOID addrBase;
		UINT32 size;
	};

	HANDLE processId;
	UCHAR saveCode[14];
	PVOID oricFuncAddr;
	UINT64 pageFrameNumber;
	MemRecord mem1;
	MemRecord mem2;

}HOOK_INFO,*PHOOK_INFO;

typedef struct _PAGE_TABLE_
{
	UINT64		linearAddress;
	pml4e_64*	pxeAddress;
	pdpte_64*	ppeAddress;
	pde_64*		pdeAddress;
	pte_64*		pteAddress;

}PAGE_TABLE,*PPAGE_TABLE;


//��־��ӡ
void Log(const char* info, BOOLEAN is_err, LONG err_code = 0);

class PageTableHookManager {
public:
	
	static PageTableHookManager* GetInstance();
	BOOLEAN pte_inline_hook(HANDLE _processId, void** _ori_addr, void* _target_func);
	BOOLEAN pte_remove_hook(HANDLE _processId, void* _ori_func_addr); 
	//�����ڲ�������ڴ�
	void clean();

	HANDLE test() {
		PEPROCESS  process=findProcess("explorer.exe");
		if (!process) {
			return 0;
		}
		HANDLE pid = *reinterpret_cast<PHANDLE>(reinterpret_cast<PUCHAR>(process)+0x440);
		return pid;
	}

private:

	//����ҳ��
	BOOLEAN isolationPages(PEPROCESS _process, PVOID _va);
	//�ָ��ҳ
	BOOLEAN splitLargePages(pde_2mb_64* _inPde,pde_64*  _outPde);
	//�滻ҳ��
	BOOLEAN replacePageTable(cr3 _cr3, UINT64 _alignAddr, pde_64* _splitPde);

private:

	//��ȡPageTable
	void getPageTable(PAGE_TABLE& _table);
	//�ر�д����
	KIRQL wp_off();
	//����д����
	void wp_on(KIRQL _irql);
	//�����ַ�������ַ
	UINT64 physicalToVirtual(UINT64 _pa);
	//�����ַ�������ַ
	UINT64 virtualToPhysical(UINT64 _va);
	////���Gλ��Ϣ
	//void addGbitInfo(PVOID _alignAddr,pde_2mb_64* _pdeAddress,pte_64* _pteAddress);
	//// �ָ�Gλ��Ϣ
	//void resumeGbit(PVOID _alignAddr);
	//��ȡPteBase
	void getPteBase();
	//��ȡPteAddress
	UINT64 getPteAddress(uint64_t _va);
	//��ȡpml4e����
	UINT64 getPml4eIndex(UINT64 _linearAddress);
	//��ȡpdpte����
	UINT64 getPdpteIndex(UINT64 _linearAddress);
	//��ȡpde����
	UINT64 getPdeIndex(UINT64 _linearAddress);
	//��ȡpte����
	UINT64 getPteIndex(UINT64 _linearAddress);
	//��ȡҳ��ƫ��
	UINT64 getPageOffset(UINT64 _linearAddress);

private:

	PEPROCESS findProcess(const char* _processName);

private:
	//hook����
	UINT32		m_hookCount;
	//hook��Ϣ
	HOOK_INFO	m_hookInfo[MAX_HOOK_COUNT]{0};
	PUCHAR		m_trampLine;
	UINT64		m_trampLineUsed;
	//�Ƿ���Ч
	BOOLEAN		m_valid;
	//pteBase
	UINT64		m_pteBase;
};



#endif // !PAGETABLE_PAGEHOOK_H
