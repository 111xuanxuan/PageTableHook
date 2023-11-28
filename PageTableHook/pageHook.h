#pragma once
#ifndef PAGETABLE_PAGEHOOK_H
#define PAGETABLE_PAGEHOOK_H

#include "Base.h"
#include "IA32/ia32_defines_only.h"

#define MAX_HOOK_COUNT 0x64

//保存hook信息
typedef struct _HOOK_INFO_
{
	//申请的内存记录
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


//日志打印
void Log(const char* info, BOOLEAN is_err, LONG err_code = 0);

class PageTableHookManager {
public:
	
	static PageTableHookManager* GetInstance();
	BOOLEAN pte_inline_hook(HANDLE _processId, void** _ori_addr, void* _target_func);
	BOOLEAN pte_remove_hook(HANDLE _processId, void* _ori_func_addr); 
	//清理内部申请的内存
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

	//隔离页面
	BOOLEAN isolationPages(PEPROCESS _process, PVOID _va);
	//分割大页
	BOOLEAN splitLargePages(pde_2mb_64* _inPde,pde_64*  _outPde);
	//替换页表
	BOOLEAN replacePageTable(cr3 _cr3, UINT64 _alignAddr, pde_64* _splitPde);

private:

	//获取PageTable
	void getPageTable(PAGE_TABLE& _table);
	//关闭写保护
	KIRQL wp_off();
	//开启写保护
	void wp_on(KIRQL _irql);
	//物理地址到虚拟地址
	UINT64 physicalToVirtual(UINT64 _pa);
	//虚拟地址到物理地址
	UINT64 virtualToPhysical(UINT64 _va);
	////添加G位信息
	//void addGbitInfo(PVOID _alignAddr,pde_2mb_64* _pdeAddress,pte_64* _pteAddress);
	//// 恢复G位信息
	//void resumeGbit(PVOID _alignAddr);
	//获取PteBase
	void getPteBase();
	//获取PteAddress
	UINT64 getPteAddress(uint64_t _va);
	//获取pml4e索引
	UINT64 getPml4eIndex(UINT64 _linearAddress);
	//获取pdpte索引
	UINT64 getPdpteIndex(UINT64 _linearAddress);
	//获取pde索引
	UINT64 getPdeIndex(UINT64 _linearAddress);
	//获取pte索引
	UINT64 getPteIndex(UINT64 _linearAddress);
	//获取页面偏移
	UINT64 getPageOffset(UINT64 _linearAddress);

private:

	PEPROCESS findProcess(const char* _processName);

private:
	//hook数量
	UINT32		m_hookCount;
	//hook信息
	HOOK_INFO	m_hookInfo[MAX_HOOK_COUNT]{0};
	PUCHAR		m_trampLine;
	UINT64		m_trampLineUsed;
	//是否有效
	BOOLEAN		m_valid;
	//pteBase
	UINT64		m_pteBase;
};



#endif // !PAGETABLE_PAGEHOOK_H
