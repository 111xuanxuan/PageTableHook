#include "pageHook.h"
#include "hde/hde.h"


void Log(const char* info, BOOLEAN is_err, LONG err_code /*= 0*/)
{
	if (is_err) {
		DbgPrintEx(77, 0, "[pte_hook]err:%s,err_code:%x\r\n", info, err_code);
	}
	else
	{
		DbgPrintEx(77, 0, "[pte_hook]info:%s\r\n", info);
	}
}

PageTableHookManager* PageTableHookManager::GetInstance()
{
	static PageTableHookManager* s_Instance;

	if (s_Instance == nullptr) {
		s_Instance = reinterpret_cast<PageTableHookManager*>(ExAllocatePoolWithTag(NonPagedPool,sizeof(PageTableHookManager),'p'));
		if (s_Instance == nullptr) {
			return nullptr;
		}
		s_Instance->m_valid = TRUE;
		s_Instance->m_pteBase = 0;
		s_Instance->m_trampLine = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 5, 'p '));
		if (!s_Instance->m_trampLine) {
			Log("failed to alloc trampline pool", TRUE, STATUS_MEMORY_NOT_ALLOCATED);
			s_Instance->m_valid = FALSE;
		}
		s_Instance->m_trampLineUsed = 0;
		s_Instance->m_hookCount = 0;
		RtlSecureZeroMemory(s_Instance->m_hookInfo, sizeof(s_Instance->m_hookInfo));
		s_Instance->getPteBase();
	}
	return s_Instance;
}

static int s_idleIndex=0;

BOOLEAN PageTableHookManager::pte_inline_hook(HANDLE _processId, void** _ori_addr, void* _target_func)
{

	if (!m_valid) {
		return FALSE;
	}

	//破坏函数头部最少字节数
	constexpr UINT32 BreakBytesLeast = 14;
	//跳板的字节数
	constexpr UINT32 TrampLineBreakBytes = 20;
	//实际破坏的字节数
	UINT32 uBreakBytes = 0;
	hde64s hde_info{ 0 };
	//被hook的函数的头部地址
	PUCHAR	jmpAddressStart = static_cast<PUCHAR>(*_ori_addr);
	BOOLEAN ret = FALSE;

	if (m_hookCount == MAX_HOOK_COUNT) {
		Log("hooks too many", true, 0);
		return FALSE;
	}

	for (int i = 0; i < MAX_HOOK_COUNT; ++i)
	{
		if (m_hookInfo[i].processId == 0) {
			s_idleIndex = i;
			break;
		}
	}

	NTSTATUS status;
	PEPROCESS process;
	status = PsLookupProcessByProcessId(_processId, &process);

	if (!NT_SUCCESS(status)) {
		Log("Failed to get process by process id", true, status);
		goto end;
	}
	//隔离页面
	ret = isolationPages(process, *_ori_addr);
	if (!ret) {
		goto end;
	}

	//获取实际需要破坏的字节数
	while (uBreakBytes<BreakBytesLeast)
	{
		if (!HdeDisassemble(jmpAddressStart + uBreakBytes, &hde_info)) {
			Log("failed to disasm addr", true, 0);
			ObDereferenceObject(process);
			return false;
		}

		uBreakBytes += hde_info.len;
	}
	
	 unsigned char TrampLineCode[TrampLineBreakBytes] = { 0x6a,0x00,0x3e,0xc7,0x04,0x24,0x00,0x00,0x00,0x00,0x3e,0xc7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xc3 };
	 unsigned char JmpCode[BreakBytesLeast]= { 0xff,0x25,0x00,0x00,0x00,0x00 ,0x00,0x00 ,0x00,0x00 ,0x00,0x00 ,0x00,0x00 };

	 //复制绝对跳转
	*reinterpret_cast<PUINT32>(&TrampLineCode[6]) = static_cast<UINT32>((reinterpret_cast<UINT64>(jmpAddressStart)+uBreakBytes)&0xffffffff);
	*reinterpret_cast<PUINT32>(&TrampLineCode[15]) = static_cast<UINT32>(((reinterpret_cast<UINT64>(jmpAddressStart) + uBreakBytes)>>32) & 0xffffffff);

	//保存函数头部被破坏的字节
	memcpy(m_trampLine + m_trampLineUsed, jmpAddressStart, uBreakBytes);
	//复制跳转回原函数的硬编码
	memcpy(m_trampLine + m_trampLineUsed + uBreakBytes, TrampLineCode, sizeof(TrampLineCode));

	//添加hook信息
	m_hookInfo[s_idleIndex].oricFuncAddr = jmpAddressStart;
	memcpy(m_hookInfo[s_idleIndex].saveCode, jmpAddressStart, 14);
	m_hookInfo[s_idleIndex].processId = _processId;
	++m_hookCount;

	*reinterpret_cast<PUINT64>(&JmpCode[6]) = reinterpret_cast<UINT64>(_target_func); 
	KAPC_STATE apc;
	KeStackAttachProcess(process, &apc);
	//关闭写保护，对函数头部写入跳转
	auto irql = wp_off();
	memcpy(jmpAddressStart, JmpCode, 14);
	wp_on(irql);
	KeUnstackDetachProcess(&apc);
	*_ori_addr = m_trampLine + m_trampLineUsed;
	m_trampLineUsed += static_cast<UINT64>(uBreakBytes) + TrampLineBreakBytes;

end:
	ObDereferenceObject(process);
	if (!ret) {
		if (m_hookInfo[s_idleIndex].mem1.addrBase) {
			MmFreeContiguousMemorySpecifyCache(m_hookInfo[s_idleIndex].mem1.addrBase, m_hookInfo[s_idleIndex].mem1.size, MmCached);
			m_hookInfo[s_idleIndex].mem1.addrBase = nullptr;
		}
		if (m_hookInfo[s_idleIndex].mem2.addrBase) {
			MmFreeContiguousMemorySpecifyCache(m_hookInfo[s_idleIndex].mem2.addrBase, m_hookInfo[s_idleIndex].mem2.size, MmCached);
			m_hookInfo[s_idleIndex].mem2.addrBase = nullptr;
		}
	}
	return ret;
}

BOOLEAN PageTableHookManager::pte_remove_hook(HANDLE _processId, void* _ori_func_addr)
{
	if (_processId == 0) {
		return FALSE;
	}

	PEPROCESS process;
	KAPC_STATE apc;
	NTSTATUS status = PsLookupProcessByProcessId(_processId, &process);

	if (!NT_SUCCESS(status)) {
		Log("Failed to get process by process id", TRUE, status);
		return FALSE;
	}

	for (int i=0;i<MAX_HOOK_COUNT;++i)
	{
		if ((_processId == m_hookInfo[i].processId)&&(m_hookInfo[i].oricFuncAddr==_ori_func_addr)) {
			KeStackAttachProcess(process, &apc);
			auto Irql = wp_off();
			memcpy(_ori_func_addr, m_hookInfo[i].saveCode, 14);
			cr3 c3;
			c3.Flags = __readcr3();
			pml4e_64* pml4t = reinterpret_cast<pml4e_64*>(physicalToVirtual(c3.address_of_page_directory * PAGE_SIZE));
			pml4t[getPml4eIndex(reinterpret_cast<UINT64>(_ori_func_addr))].page_frame_number = m_hookInfo[i].pageFrameNumber;
			if (m_hookInfo[i].mem1.addrBase) {
				MmFreeContiguousMemorySpecifyCache(m_hookInfo[i].mem1.addrBase, m_hookInfo[i].mem1.size, MmCached);
				m_hookInfo[i].mem1.addrBase = nullptr;
			}
			MmFreeContiguousMemorySpecifyCache(m_hookInfo[i].mem2.addrBase, m_hookInfo[i].mem2.size, MmCached);
			m_hookInfo[i].mem2.addrBase = nullptr;
			wp_on(Irql);
			KeUnstackDetachProcess(&apc);
			m_hookInfo[i].processId = 0;
			--m_hookCount;

			ObDereferenceObject(process);
			return TRUE;
		}
	}

	ObDereferenceObject(process);
	return FALSE;
}

void PageTableHookManager::clean()
{
	for (int i = 0; i < MAX_HOOK_COUNT; ++i)
	{
		if (m_hookInfo[i].processId) {
			pte_remove_hook(m_hookInfo[i].processId, m_hookInfo[i].oricFuncAddr);
		}
	}

	if (m_trampLine) {
		ExFreePoolWithTag(m_trampLine, 'p');
		m_trampLine = nullptr;
	}
}

BOOLEAN PageTableHookManager::isolationPages(PEPROCESS _process, PVOID _va)
{
	PVOID alignIsoAddr= PAGE_ALIGN(_va);
	PAGE_TABLE table{ 0 };
	PHYSICAL_ADDRESS low{ 0 }, high{ 0 };
	high.QuadPart = MAXULONG64;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KAPC_STATE apc{ 0 };
	//附加进程
	KeStackAttachProcess(_process, &apc);
	table.linearAddress =reinterpret_cast<UINT64>(alignIsoAddr);
	getPageTable(table);

	BOOLEAN bSuc;
	//分割完后的pde
	pde_64 splitPde{ 0 };
	//如果是大页
	if (table.pdeAddress->large_page == 1) {

		auto pdeAddress_2mb = reinterpret_cast<pde_2mb_64*>(table.pdeAddress);

		//分割物理页
		bSuc = splitLargePages(pdeAddress_2mb, &splitPde);

		if (!bSuc) {
			goto end;
		}

		//取消G位
		if (pdeAddress_2mb->global == 1) {
			pdeAddress_2mb->global = 0;
			//添加G位信息
			//addGbitInfo(alignIsoAddr, pdeAddress_2mb, nullptr);
		}

	}//如果是小页
	else
	{
		//取消G位
		if (table.pteAddress->global == 1) {
			table.pteAddress->global = 0;
			//添加G位信息
			//addGbitInfo(alignIsoAddr, nullptr, table.pteAddress);
		}
	}

	cr3 c3;
	c3.Flags = __readcr3();
	//替换页表
	bSuc = replacePageTable(c3,reinterpret_cast<UINT64>(alignIsoAddr), &splitPde);

	if (bSuc) {
		Log("isolation success!", false);
	}
	else {
		Log("failed isolation", true, 0);
	}

end:
	KeUnstackDetachProcess(&apc);
	return bSuc;
}

BOOLEAN PageTableHookManager::splitLargePages(pde_2mb_64* _inPde, pde_64* _outPde)
{
	PHYSICAL_ADDRESS maxAddrPa{ 0 }, lowAddrPa{ 0 };
	maxAddrPa.QuadPart = MAXULONG64;
	lowAddrPa.QuadPart = 0;
	//2mb页面下的27位的页帧号转换到4kb下36位的页帧号
	auto startPfn = _inPde->page_frame_number<<9;
	//申请一个物理页当作pt
	pte_64* pt = reinterpret_cast<pte_64*>(MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE,lowAddrPa,maxAddrPa,lowAddrPa,MmCached));
	if (!pt) {
		Log("failed to alloc physical memory for new pt", true, STATUS_NO_MEMORY);
		return FALSE;
	}

	//保存申请内存的记录，方便释放
	m_hookInfo[s_idleIndex].mem1.addrBase = pt;
	m_hookInfo[s_idleIndex].mem1.size = PAGE_SIZE;

	//给PageTable的每一项赋值
	for (int i = 0; i < 512; ++i)
	{
		pt[i].Flags = _inPde->Flags;
		pt[i].pat = 0;
		pt[i].global = 0;
		pt[i].page_frame_number = startPfn + i;
	}

	_outPde->Flags = _inPde->Flags;
	//将大页位设为0
	_outPde->large_page = 0;
	//将申请的pt的物理页帧号赋值到outPte
	_outPde->page_frame_number = virtualToPhysical(reinterpret_cast<UINT64>(pt)) / PAGE_SIZE;
	return TRUE;
}

BOOLEAN PageTableHookManager::replacePageTable(cr3 _cr3, UINT64 _alignAddr, pde_64* _splitPde)
{
	PHYSICAL_ADDRESS maxAddrPa{ 0 }, lowAddrPa{ 0 };
	maxAddrPa.QuadPart = MAXULONG64;
	lowAddrPa.QuadPart = 0;

	//申请连续的4个4kb物理页来模拟3个表一个页.4kb,pt,pdt,pdpt
	PUINT64 va = reinterpret_cast<PUINT64>(MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE*4,lowAddrPa,maxAddrPa,lowAddrPa,MmCached));

	if (!va) {
		Log("failed to alloc page table entry", TRUE, STATUS_NO_MEMORY);
		return FALSE;
	}

	m_hookInfo[s_idleIndex].mem2.addrBase = va;
	m_hookInfo[s_idleIndex].mem2.size = 4 * PAGE_SIZE;

	UINT64 *va4kb = 0, * vaPt = 0, * vaPdt = 0, * vaPdpt = 0, * vaPml4t = 0;
	va4kb = va;
	vaPt =reinterpret_cast<PUINT64>( reinterpret_cast<PUCHAR>(va) + PAGE_SIZE);
	vaPdt = reinterpret_cast<PUINT64>(reinterpret_cast<PUCHAR>(va) + 2 * PAGE_SIZE);
	vaPdpt = reinterpret_cast<PUINT64>(reinterpret_cast<PUCHAR>(va) + 3 * PAGE_SIZE);
	vaPml4t =reinterpret_cast<PUINT64>( physicalToVirtual(_cr3.address_of_page_directory * PAGE_SIZE));

	auto pteIndex = getPteIndex(_alignAddr);
	auto pdeIndex = getPdeIndex(_alignAddr);
	auto pdpteIndex = getPdpteIndex(_alignAddr);
	auto pml4eIndex = getPml4eIndex(_alignAddr);

	PAGE_TABLE table;
	table.linearAddress =_alignAddr;
	getPageTable(table);

	//复制4kb页面
	memcpy(va, reinterpret_cast<PVOID>(_alignAddr), PAGE_SIZE);

	//如果是小页，大页无pt
	if (table.pdeAddress->large_page==0) {
		//复制pt
		memcpy(vaPt, table.pteAddress - pteIndex, PAGE_SIZE);
	}
	else
	{
		vaPt =reinterpret_cast<PUINT64>( physicalToVirtual(_splitPde->page_frame_number * PAGE_SIZE));
	}
	//复制pdt
	memcpy(vaPdt, table.pdeAddress - pdeIndex , PAGE_SIZE);
	//复制pdpt
	memcpy(vaPdpt, table.ppeAddress - pdpteIndex, PAGE_SIZE);
	//pt表项赋值
	reinterpret_cast<pte_64*>(vaPt)[pteIndex].page_frame_number = virtualToPhysical(reinterpret_cast<UINT64>(va4kb)) / PAGE_SIZE;
	//pdt表项赋值
	auto pde = &reinterpret_cast<pde_64*>(vaPdt)[pdeIndex];
	pde->page_frame_number = virtualToPhysical(reinterpret_cast<UINT64>(vaPt)) / PAGE_SIZE;
	pde->large_page = 0;
	pde->ignored_1 = 0;//2mb页面的bit位是D
	pde->page_level_cache_disable = 0;//禁用页面级缓存位
	//pdpt表项赋值
	reinterpret_cast<pdpte_64*>(vaPdpt)[pdpteIndex].page_frame_number=virtualToPhysical(reinterpret_cast<UINT64>(vaPdt))/PAGE_SIZE;
	//pml4t表项赋值
	auto pml4e = &reinterpret_cast<pml4e_64*>(vaPml4t)[pml4eIndex];
	m_hookInfo[s_idleIndex].pageFrameNumber = pml4e->page_frame_number;
	pml4e->page_frame_number = virtualToPhysical(reinterpret_cast<UINT64>(vaPdpt)) / PAGE_SIZE;
	//刷新tlb
	__invlpg(pml4e);
	return TRUE;
}

void PageTableHookManager::getPageTable(PAGE_TABLE& _table)
{
	auto va = _table.linearAddress;
	_table.pteAddress = reinterpret_cast<pte_64*>(getPteAddress(va));
	_table.pdeAddress = reinterpret_cast<pde_64*>(getPteAddress(reinterpret_cast<UINT64>(_table.pteAddress)));
	_table.ppeAddress = reinterpret_cast<pdpte_64*>(getPteAddress(reinterpret_cast<UINT64>(_table.pdeAddress)));
	_table.pxeAddress = reinterpret_cast<pml4e_64*>(getPteAddress(reinterpret_cast<UINT64>(_table.ppeAddress)));
}

KIRQL PageTableHookManager::wp_off()
{
	//提升irql以屏蔽低中断
	auto irql = KeRaiseIrqlToDpcLevel();  
	//读取cr0
	uint64_t Cr0 = __readcr0();
	//清除写保护位
	Cr0 &= 0xfffffffffffeffff;
	//写入cr0
	__writecr0(Cr0);
	//禁用中断
	_disable();
	return irql;
}

void PageTableHookManager::wp_on(KIRQL _irql)
{
	uint64_t Cr0 = __readcr0();
	Cr0 |= 0x10000;
	//开启中断
	_enable();
	__writecr0(Cr0);
	//降低irql
	KeLowerIrql(_irql);
}

UINT64 PageTableHookManager::physicalToVirtual(UINT64 _pa)
{
	PHYSICAL_ADDRESS phy;
	phy.QuadPart = _pa;
	return reinterpret_cast<UINT64>(MmGetVirtualForPhysical(phy));
}

UINT64 PageTableHookManager::virtualToPhysical(UINT64 _va)
{
	return MmGetPhysicalAddress(reinterpret_cast<PVOID>(_va)).QuadPart;
}

void PageTableHookManager::getPteBase()
{
	cr3 Cr3;
	Cr3.Flags = __readcr3();
	//获取页表目录首地址
	pml4e_64* pPml4e = reinterpret_cast<pml4e_64*>(physicalToVirtual(Cr3.address_of_page_directory*PAGE_SIZE));
	//查找自映射索引
	for (UINT64 i=0;i<512;++i)
	{
		if (pPml4e[i].page_frame_number == Cr3.address_of_page_directory) {
			m_pteBase = 0xffff000000000000|(i<<39);
			return;
		}
	}
}

UINT64 PageTableHookManager::getPteAddress(uint64_t _va)
{
	//清除高16位
	_va &= 0xffffffffffff;
	auto offset = (_va >> 12) << 3;
	return m_pteBase + offset;
}

UINT64 PageTableHookManager::getPml4eIndex(UINT64 _linearAddress)
{
	return (_linearAddress >> 39) & 0x1ff;
}

UINT64 PageTableHookManager::getPdpteIndex(UINT64 _linearAddress)
{
	return (_linearAddress >> 30) & 0x1ff;
}

UINT64 PageTableHookManager::getPdeIndex(UINT64 _linearAddress)
{
	return (_linearAddress >> 21) & 0x1ff;
}

UINT64 PageTableHookManager::getPteIndex(UINT64 _linearAddress)
{
	return (_linearAddress >> 12) & 0x1ff;
}

UINT64 PageTableHookManager::getPageOffset(UINT64 _linearAddress)
{
	return _linearAddress & 0xfff;
}

PEPROCESS PageTableHookManager::findProcess(const char* _processName)
{
	//21h2
	PLIST_ENTRY pEntry=reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<PCHAR>(PsInitialSystemProcess)+0x448);
	PLIST_ENTRY pActiveEntryHead = pEntry;
	PEPROCESS eProcess = nullptr;

	do 
	{
		eProcess = reinterpret_cast<PEPROCESS>(reinterpret_cast<PCHAR>(pEntry)-0x448);
		const char* imageFileName = reinterpret_cast<const char*>(eProcess) + 0x5a8;
		UINT32 minSize = strlen(imageFileName) >= strlen(_processName) ? strlen(_processName) : strlen(imageFileName);
		if (strncmp(imageFileName, _processName, minSize) == 0) {
			return eProcess;
		}
		pEntry = pEntry->Flink;
	} while (pEntry!=pActiveEntryHead);

	return nullptr;
}

