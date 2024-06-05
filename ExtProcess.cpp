#include "ExtProcess.hpp"
#include "LocalProcess.hpp"

bool ExtProcessA::updateModuleInfo_x86() noexcept
{
	if (!m_processInfo.wow64Process)
		return false;

	const QWORD peb32Addr{ getPEBAddress_x86() };

	if (!peb32Addr)
		return false;

	PEB32 peb32{};

	if (!RPM(static_cast<QWORD>(peb32Addr), static_cast<void*>(&peb32), sizeof(peb32), nullptr))
		return false;

	PEB_LDR_DATA32 loaderData{};

	if (!RPM(static_cast<QWORD>(peb32.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return false;

	DWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const DWORD startAddressIterator{ currEntryAddr };

	std::vector<Process::ModuleInformationA> newModuleList{};

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY32 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY32>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == startAddressIterator)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			Process::ModuleInformationA currentModule{};
			std::wstring realModName{ reinterpret_cast<wchar_t*>(pModuleName) };

			currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::string{ realModName.begin(), realModName.end() };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	m_x86Modules = newModuleList;

	return true;
}

bool ExtProcessA::updateModuleInfo_x64() noexcept
{
	const QWORD peb64Addr{ getPEBAddress_x64() };

	if (!peb64Addr)
		return false;

	PEB64 peb64{};

	if (!RPM(static_cast<QWORD>(peb64Addr), static_cast<void*>(&peb64), sizeof(peb64), nullptr))
		return false;

	PEB_LDR_DATA64 loaderData{};

	if (!RPM(static_cast<QWORD>(peb64.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return false;

	QWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const QWORD startAddressIterator{ currEntryAddr };

	std::vector<Process::ModuleInformationA> newModuleList{};

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY64>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == startAddressIterator)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			Process::ModuleInformationA currentModule{};
			std::wstring realModName{ reinterpret_cast<wchar_t*>(pModuleName) };

			currentModule.modBA.x64Addr = currentLoaderEntry.DllBase;
			currentModule.modName = std::string{ realModName.begin(), realModName.end() };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	m_x64Modules = newModuleList;

	return true;
}


#ifndef _WIN64
BOOL ExtProcessA::RPM_Wow64(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept
{
	if (!pBuffer || !size || !readAddr)
		return FALSE;

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(LocalProcessA::getInstance().getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(LocalProcessA::getInstance().getNativeProcAddress( "NtWow64ReadVirtualMemory64"));
		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64RVM(m_hProc, readAddr, pBuffer, size, pBytesRead) == STATUS_SUCCESS);
}

BOOL ExtProcessA::WPM_Wow64(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept
{
	if (!pBuffer || !size || !writeAddr)
		return FALSE;

	static tNtWow64WriteVirtualMemory64 _NtWow64WVM{ reinterpret_cast<tNtWow64WriteVirtualMemory64>(LocalProcessA::getInstance().getNativeProcAddress( "NtWow64WriteVirtualMemory64")) };

	if (!_NtWow64WVM)
	{
		_NtWow64WVM = reinterpret_cast<tNtWow64WriteVirtualMemory64>(LocalProcessA::getInstance().getNativeProcAddress( "NtWow64WriteVirtualMemory64"));
		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64WVM(m_hProc, writeAddr, pBuffer, size, pBytesWritten) == STATUS_SUCCESS);
}


QWORD ExtProcessA::AVM_Wow64(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept
{
	if (!size)
		return 0;

	static QWORD _NtWow64AVM{ LocalProcessA::getInstance().getNativeProcAddressWow64("NtAllocateVirtualMemory") };

	if (!_NtWow64AVM)
	{
		_NtWow64AVM = LocalProcessA::getInstance().getNativeProcAddressWow64("NtAllocateVirtualMemory");
		return 0;
	}

	QWORD resultAllocAddr{ allocAddr };
	QWORD resultSize{ size };

	if (!LocalProcessA::getInstance().callNativeFunction(_NtWow64AVM, 6, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultAllocAddr), static_cast<QWORD>(0), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(allocType), static_cast<QWORD>(protectionFlags)))
	{
		return 0;
	}

	return resultAllocAddr;
}

BOOL ExtProcessA::FVM_Wow64(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept
{
	if (!freeAddr)
		return FALSE;

	if (!size && !(freeType & MEM_RELEASE))
		return FALSE;

	static QWORD _NtWow64FVM{ LocalProcessA::getInstance().getNativeProcAddressWow64("NtFreeVirtualMemory") };

	if (!_NtWow64FVM)
	{
		_NtWow64FVM = LocalProcessA::getInstance().getNativeProcAddressWow64("NtFreeVirtualMemory");
		return FALSE;
	}

	QWORD resultFreeAddr{ freeAddr };
	QWORD resultSize{ (freeType & MEM_RELEASE) ? 0 : size };

	return LocalProcessA::getInstance().callNativeFunction(_NtWow64FVM, 4, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultFreeAddr), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(freeType));
}


BOOL ExtProcessA::PVM_Wow64(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept
{
	if (!protectAddr || !protectLength || !pOldProtect)
		return FALSE;

	static QWORD _NtWow64PVM{ LocalProcessA::getInstance().getNativeProcAddressWow64("NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = LocalProcessA::getInstance().getNativeProcAddressWow64("NtProtectVirtualMemory");
		return FALSE;
	}

	QWORD resultProtectAddr{ protectAddr };
	QWORD resultSize{ protectLength };

	return LocalProcessA::getInstance().callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultProtectAddr), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(protectFlags), reinterpret_cast<QWORD>(pOldProtect));
}

SIZE_T ExtProcessA::QVM_Wow64(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept
{
	if (!baseAddr || !pMBI)
		return 0;

	static QWORD _NtWow64QVM{ LocalProcessA::getInstance().getNativeProcAddressWow64("NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = LocalProcessA::getInstance().getNativeProcAddressWow64("NtQueryVirtualMemory");
		return 0;
	}

	QWORD returnLength{};

	if (!LocalProcessA::getInstance().callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), baseAddr, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(pMBI), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
	{
		return 0;
	}

	return returnLength;
}
#endif


ExtProcessA::ExtProcessA() noexcept
{
}

ExtProcessA::ExtProcessA(const std::string& procName, const DWORD handleFlags) noexcept
	: IProcessA{ { 0, 0, procName, 0, 0, false }, INVALID_HANDLE_VALUE }
	, m_handleFlags{ handleFlags }
	, m_closeHandleOnDetach{ true }
	, m_reattachByName{ true }
{
	m_attached = attach(procName);
}

ExtProcessA::ExtProcessA(const DWORD procID, const DWORD handleFlags) noexcept
	: IProcessA{ { procID, 0, std::string{}, 0, 0, false }, INVALID_HANDLE_VALUE }
	, m_handleFlags{ handleFlags }
	, m_closeHandleOnDetach{ true }
	, m_reattachByName{ false }
{
	m_attached = attach(procID);
}

ExtProcessA::ExtProcessA(const HANDLE duplicatedHandle, bool reattachByName, bool closeHandleOnDetach) noexcept
	: IProcessA{ duplicatedHandle }
	, m_handleFlags{}
	, m_closeHandleOnDetach{ closeHandleOnDetach }
	, m_reattachByName{ reattachByName }
{
	m_attached = attach(duplicatedHandle, reattachByName, closeHandleOnDetach);
}

ExtProcessA::~ExtProcessA()
{
	if (m_attached)
		detach();
}


bool ExtProcessA::attach(const std::string& procName) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationA{};
	m_processInfo.procName = procName;
	m_hProc = INVALID_HANDLE_VALUE;

	m_closeHandleOnDetach = true;
	m_reattachByName = true;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessA::attach(const DWORD procID) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationA{};
	m_processInfo.procID = procID;
	m_hProc = INVALID_HANDLE_VALUE;

	m_closeHandleOnDetach = true;
	m_reattachByName = false;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessA::attach(const HANDLE hProc, bool reattachByName, bool closeHandleOnDetach) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationA{};
	m_hProc = hProc;

	m_closeHandleOnDetach = closeHandleOnDetach;
	m_reattachByName = reattachByName;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessA::detach() noexcept
{
	if (!m_attached)
		return false;

	Process::ProcessInformationA newProcessInfo{};

	if (m_reattachByName)
		newProcessInfo.procName = m_processInfo.procName;
	else
		newProcessInfo.procID = m_processInfo.procID;

	m_processInfo = newProcessInfo;

	if (!m_handleFlags)
		m_handleFlags = PROCESS_ALL_ACCESS;

	if (m_closeHandleOnDetach && validProcessHandle(m_hProc))
		CloseHandle(m_hProc);

	m_hProc = INVALID_HANDLE_VALUE;
	m_closeHandleOnDetach = true;

	m_attached = false;

	return true;
}

bool ExtProcessA::reattach() noexcept
{
	if (m_attached)
		detach();

	m_x86Modules.clear();
	m_x64Modules.clear();

	m_x86Modules.reserve(20);
	m_x64Modules.reserve(20);

	if (!m_processInfo.procID && m_processInfo.procName.empty())
	{
		if (!validProcessHandle(m_hProc))
			return false;

		m_handleFlags = getHandleFlags(m_hProc);
	}
	else
	{
		HANDLE hProc{ INVALID_HANDLE_VALUE };

		if (m_processInfo.procID)
		{
			hProc = OpenProcess(m_handleFlags, FALSE, m_processInfo.procID);
		}
		else
		{
			const DWORD procID{ getProcess(m_processInfo.procName).procID };

			if (!procID)
				return false;

			hProc = OpenProcess(m_handleFlags, FALSE, procID);
		}

		if (!validHandle(hProc))
			return false;

		m_hProc = hProc;
	}

	const Process::ProcessInformationA oldProcInfo{ m_processInfo };

	m_processInfo = getProcess(m_hProc);

	if (m_processInfo.procID && !m_processInfo.procName.empty())
	{
		m_attached = true;
		updateModuleInfo();
	}
	else
	{
		m_attached = false;
		m_processInfo = oldProcInfo;
	}

	return m_attached;
}


bool ExtProcessA::updateProcessInfo() noexcept
{
	const Process::ProcessInformationA newProcInfo{ getProcess(m_hProc) };

	if (validProcess(newProcInfo) && !newProcInfo.procName.empty())
	{
		m_processInfo.parentProcID = newProcInfo.parentProcID;
		m_processInfo.threadBasePriority = newProcInfo.threadBasePriority;
		m_processInfo.threadCount = newProcInfo.threadCount;

		return true;
	}

	return false;
}

bool ExtProcessA::updateModuleInfo() noexcept
{
	bool status{ updateModuleInfo_x64() };

	if (m_processInfo.wow64Process)
	{
		status = updateModuleInfo_x86() && status;
	}

	return status;
}


QWORD ExtProcessA::getPEBAddress_x86() const noexcept
{
	if (!m_processInfo.wow64Process)
		return 0;

#ifdef _WIN64

	ULONG_PTR peb32Addr{};

	return (QIP(ProcessWow64Information, &peb32Addr, sizeof(peb32Addr), nullptr) ? static_cast<QWORD>(peb32Addr) : 0);

#else

	PROCESS_BASIC_INFORMATION pbi{};

	return (QIP(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? reinterpret_cast<QWORD>(pbi.PebBaseAddress) : 0);

#endif
}

QWORD ExtProcessA::getPEBAddress_x64() const noexcept
{
	PROCESS_BASIC_INFORMATION64 pbi{};

#ifdef _WIN64
	return (QIP(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? pbi.PEB_BaseAddress : 0);
#else
	return (QIP_Wow64(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? pbi.PEB_BaseAddress : 0);
#endif
}


Process::ModuleInformationA ExtProcessA::getModuleInfo_x86(const std::string& modName) const noexcept
{
	if (!m_processInfo.wow64Process)
		return Process::ModuleInformationA{};

	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationA newModule{};

	const QWORD peb32Addr{ getPEBAddress_x86() };

	if (!peb32Addr)
		return newModule;

	PEB32 peb32{};

	if (!RPM(static_cast<QWORD>(peb32Addr), static_cast<void*>(&peb32), sizeof(peb32), nullptr))
		return newModule;

	PEB_LDR_DATA32 loaderData{};

	if (!RPM(static_cast<QWORD>(peb32.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return newModule;

	DWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const DWORD startAddressIterator{ currEntryAddr };

	std::wstring searchedModule{ modName.begin(), modName.end() };

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY32 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY32>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			return newModule;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			if (!_wcsicmp(searchedModule.c_str(), reinterpret_cast<wchar_t*>(pModuleName)))
			{
				std::wstring realModName{ reinterpret_cast<wchar_t*>(pModuleName) };

				delete[] pModuleName;
				pModuleName = nullptr;

				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = std::string{ realModName.begin(), realModName.end() };
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	return newModule;
}

Process::ModuleInformationA ExtProcessA::getModuleInfo_x64(const std::string& modName) const noexcept
{
	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationA newModule{};

	const QWORD peb64Addr{ getPEBAddress_x64() };

	if (!peb64Addr)
		return newModule;

	PEB64 peb64{};

	if (!RPM(static_cast<QWORD>(peb64Addr), static_cast<void*>(&peb64), sizeof(peb64), nullptr))
		return newModule;

	PEB_LDR_DATA64 loaderData{};

	if (!RPM(static_cast<QWORD>(peb64.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return newModule;

	QWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const QWORD startAddressIterator{ currEntryAddr };

	std::wstring searchedModule{ modName.begin(), modName.end() };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (!RPM(currEntryAddr, static_cast<void*>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr))
			return newModule;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			return newModule;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr);

			if (!_wcsicmp(searchedModule.c_str(), reinterpret_cast<wchar_t*>(pModuleName)))
			{
				std::wstring realModName{ reinterpret_cast<wchar_t*>(pModuleName) };

				delete[] pModuleName;
				pModuleName = nullptr;

				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = std::string{ realModName.begin(), realModName.end() };
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	return newModule;
}


QWORD ExtProcessA::getProcAddress_x86(const QWORD modBA, const std::string& functionName) const noexcept
{
	if (modBA > static_cast<QWORD>(0xFFFFFFFF))
		return 0;

	QWORD procAddress{};

	const IMAGE_DOS_HEADER dosHeader{ RPM<IMAGE_DOS_HEADER>(static_cast<uintptr_t>(modBA)) };

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS32 ntHeader{ RPM<IMAGE_NT_HEADERS32>(modBA + dosHeader.e_lfanew) };

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x10B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY exportDirectory{ RPM<IMAGE_EXPORT_DIRECTORY>(modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	if (!RPM(exportTableAddr, exportTable.data(), static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)), nullptr) ||
		!RPM(ordinalsAddr, ordinalTable.data(), static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)), nullptr) ||
		!RPM(namesAddr, nameTable.data(), static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)), nullptr))
	{
		return 0;
	}

	char nameBuffer[128]{};

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		if (!RPM(modBA + nameTable.at(iterator), nameBuffer, sizeof(nameBuffer), nullptr))
		{
			continue;
		}
		else
		{
			std::string strTableEntry{ &nameBuffer[0] };

			if (!_stricmp(strTableEntry.c_str(), functionName.c_str()))
			{
				const WORD ordinal{ ordinalTable.at(iterator) };
				procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

				if (procAddress > static_cast<QWORD>(0xFFFFFFFF))
					return 0;

				break;
			}
		}
	}

	return procAddress;
}

QWORD ExtProcessA::getProcAddress_x64(const QWORD modBA, const std::string& functionName) const noexcept
{
	QWORD procAddress{};

	const IMAGE_DOS_HEADER dosHeader{ RPM<IMAGE_DOS_HEADER>(modBA) };

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS64 ntHeader{ RPM<IMAGE_NT_HEADERS64>(modBA + dosHeader.e_lfanew) };

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x20B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY exportDirectory{ RPM<IMAGE_EXPORT_DIRECTORY>(modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	if (!RPM(exportTableAddr, exportTable.data(), static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)), nullptr) ||
		!RPM(ordinalsAddr, ordinalTable.data(), static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)), nullptr) ||
		!RPM(namesAddr, nameTable.data(), static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)), nullptr))
	{
		return 0;
	}

	char nameBuffer[128]{};

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		if (!RPM(modBA + nameTable.at(iterator), nameBuffer, sizeof(nameBuffer), nullptr))
		{
			continue;
		}
		else
		{
			std::string strTableEntry{ &nameBuffer[0] };

			if (!_stricmp(strTableEntry.c_str(), functionName.c_str()))
			{
				const WORD ordinal{ ordinalTable.at(iterator) };
				procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

				break;
			}
		}
	}

	return procAddress;
}


QWORD ExtProcessA::getProcAddress_x86(const std::string modName, const std::string& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD ExtProcessA::getProcAddress_x64(const std::string modName, const std::string& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getProcAddress_x64(modBA, functionName) : 0;
}


Process::ModuleInformationA ExtProcessA::getModuleInfo_x86(const std::string& modName) noexcept
{
	if (!m_processInfo.wow64Process)
		return Process::ModuleInformationA{};

	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationA modInfo{ const_cast<const ExtProcessA* const>(this)->getModuleInfo_x86(modName) };

	if (validModule(modInfo))
		m_x86Modules.push_back(modInfo);

	return modInfo;
}

Process::ModuleInformationA ExtProcessA::getModuleInfo_x64(const std::string& modName) noexcept
{
	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationA modInfo{ const_cast<const ExtProcessA* const>(this)->getModuleInfo_x64(modName) };

	if (validModule(modInfo))
		m_x64Modules.push_back(modInfo);

	return modInfo;
}


QWORD ExtProcessA::scanPattern(const Process::SignatureA& signature) const noexcept
{
	QWORD result{};

	if (m_processInfo.wow64Process)
	{
		for (const Process::ModuleInformationA& currModule : m_x86Modules)
		{
			if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x86({ signature, currModule.modName })))
			{
				return result;
			}
		}
	}

	for (const Process::ModuleInformationA& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x64({ signature, currModule.modName })))
		{
			return result;
		}
	}

	return result;
}

QWORD ExtProcessA::scanPattern_x86(const Process::ModuleSignatureA& signature) const noexcept
{
	if (!m_processInfo.wow64Process)
		return 0;

	if (!signature.pattern.size())
		return 0;

	//bool found{ false };

	//QWORD result{ getPatternAddress_x86(signature, found) };

	const std::vector<Process::FoundGadgetA> foundPatterns{ findGadgets_x86(signature) };

	QWORD result{ (foundPatterns.size()) ? foundPatterns.front().absoluteAddress : 0 };

	if (!result)
		return 0;

	//if (!found)
		//return 0;

	for (const DWORD currOffset : signature.offsets)
	{
		result = static_cast<QWORD>(RPM<DWORD>(result + currOffset));
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x86(signature.moduleName);

	return result;
}

QWORD ExtProcessA::scanPattern_x64(const Process::ModuleSignatureA& signature) const noexcept
{
	if (!signature.pattern.size())
		return 0;

	//bool found{ false };

	//QWORD result{ getPatternAddress_x64(signature, found) };

	const std::vector<Process::FoundGadgetA> foundPatterns{ findGadgets_x64(signature) };

	QWORD result{ (foundPatterns.size()) ? foundPatterns.front().absoluteAddress : 0 };

	if (!result)
		return 0;

	//if (!found)
		//return 0;

	for (const DWORD currOffset : signature.offsets)
	{
		result = RPM<QWORD>(result + currOffset);
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
}


int ExtProcessA::patternCount(const Process::SignatureA& signature) const noexcept
{
	return findGadgets(signature).size();
}

int ExtProcessA::patternCount_x86(const Process::ModuleSignatureA& signature) const noexcept
{
	return findGadgets_x86(signature).size();
}

int ExtProcessA::patternCount_x64(const Process::ModuleSignatureA& signature) const noexcept
{
	return findGadgets_x64(signature).size();
}


std::vector<Process::FoundGadgetA> ExtProcessA::findGadgets(const Process::SignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

	if (m_processInfo.wow64Process)
	{
		for (const Process::ModuleInformationA& currModule : m_x86Modules)
		{
			if (validModule(currModule) && !currModule.modName.empty())
			{
				std::vector<Process::FoundGadgetA> moduleGadgets{ findGadgets_x86({signature, currModule.modName }) };

				if (moduleGadgets.size())
					result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
			}
		}
	}

	for (const Process::ModuleInformationA& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty())
		{
			std::vector<Process::FoundGadgetA> moduleGadgets{ findGadgets_x64({signature, currModule.modName }) };

			if (moduleGadgets.size())
				result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
		}
	}

	return result;
}

std::vector<Process::FoundGadgetA> ExtProcessA::findGadgets_x86(const Process::ModuleSignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

	if (m_processInfo.wow64Process)
		return result;

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!QVM(static_cast<QWORD>(currAddress), &mbi))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				continue;
			}

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetA currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
					currGadget.readable = signature.readable;
					currGadget.writable = signature.writable;
					currGadget.pattern = pattern;
					currGadget.moduleName = modInfo.modName;

					currGadget.bytes.clear();
					currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

					result.push_back(currGadget);
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
		else
		{
			DWORD oldProtect{};

			if (PVM(currAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
				{
					PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
						currGadget.readable = signature.readable;
						currGadget.writable = signature.writable;
						currGadget.pattern = pattern;
						currGadget.moduleName = modInfo.modName;

						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						result.push_back(currGadget);
					}
				}

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
			}
		}
	}

	return result;
}

std::vector<Process::FoundGadgetA> ExtProcessA::findGadgets_x64(const Process::ModuleSignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!QVM(currAddress, &mbi))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				continue;
			}

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetA currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
					currGadget.readable = signature.readable;
					currGadget.writable = signature.writable;
					currGadget.pattern = pattern;
					currGadget.moduleName = modInfo.modName;

					currGadget.bytes.clear();
					currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

					result.push_back(currGadget);
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
		else
		{
			DWORD oldProtect{};

			if (PVM(currAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
				{
					PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
						currGadget.readable = signature.readable;
						currGadget.writable = signature.writable;
						currGadget.pattern = pattern;
						currGadget.moduleName = modInfo.modName;

						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						result.push_back(currGadget);
					}
				}

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
			}
		}
	}

	return result;
}


bool ExtProcessA::validProcessHandle(const HANDLE handle) noexcept
{
	if (!validHandle(handle))
		return false;

	static tNtQueryObject _NtQueryObject{ reinterpret_cast<tNtQueryObject>(LocalProcessA::getInstance().getNativeProcAddress("NtQueryObject"))};

	if (!_NtQueryObject)
	{
		_NtQueryObject = reinterpret_cast<tNtQueryObject>(LocalProcessA::getInstance().getNativeProcAddress("NtQueryObject"));

		return false;
	}

	OBJECT_TYPE_INFORMATION oti[2]{};	//Allocate 2 of these structures to deal with potential buffer overrun
	ULONG dummyRetLen{};

	if (_NtQueryObject(handle, ObjectTypeInformation, static_cast<PVOID>(&oti[0]), static_cast<ULONG>(sizeof(oti)), &dummyRetLen) != STATUS_SUCCESS)
	{
		return false;
	}

	if (oti[0].TypeIndex == static_cast<UCHAR>(0x7))
		return true;
	else
		return false;
}

DWORD ExtProcessA::getHandleFlags(const HANDLE handle) noexcept
{
	static tNtQueryObject _NtQueryObject{ reinterpret_cast<tNtQueryObject>(LocalProcessA::getInstance().getNativeProcAddress("NtQueryObject")) };

	if (!_NtQueryObject)
	{
		_NtQueryObject = reinterpret_cast<tNtQueryObject>(LocalProcessA::getInstance().getNativeProcAddress("NtQueryObject"));

		return 0;
	}

	OBJECT_BASIC_INFORMATION obi[1]{};
	ULONG dummyRetLen{};

	if (_NtQueryObject(handle, ObjectBasicInformation, static_cast<PVOID>(&obi[0]), static_cast<ULONG>(sizeof(obi)), &dummyRetLen) != STATUS_SUCCESS)
	{
		return 0;
	}

	return obi[0].GrantedAccess;
}


Process::ProcessInformationA ExtProcessA::getProcess(const std::string& procName) noexcept
{
	Process::ProcessInformationA result{};

	if (procName.empty())
		return result;

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	std::wstring searchProcName{ procName.begin(), procName.end() };

	do
	{
		if (pSPI->ImageName.Length <= 0 ||
			pSPI->ImageName.MaximumLength <= 0 ||
			pSPI->ImageName.Length > 256 ||
			pSPI->ImageName.MaximumLength > 256)
		{
			nextEntryOffset = pSPI->NextEntryOffset;
			pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

			continue;
		}

		if (!_wcsicmp(searchProcName.c_str(), pSPI->ImageName.Buffer))
		{
			result.procID = reinterpret_cast<DWORD>(pSPI->UniqueProcessId);
			result.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			result.threadBasePriority = pSPI->BasePriority;
			result.threadCount = pSPI->NumberOfThreads;
			std::wstring realProcName{ pSPI->ImageName.Buffer };
			result.procName = std::string{ realProcName.begin(), realProcName.end() };

			const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, result.procID) };

			if (validProcessHandle(hProc))
			{
				BOOL wow64Process{ FALSE };
				if (IsWow64Process(hProc, &wow64Process))
					result.wow64Process = static_cast<bool>(wow64Process);

				CloseHandle(hProc);
			}

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return result;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}

Process::ProcessInformationA ExtProcessA::getProcess(const DWORD procID) noexcept
{
	Process::ProcessInformationA result{};

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	do
	{
		if (reinterpret_cast<uintptr_t>(pSPI->UniqueProcessId) == static_cast<uintptr_t>(procID))
		{
			result.procID = procID;
			result.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			result.threadBasePriority = pSPI->BasePriority;
			result.threadCount = pSPI->NumberOfThreads;

			const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, result.procID) };

			if (validProcessHandle(hProc))
			{
				BOOL wow64Process{ FALSE };
				if (IsWow64Process(hProc, &wow64Process))
					result.wow64Process = static_cast<bool>(wow64Process);

				CloseHandle(hProc);
			}

			if (pSPI->ImageName.Length <= 0 ||
				pSPI->ImageName.MaximumLength <= 0 ||
				pSPI->ImageName.Length > 256 ||
				pSPI->ImageName.MaximumLength > 256)
			{
				VirtualFree(pBuffer, 0, MEM_RELEASE);
				return result;
			}

			std::wstring nameBuffer{ pSPI->ImageName.Buffer };
			result.procName = std::string{ nameBuffer.begin(), nameBuffer.end() };

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return result;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}

Process::ProcessInformationA ExtProcessA::getProcess(const HANDLE hProc) noexcept
{
	return getProcess(GetProcessId(hProc));
}

std::vector<Process::ProcessInformationA> ExtProcessA::getProcessList() noexcept
{
	std::vector<Process::ProcessInformationA> result{};

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessA::getInstance().getNativeProcAddress("NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	result.reserve(200);

	do
	{
		Process::ProcessInformationA currentProc{};

		currentProc.procID = reinterpret_cast<DWORD>(pSPI->UniqueProcessId);
		currentProc.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
		currentProc.threadBasePriority = pSPI->BasePriority;
		currentProc.threadCount = pSPI->NumberOfThreads;

		const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentProc.procID) };

		if (validProcessHandle(hProc))
		{
			BOOL wow64Process{ FALSE };
			if (IsWow64Process(hProc, &wow64Process))
				currentProc.wow64Process = static_cast<bool>(wow64Process);

			CloseHandle(hProc);
		}

		if (pSPI->ImageName.Length <= 0 ||
			pSPI->ImageName.MaximumLength <= 0 ||
			pSPI->ImageName.Length > 256 ||
			pSPI->ImageName.MaximumLength > 256)
		{
			nextEntryOffset = pSPI->NextEntryOffset;
			pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

			if (validProcess(currentProc) || !result.size())
				result.push_back(currentProc);

			continue;
		}

		std::wstring nameBuffer{ pSPI->ImageName.Buffer };
		currentProc.procName = std::string{ nameBuffer.begin(), nameBuffer.end() };

		if (validProcess(currentProc) || !result.size())
			result.push_back(currentProc);

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}


BOOL ExtProcessA::RPM(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept
{
	if (!pBuffer || !size || !readAddr)
		return FALSE;

#ifdef _WIN64
	return ReadProcessMemory(m_hProc, reinterpret_cast<void*>(readAddr), pBuffer, size, reinterpret_cast<SIZE_T*>(pBytesRead));
#else
	return RPM_Wow64(readAddr, pBuffer, size, pBytesRead);
#endif
}

BOOL ExtProcessA::WPM(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept
{
	if (!pBuffer || !size || !writeAddr)
		return FALSE;

#ifdef _WIN64
	return WriteProcessMemory(m_hProc, reinterpret_cast<void*>(writeAddr), pBuffer, size, reinterpret_cast<SIZE_T*>(pBytesWritten));
#else
	return WPM_Wow64(writeAddr, pBuffer, size, pBytesWritten);
#endif
}


QWORD ExtProcessA::AVM(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept
{
	if (!size)
		return 0;

#ifdef _WIN64
	return reinterpret_cast<QWORD>(VirtualAllocEx(m_hProc, reinterpret_cast<LPVOID>(allocAddr), size, allocType, protectionFlags));
#else
	return AVM_Wow64(allocAddr, size, allocType, protectionFlags);
#endif
}

BOOL ExtProcessA::FVM(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept
{
	if (!freeAddr)
		return FALSE;

	if (!size && !(freeType & MEM_RELEASE))
		return FALSE;

#ifdef _WIN64
	return VirtualFreeEx(m_hProc, reinterpret_cast<LPVOID>(freeAddr), size, freeType);
#else
	return FVM_Wow64(freeAddr, size, freeType);
#endif
}


BOOL ExtProcessA::PVM(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept
{
	if (!protectLength || !protectAddr)
		return FALSE;

#ifdef _WIN64
	return VirtualProtectEx(m_hProc, reinterpret_cast<void*>(protectAddr), protectLength, protectFlags, pOldProtect);
#else
	return PVM_Wow64(protectAddr, protectLength, protectFlags, pOldProtect);
#endif
}

SIZE_T ExtProcessA::QVM(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept
{
	if (!baseAddr || !pMBI)
		return 0;

#ifdef _WIN64
	return VirtualQueryEx(m_hProc, reinterpret_cast<void*>(baseAddr), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(pMBI), sizeof(MEMORY_BASIC_INFORMATION64));
#else
	return QVM_Wow64(baseAddr, static_cast<MEMORY_BASIC_INFORMATION64* const>(pMBI));
#endif
}


BOOL ExtProcessA::QIP(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept
{
	if (!pProcessInfo || !size)
		return FALSE;

	static tNtQueryInformationProcess _NtQIP{ reinterpret_cast<tNtQueryInformationProcess>(LocalProcessA::getInstance().getNativeProcAddress( "NtQueryInformationProcess")) };

	if (!_NtQIP)
	{
		_NtQIP = reinterpret_cast<tNtQueryInformationProcess>(LocalProcessA::getInstance().getNativeProcAddress( "NtQueryInformationProcess"));

		return FALSE;
	}

	return static_cast<BOOL>(_NtQIP(m_hProc, processInfoClass, pProcessInfo, size, reinterpret_cast<PULONG>(pReturnLength)) == STATUS_SUCCESS);
}


#ifndef _WIN64
BOOL ExtProcessA::QIP_Wow64(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept
{
	if (!pProcessInfo || !size)
		return FALSE;

	static tNtWow64QueryInformationProcess64 _NtWow64QIP{ reinterpret_cast<tNtWow64QueryInformationProcess64>(LocalProcessA::getInstance().getNativeProcAddress("NtWow64QueryInformationProcess64")) };

	if (!_NtWow64QIP)
	{
		_NtWow64QIP = reinterpret_cast<tNtWow64QueryInformationProcess64>(LocalProcessA::getInstance().getNativeProcAddress("NtWow64QueryInformationProcess64"));

		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64QIP(m_hProc, processInfoClass, pProcessInfo, size, reinterpret_cast<PULONG>(pReturnLength)) == STATUS_SUCCESS);
}
#endif


bool ExtProcessW::updateModuleInfo_x86() noexcept
{
	if (!m_processInfo.wow64Process)
		return false;

	const QWORD peb32Addr{ getPEBAddress_x86() };

	if (!peb32Addr)
		return false;

	PEB32 peb32{};

	if (!RPM(static_cast<QWORD>(peb32Addr), static_cast<void*>(&peb32), sizeof(peb32), nullptr))
		return false;

	PEB_LDR_DATA32 loaderData{};

	if (!RPM(static_cast<QWORD>(peb32.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return false;

	DWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const DWORD startAddressIterator{ currEntryAddr };

	std::vector<Process::ModuleInformationW> newModuleList{};

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY32 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY32>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == startAddressIterator)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			Process::ModuleInformationW currentModule{};

			currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	m_x86Modules = newModuleList;

	return true;
}

bool ExtProcessW::updateModuleInfo_x64() noexcept
{
	const QWORD peb64Addr{ getPEBAddress_x64() };

	if (!peb64Addr)
		return false;

	PEB64 peb64{};

	if (!RPM(static_cast<QWORD>(peb64Addr), static_cast<void*>(&peb64), sizeof(peb64), nullptr))
		return false;

	PEB_LDR_DATA64 loaderData{};

	if (!RPM(static_cast<QWORD>(peb64.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return false;

	QWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const QWORD startAddressIterator{ currEntryAddr };

	std::vector<Process::ModuleInformationW> newModuleList{};

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY64>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == startAddressIterator)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			Process::ModuleInformationW currentModule{};

			currentModule.modBA.x64Addr = currentLoaderEntry.DllBase;
			currentModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	m_x64Modules = newModuleList;

	return true;
}


#ifndef _WIN64
BOOL ExtProcessW::RPM_Wow64(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept
{
	if (!pBuffer || !size || !readAddr)
		return FALSE;

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64RVM(m_hProc, readAddr, pBuffer, size, pBytesRead) == STATUS_SUCCESS);
}

BOOL ExtProcessW::WPM_Wow64(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept
{
	if (!pBuffer || !size || !writeAddr)
		return FALSE;

	static tNtWow64WriteVirtualMemory64 _NtWow64WVM{ reinterpret_cast<tNtWow64WriteVirtualMemory64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64WriteVirtualMemory64")) };

	if (!_NtWow64WVM)
	{
		_NtWow64WVM = reinterpret_cast<tNtWow64WriteVirtualMemory64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64WriteVirtualMemory64"));
		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64WVM(m_hProc, writeAddr, pBuffer, size, pBytesWritten) == STATUS_SUCCESS);
}


QWORD ExtProcessW::AVM_Wow64(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept
{
	if (!size)
		return 0;

	static QWORD _NtWow64AVM{ LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtAllocateVirtualMemory") };

	if (!_NtWow64AVM)
	{
		_NtWow64AVM = LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtAllocateVirtualMemory");
		return 0;
	}

	QWORD resultAllocAddr{ allocAddr };
	QWORD resultSize{ size };

	if (!LocalProcessW::getInstance().callNativeFunction(_NtWow64AVM, 6, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultAllocAddr), static_cast<QWORD>(0), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(allocType), static_cast<QWORD>(protectionFlags)))
	{
		return 0;
	}

	return resultAllocAddr;
}

BOOL ExtProcessW::FVM_Wow64(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept
{
	if (!freeAddr)
		return FALSE;

	if (!size && !(freeType & MEM_RELEASE))
		return FALSE;

	static QWORD _NtWow64FVM{ LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtFreeVirtualMemory") };

	if (!_NtWow64FVM)
	{
		_NtWow64FVM = LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtFreeVirtualMemory");
		return FALSE;
	}

	QWORD resultFreeAddr{ freeAddr };
	QWORD resultSize{ (freeType & MEM_RELEASE) ? 0 : size };

	return LocalProcessW::getInstance().callNativeFunction(_NtWow64FVM, 4, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultFreeAddr), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(freeType));
}


BOOL ExtProcessW::PVM_Wow64(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept
{
	if (!protectAddr || !protectLength || !pOldProtect)
		return FALSE;

	static QWORD _NtWow64PVM{ LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtProtectVirtualMemory");
		return FALSE;
	}

	QWORD resultProtectAddr{ protectAddr };
	QWORD resultSize{ protectLength };

	return LocalProcessW::getInstance().callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&resultProtectAddr), reinterpret_cast<QWORD>(&resultSize), static_cast<QWORD>(protectFlags), reinterpret_cast<QWORD>(pOldProtect));
}

SIZE_T ExtProcessW::QVM_Wow64(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept
{
	if (!baseAddr || !pMBI)
		return 0;

	static QWORD _NtWow64QVM{ LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = LocalProcessW::getInstance().getNativeProcAddressWow64(L"NtQueryVirtualMemory");
		return 0;
	}

	QWORD returnLength{};

	if (!LocalProcessW::getInstance().callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), baseAddr, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(pMBI), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
	{
		return 0;
	}

	return returnLength;
}
#endif


ExtProcessW::ExtProcessW() noexcept
{
}

ExtProcessW::ExtProcessW(const std::wstring& procName, const DWORD handleFlags) noexcept
	: IProcessW{ { 0, 0, procName, 0, 0, false }, INVALID_HANDLE_VALUE }
	, m_handleFlags{ handleFlags }
	, m_closeHandleOnDetach{ true }
	, m_reattachByName{ true }
{
	m_attached = attach(procName);
}

ExtProcessW::ExtProcessW(const DWORD procID, const DWORD handleFlags) noexcept
	: IProcessW{ { procID, 0, std::wstring{}, 0, 0, false }, INVALID_HANDLE_VALUE }
	, m_handleFlags{ handleFlags }
	, m_closeHandleOnDetach{ true }
	, m_reattachByName{ false }
{
	m_attached = attach(procID);
}

ExtProcessW::ExtProcessW(const HANDLE duplicatedHandle, bool reattachByName, bool closeHandleOnDetach) noexcept
	: IProcessW{ duplicatedHandle }
	, m_handleFlags{}
	, m_closeHandleOnDetach{ closeHandleOnDetach }
	, m_reattachByName{ reattachByName }
{
	m_attached = attach(duplicatedHandle, reattachByName, closeHandleOnDetach);
}

ExtProcessW::~ExtProcessW()
{
	if (m_attached)
		detach();
}


bool ExtProcessW::attach(const std::wstring& procName) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationW{};
	m_processInfo.procName = procName;
	m_hProc = INVALID_HANDLE_VALUE;

	m_closeHandleOnDetach = true;
	m_reattachByName = true;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessW::attach(const DWORD procID) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationW{};
	m_processInfo.procID = procID;
	m_hProc = INVALID_HANDLE_VALUE;

	m_closeHandleOnDetach = true;
	m_reattachByName = false;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessW::attach(const HANDLE hProc, bool reattachByName, bool closeHandleOnDetach) noexcept
{
	if (m_attached)
		return false;

	m_processInfo = Process::ProcessInformationW{};
	m_hProc = hProc;

	m_closeHandleOnDetach = closeHandleOnDetach;
	m_reattachByName = reattachByName;

	m_attached = reattach();
	return m_attached;
}

bool ExtProcessW::detach() noexcept
{
	if (!m_attached)
		return false;

	Process::ProcessInformationW newProcessInfo{};

	if (m_reattachByName)
		newProcessInfo.procName = m_processInfo.procName;
	else
		newProcessInfo.procID = m_processInfo.procID;

	m_processInfo = newProcessInfo;

	if (!m_handleFlags)
		m_handleFlags = PROCESS_ALL_ACCESS;

	if (m_closeHandleOnDetach && validProcessHandle(m_hProc))
		CloseHandle(m_hProc);

	m_hProc = INVALID_HANDLE_VALUE;
	m_closeHandleOnDetach = true;

	m_attached = false;

	return true;
}

bool ExtProcessW::reattach() noexcept
{
	if (m_attached)
		detach();

	m_x86Modules.clear();
	m_x64Modules.clear();

	m_x86Modules.reserve(20);
	m_x64Modules.reserve(20);

	if (!m_processInfo.procID && m_processInfo.procName.empty())
	{
		if (!validProcessHandle(m_hProc))
			return false;

		m_handleFlags = getHandleFlags(m_hProc);
	}
	else
	{
		HANDLE hProc{ INVALID_HANDLE_VALUE };

		if (m_processInfo.procID)
		{
			hProc = OpenProcess(m_handleFlags, FALSE, m_processInfo.procID);
		}
		else
		{
			const DWORD procID{ getProcess(m_processInfo.procName).procID };

			if (!procID)
				return false;

			hProc = OpenProcess(m_handleFlags, FALSE, procID);
		}

		if (!validHandle(hProc))
			return false;

		m_hProc = hProc;
	}

	const Process::ProcessInformationW oldProcInfo{ m_processInfo };

	m_processInfo = getProcess(m_hProc);

	if (m_processInfo.procID && !m_processInfo.procName.empty())
	{
		m_attached = true;
		updateModuleInfo();
	}
	else
	{
		m_attached = false;
		m_processInfo = oldProcInfo;
	}

	return m_attached;
}


bool ExtProcessW::updateProcessInfo() noexcept
{
	const Process::ProcessInformationW newProcInfo{ getProcess(m_hProc) };

	if (validProcess(newProcInfo) && !newProcInfo.procName.empty())
	{
		m_processInfo.parentProcID = newProcInfo.parentProcID;
		m_processInfo.threadBasePriority = newProcInfo.threadBasePriority;
		m_processInfo.threadCount = newProcInfo.threadCount;

		return true;
	}

	return false;
}

bool ExtProcessW::updateModuleInfo() noexcept
{
	bool status{ updateModuleInfo_x64() };

	if (m_processInfo.wow64Process)
	{
		status = updateModuleInfo_x86() && status;
	}

	return status;
}


QWORD ExtProcessW::getPEBAddress_x86() const noexcept
{
	if (!m_processInfo.wow64Process)
		return 0;

#ifdef _WIN64

	ULONG_PTR peb32Addr{};

	return (QIP(ProcessWow64Information, &peb32Addr, sizeof(peb32Addr), nullptr) ? static_cast<QWORD>(peb32Addr) : 0);

#else

	PROCESS_BASIC_INFORMATION pbi{};

	return (QIP(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? reinterpret_cast<QWORD>(pbi.PebBaseAddress) : 0);

#endif
}

QWORD ExtProcessW::getPEBAddress_x64() const noexcept
{
	PROCESS_BASIC_INFORMATION64 pbi{};

#ifdef _WIN64
	return (QIP(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? pbi.PEB_BaseAddress : 0);
#else
	return (QIP_Wow64(ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) ? pbi.PEB_BaseAddress : 0);
#endif
}


Process::ModuleInformationW ExtProcessW::getModuleInfo_x86(const std::wstring& modName) const noexcept
{
	if (!m_processInfo.wow64Process)
		return Process::ModuleInformationW{};

	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationW newModule{};

	const QWORD peb32Addr{ getPEBAddress_x86() };

	if (!peb32Addr)
		return newModule;

	PEB32 peb32{};

	if (!RPM(static_cast<QWORD>(peb32Addr), static_cast<void*>(&peb32), sizeof(peb32), nullptr))
		return newModule;

	PEB_LDR_DATA32 loaderData{};

	if (!RPM(static_cast<QWORD>(peb32.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return newModule;

	DWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const DWORD startAddressIterator{ currEntryAddr };

	while (currEntryAddr)
	{
		const LDR_DATA_TABLE_ENTRY32 currentLoaderEntry{ RPM<LDR_DATA_TABLE_ENTRY32>(currEntryAddr) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			return newModule;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(static_cast<QWORD>(currentLoaderEntry.BaseDllName.WideStringAddress), pModuleName, static_cast<QWORD>(moduleStringLength), nullptr);

			if (!_wcsicmp(modName.c_str(), reinterpret_cast<wchar_t*>(pModuleName)))
			{
				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				delete[] pModuleName;
				pModuleName = nullptr;

				break;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	return newModule;
}

Process::ModuleInformationW ExtProcessW::getModuleInfo_x64(const std::wstring& modName) const noexcept
{
	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationW newModule{};

	const QWORD peb64Addr{ getPEBAddress_x64() };

	if (!peb64Addr)
		return newModule;

	PEB64 peb64{};

	if (!RPM(static_cast<QWORD>(peb64Addr), static_cast<void*>(&peb64), sizeof(peb64), nullptr))
		return newModule;

	PEB_LDR_DATA64 loaderData{};

	if (!RPM(static_cast<QWORD>(peb64.Ldr), static_cast<void*>(&loaderData), sizeof(loaderData), nullptr))
		return newModule;

	QWORD currEntryAddr{ loaderData.InLoadOrderModuleList.Flink };
	const QWORD startAddressIterator{ currEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (!RPM(currEntryAddr, static_cast<void*>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr))
			return newModule;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			return newModule;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			char* pModuleName{ nullptr };

			DWORD moduleStringLength{ currentLoaderEntry.BaseDllName.Length + 2u };

			while (!pModuleName)
				pModuleName = new char[moduleStringLength];

			memset(pModuleName, 0, moduleStringLength);

			RPM(currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr);

			if (!_wcsicmp(modName.c_str(), reinterpret_cast<wchar_t*>(pModuleName)))
			{
				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				delete[] pModuleName;
				pModuleName = nullptr;

				break;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == startAddressIterator)
			break;
	}

	return newModule;
}


QWORD ExtProcessW::getProcAddress_x86(const QWORD modBA, const std::wstring& functionName) const noexcept
{
	if (modBA > static_cast<QWORD>(0xFFFFFFFF))
		return 0;

	QWORD procAddress{};

	const IMAGE_DOS_HEADER dosHeader{ RPM<IMAGE_DOS_HEADER>(static_cast<uintptr_t>(modBA)) };

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS32 ntHeader{ RPM<IMAGE_NT_HEADERS32>(modBA + dosHeader.e_lfanew) };

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x10B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY exportDirectory{ RPM<IMAGE_EXPORT_DIRECTORY>(modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	if (!RPM(exportTableAddr, exportTable.data(), static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)), nullptr) ||
		!RPM(ordinalsAddr, ordinalTable.data(), static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)), nullptr) ||
		!RPM(namesAddr, nameTable.data(), static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)), nullptr))
	{
		return 0;
	}

	char nameBuffer[128]{};

	std::string aFuncName{ functionName.begin(), functionName.end() };

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		if (!RPM(modBA + nameTable.at(iterator), nameBuffer, sizeof(nameBuffer), nullptr))
		{
			continue;
		}
		else
		{
			std::string strTableEntry{ &nameBuffer[0] };

			if (!_stricmp(strTableEntry.c_str(), aFuncName.c_str()))
			{
				const WORD ordinal{ ordinalTable.at(iterator) };
				procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

				if (procAddress > static_cast<QWORD>(0xFFFFFFFF))
					return 0;

				break;
			}
		}
	}

	return procAddress;
}

QWORD ExtProcessW::getProcAddress_x64(const QWORD modBA, const std::wstring& functionName) const noexcept
{
	QWORD procAddress{};

	const IMAGE_DOS_HEADER dosHeader{ RPM<IMAGE_DOS_HEADER>(modBA) };

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS64 ntHeader{ RPM<IMAGE_NT_HEADERS64>(modBA + dosHeader.e_lfanew) };

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x20B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY exportDirectory{ RPM<IMAGE_EXPORT_DIRECTORY>(modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	if (!RPM(exportTableAddr, exportTable.data(), static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)), nullptr) ||
		!RPM(ordinalsAddr, ordinalTable.data(), static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)), nullptr) ||
		!RPM(namesAddr, nameTable.data(), static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)), nullptr))
	{
		return 0;
	}

	char nameBuffer[128]{};

	std::string aFuncName{ functionName.begin(), functionName.end() };

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		if (!RPM(modBA + nameTable.at(iterator), nameBuffer, sizeof(nameBuffer), nullptr))
		{
			continue;
		}
		else
		{
			std::string strTableEntry{ &nameBuffer[0] };

			if (!_stricmp(strTableEntry.c_str(), aFuncName.c_str()))
			{
				const WORD ordinal{ ordinalTable.at(iterator) };
				procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

				break;
			}
		}
	}

	return procAddress;
}


QWORD ExtProcessW::getProcAddress_x86(const std::wstring modName, const std::wstring& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD ExtProcessW::getProcAddress_x64(const std::wstring modName, const std::wstring& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getProcAddress_x64(modBA, functionName) : 0;
}


Process::ModuleInformationW ExtProcessW::getModuleInfo_x86(const std::wstring& modName) noexcept
{
	if (!m_processInfo.wow64Process)
		return Process::ModuleInformationW{};

	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationW modInfo{ const_cast<const ExtProcessW* const>(this)->getModuleInfo_x86(modName) };

	if (validModule(modInfo))
		m_x86Modules.push_back(modInfo);

	return modInfo;
}

Process::ModuleInformationW ExtProcessW::getModuleInfo_x64(const std::wstring& modName) noexcept
{
	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationW modInfo{ const_cast<const ExtProcessW* const>(this)->getModuleInfo_x64(modName) };

	if (validModule(modInfo))
		m_x64Modules.push_back(modInfo);

	return modInfo;
}


QWORD ExtProcessW::scanPattern(const Process::SignatureW& signature) const noexcept
{
	QWORD result{};

	if (m_processInfo.wow64Process)
	{
		for (const Process::ModuleInformationW& currModule : m_x86Modules)
		{
			if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x86({ signature, currModule.modName })))
			{
				return result;
			}
		}
	}

	for (const Process::ModuleInformationW& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x64({ signature, currModule.modName })))
		{
			return result;
		}
	}

	return result;
}

QWORD ExtProcessW::scanPattern_x86(const Process::ModuleSignatureW& signature) const noexcept
{
	if (!m_processInfo.wow64Process)
		return 0;

	if (!signature.pattern.size())
		return 0;

	//bool found{ false };

	//QWORD result{ getPatternAddress_x86(signature, found) };

	const std::vector<Process::FoundGadgetW> foundPatterns{ findGadgets_x86(signature) };

	QWORD result{ (foundPatterns.size()) ? foundPatterns.front().absoluteAddress : 0 };

	if (!result)
		return 0;

	//if (!found)
		//return 0;

	for (const DWORD currOffset : signature.offsets)
	{
		result = static_cast<QWORD>(RPM<DWORD>(result + currOffset));
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x86(signature.moduleName);

	return result;
}

QWORD ExtProcessW::scanPattern_x64(const Process::ModuleSignatureW& signature) const noexcept
{
	if (!signature.pattern.size())
		return 0;

	//bool found{ false };

	//QWORD result{ getPatternAddress_x64(signature, found) };

	const std::vector<Process::FoundGadgetW> foundPatterns{ findGadgets_x64(signature) };

	QWORD result{ (foundPatterns.size()) ? foundPatterns.front().absoluteAddress : 0 };

	if (!result)
		return 0;

	//if (!found)
		//return 0;

	for (const DWORD currOffset : signature.offsets)
	{
		result = RPM<QWORD>(result + currOffset);
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
}


int ExtProcessW::patternCount(const Process::SignatureW& signature) const noexcept
{
	return findGadgets(signature).size();
}

int ExtProcessW::patternCount_x86(const Process::ModuleSignatureW& signature) const noexcept
{
	return findGadgets_x86(signature).size();
}

int ExtProcessW::patternCount_x64(const Process::ModuleSignatureW& signature) const noexcept
{
	return findGadgets_x64(signature).size();
}


std::vector<Process::FoundGadgetW> ExtProcessW::findGadgets(const Process::SignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

	if (m_processInfo.wow64Process)
	{
		for (const Process::ModuleInformationW& currModule : m_x86Modules)
		{
			if (validModule(currModule) && !currModule.modName.empty())
			{
				std::vector<Process::FoundGadgetW> moduleGadgets{ findGadgets_x86({signature, currModule.modName }) };

				if (moduleGadgets.size())
					result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
			}
		}
	}

	for (const Process::ModuleInformationW& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty())
		{
			std::vector<Process::FoundGadgetW> moduleGadgets{ findGadgets_x64({signature, currModule.modName }) };

			if (moduleGadgets.size())
				result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
		}
	}

	return result;
}

std::vector<Process::FoundGadgetW> ExtProcessW::findGadgets_x86(const Process::ModuleSignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

	if (m_processInfo.wow64Process)
		return result;

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!QVM(static_cast<QWORD>(currAddress), &mbi))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				continue;
			}

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetW currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
					currGadget.readable = signature.readable;
					currGadget.writable = signature.writable;
					currGadget.pattern = pattern;
					currGadget.moduleName = modInfo.modName;

					currGadget.bytes.clear();
					currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

					result.push_back(currGadget);
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
		else
		{
			DWORD oldProtect{};

			if (PVM(currAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
				{
					PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
						currGadget.readable = signature.readable;
						currGadget.writable = signature.writable;
						currGadget.pattern = pattern;
						currGadget.moduleName = modInfo.modName;

						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						result.push_back(currGadget);
					}
				}

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
			}
		}
	}

	return result;
}

std::vector<Process::FoundGadgetW> ExtProcessW::findGadgets_x64(const Process::ModuleSignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!QVM(currAddress, &mbi))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				continue;
			}

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetW currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
					currGadget.readable = signature.readable;
					currGadget.writable = signature.writable;
					currGadget.pattern = pattern;
					currGadget.moduleName = modInfo.modName;

					currGadget.bytes.clear();
					currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

					result.push_back(currGadget);
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
		else
		{
			DWORD oldProtect{};

			if (PVM(currAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				if (!RPM(currAddress, pScanBuffer, mbi.RegionSize, nullptr))
				{
					PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				PVM(currAddress, mbi.RegionSize, oldProtect, &oldProtect);

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = currGadget.absoluteAddress - modInfo.modBA.x64Addr;
						currGadget.readable = signature.readable;
						currGadget.writable = signature.writable;
						currGadget.pattern = pattern;
						currGadget.moduleName = modInfo.modName;

						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						result.push_back(currGadget);
					}
				}

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
			}
		}
	}

	return result;
}


bool ExtProcessW::validProcessHandle(const HANDLE handle) noexcept
{
	if (!validHandle(handle))
		return false;

	static tNtQueryObject _NtQueryObject{ reinterpret_cast<tNtQueryObject>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryObject")) };

	if (!_NtQueryObject)
	{
		_NtQueryObject = reinterpret_cast<tNtQueryObject>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryObject"));

		return false;
	}

	OBJECT_TYPE_INFORMATION oti[2]{};	//Allocate 2 of these structures to deal with potential buffer overrun
	ULONG dummyRetLen{};

	if (_NtQueryObject(handle, ObjectTypeInformation, static_cast<PVOID>(&oti[0]), static_cast<ULONG>(sizeof(oti)), &dummyRetLen) != STATUS_SUCCESS)
	{
		return false;
	}

	if (oti[0].TypeIndex == static_cast<UCHAR>(0x7))
		return true;
	else
		return false;
}

DWORD ExtProcessW::getHandleFlags(const HANDLE handle) noexcept
{
	static tNtQueryObject _NtQueryObject{ reinterpret_cast<tNtQueryObject>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryObject")) };

	if (!_NtQueryObject)
	{
		_NtQueryObject = reinterpret_cast<tNtQueryObject>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryObject"));

		return 0;
	}

	OBJECT_BASIC_INFORMATION obi[1]{};
	ULONG dummyRetLen{};

	if (_NtQueryObject(handle, ObjectBasicInformation, static_cast<PVOID>(&obi[0]), static_cast<ULONG>(sizeof(obi)), &dummyRetLen) != STATUS_SUCCESS)
	{
		return 0;
	}

	return obi[0].GrantedAccess;
}


Process::ProcessInformationW ExtProcessW::getProcess(const std::wstring& procName) noexcept
{
	Process::ProcessInformationW result{};

	if (procName.empty())
		return result;

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	do
	{
		if (pSPI->ImageName.Length <= 0 ||
			pSPI->ImageName.MaximumLength <= 0 ||
			pSPI->ImageName.Length > 256 ||
			pSPI->ImageName.MaximumLength > 256)
		{
			nextEntryOffset = pSPI->NextEntryOffset;
			pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

			continue;
		}

		if (!_wcsicmp(procName.c_str(), pSPI->ImageName.Buffer))
		{
			result.procID = reinterpret_cast<DWORD>(pSPI->UniqueProcessId);
			result.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			result.threadBasePriority = pSPI->BasePriority;
			result.threadCount = pSPI->NumberOfThreads;
			result.procName = std::wstring{ pSPI->ImageName.Buffer };

			const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, result.procID) };

			if (validProcessHandle(hProc))
			{
				BOOL wow64Process{ FALSE };
				if (IsWow64Process(hProc, &wow64Process))
					result.wow64Process = static_cast<bool>(wow64Process);

				CloseHandle(hProc);
			}

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return result;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}

Process::ProcessInformationW ExtProcessW::getProcess(const DWORD procID) noexcept
{
	Process::ProcessInformationW result{};

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	do
	{
		if (reinterpret_cast<uintptr_t>(pSPI->UniqueProcessId) == static_cast<uintptr_t>(procID))
		{
			result.procID = procID;
			result.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			result.threadBasePriority = pSPI->BasePriority;
			result.threadCount = pSPI->NumberOfThreads;

			const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, result.procID) };

			if (validProcessHandle(hProc))
			{
				BOOL wow64Process{ FALSE };
				if (IsWow64Process(hProc, &wow64Process))
					result.wow64Process = static_cast<bool>(wow64Process);

				CloseHandle(hProc);
			}

			if (pSPI->ImageName.Length <= 0 ||
				pSPI->ImageName.MaximumLength <= 0 ||
				pSPI->ImageName.Length > 256 ||
				pSPI->ImageName.MaximumLength > 256)
			{
				VirtualFree(pBuffer, 0, MEM_RELEASE);
				return result;
			}

			result.procName = std::wstring{ pSPI->ImageName.Buffer };

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return result;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}

Process::ProcessInformationW ExtProcessW::getProcess(const HANDLE hProc) noexcept
{
	return getProcess(GetProcessId(hProc));
}

std::vector<Process::ProcessInformationW> ExtProcessW::getProcessList() noexcept
{
	std::vector<Process::ProcessInformationW> result{};

	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQuerySystemInformation"));

		return result;
	}

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return result;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return result;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return result;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	result.reserve(200);

	do
	{
		Process::ProcessInformationW currentProc{};

		currentProc.procID = reinterpret_cast<DWORD>(pSPI->UniqueProcessId);
		currentProc.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
		currentProc.threadBasePriority = pSPI->BasePriority;
		currentProc.threadCount = pSPI->NumberOfThreads;

		const HANDLE hProc{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentProc.procID) };

		if (validProcessHandle(hProc))
		{
			BOOL wow64Process{ FALSE };
			if (IsWow64Process(hProc, &wow64Process))
				currentProc.wow64Process = static_cast<bool>(wow64Process);

			CloseHandle(hProc);
		}

		if (pSPI->ImageName.Length <= 0 ||
			pSPI->ImageName.MaximumLength <= 0 ||
			pSPI->ImageName.Length > 256 ||
			pSPI->ImageName.MaximumLength > 256)
		{
			nextEntryOffset = pSPI->NextEntryOffset;
			pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

			if (validProcess(currentProc) || !result.size())
				result.push_back(currentProc);

			continue;
		}
		
		currentProc.procName = std::wstring{ pSPI->ImageName.Buffer };

		if (validProcess(currentProc) || !result.size())
			result.push_back(currentProc);

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return result;
}


BOOL ExtProcessW::RPM(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept
{
	if (!pBuffer || !size || !readAddr)
		return FALSE;

#ifdef _WIN64
	return ReadProcessMemory(m_hProc, reinterpret_cast<void*>(readAddr), pBuffer, size, reinterpret_cast<SIZE_T*>(pBytesRead));
#else
	return RPM_Wow64(readAddr, pBuffer, size, pBytesRead);
#endif
}

BOOL ExtProcessW::WPM(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept
{
	if (!pBuffer || !size || !writeAddr)
		return FALSE;

#ifdef _WIN64
	return WriteProcessMemory(m_hProc, reinterpret_cast<void*>(writeAddr), pBuffer, size, reinterpret_cast<SIZE_T*>(pBytesWritten));
#else
	return WPM_Wow64(writeAddr, pBuffer, size, pBytesWritten);
#endif
}


QWORD ExtProcessW::AVM(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept
{
	if (!size)
		return 0;

#ifdef _WIN64
	return reinterpret_cast<QWORD>(VirtualAllocEx(m_hProc, reinterpret_cast<LPVOID>(allocAddr), size, allocType, protectionFlags));
#else
	return AVM_Wow64(allocAddr, size, allocType, protectionFlags);
#endif
}

BOOL ExtProcessW::FVM(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept
{
	if (!freeAddr)
		return FALSE;

	if (!size && !(freeType & MEM_RELEASE))
		return FALSE;

#ifdef _WIN64
	return VirtualFreeEx(m_hProc, reinterpret_cast<LPVOID>(freeAddr), size, freeType);
#else
	return FVM_Wow64(freeAddr, size, freeType);
#endif
}


BOOL ExtProcessW::PVM(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept
{
	if (!protectLength || !protectAddr)
		return FALSE;

#ifdef _WIN64
	return VirtualProtectEx(m_hProc, reinterpret_cast<void*>(protectAddr), protectLength, protectFlags, pOldProtect);
#else
	return PVM_Wow64(protectAddr, protectLength, protectFlags, pOldProtect);
#endif
}

SIZE_T ExtProcessW::QVM(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept
{
	if (!baseAddr || !pMBI)
		return 0;

#ifdef _WIN64
	return VirtualQueryEx(m_hProc, reinterpret_cast<void*>(baseAddr), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(pMBI), sizeof(MEMORY_BASIC_INFORMATION64));
#else
	return QVM_Wow64(baseAddr, static_cast<MEMORY_BASIC_INFORMATION64* const>(pMBI));
#endif
}


BOOL ExtProcessW::QIP(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept
{
	if (!pProcessInfo || !size)
		return FALSE;

	static tNtQueryInformationProcess _NtQIP{ reinterpret_cast<tNtQueryInformationProcess>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryInformationProcess")) };

	if (!_NtQIP)
	{
		_NtQIP = reinterpret_cast<tNtQueryInformationProcess>(LocalProcessW::getInstance().getNativeProcAddress(L"NtQueryInformationProcess"));

		return FALSE;
	}

	return static_cast<BOOL>(_NtQIP(m_hProc, processInfoClass, pProcessInfo, size, reinterpret_cast<PULONG>(pReturnLength)) == STATUS_SUCCESS);
}


#ifndef _WIN64
BOOL ExtProcessW::QIP_Wow64(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept
{
	if (!pProcessInfo || !size)
		return FALSE;

	static tNtWow64QueryInformationProcess64 _NtWow64QIP{ reinterpret_cast<tNtWow64QueryInformationProcess64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64QueryInformationProcess64")) };

	if (!_NtWow64QIP)
	{
		_NtWow64QIP = reinterpret_cast<tNtWow64QueryInformationProcess64>(LocalProcessW::getInstance().getNativeProcAddress(L"NtWow64QueryInformationProcess64"));

		return FALSE;
	}

	return static_cast<BOOL>(_NtWow64QIP(m_hProc, processInfoClass, pProcessInfo, size, reinterpret_cast<PULONG>(pReturnLength)) == STATUS_SUCCESS);
}
#endif