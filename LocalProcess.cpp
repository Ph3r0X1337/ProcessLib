#include "LocalProcess.hpp"
#include <intrin.h>
#include <cstdarg>
#include <thread>

LocalProcessA LocalProcessA::s_instance;
LocalProcessW LocalProcessW::s_instance;


QWORD LocalProcess::generateSwitchToLongMode(const DWORD farJumpAddress32Bit) noexcept
{
	QWORD result{ static_cast<QWORD>(farJumpAddress32Bit) << (1 * 8) };

	result += 0xEA;
	result += static_cast<QWORD>(0x90) << (7 * 8);
	result += static_cast<QWORD>(0x33) << (5 * 8);

	return result;
}


bool LocalProcessA::updateModuleInfo_x86() noexcept
{
#ifdef _WIN64

	return false;

#else

	const QWORD pebAddr{ getPEBAddress_x86() };

	if (!pebAddr)
		return false;

	const LIST_ENTRY* const pFirstEntry{ reinterpret_cast<PEB*>(pebAddr)->Ldr->InLoadOrderModuleList.Flink };
	const LIST_ENTRY* pCurrEntry{ pFirstEntry };

	std::vector<Process::ModuleInformationA> newModuleList{};

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.Buffer)
		{
			const std::wstring moduleName{ currentLoaderEntry.BaseDllName.Buffer };

			Process::ModuleInformationA currentModule{};

			currentModule.modBA.x64Addr = reinterpret_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::string{ moduleName.begin(), moduleName.end() };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);
		}

		pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (pCurrEntry == pFirstEntry)
			break;
	}

	m_x86Modules = newModuleList;

	return true;

#endif
}

bool LocalProcessA::updateModuleInfo_x64() noexcept
{
	const QWORD pebAddr{ getPEBAddress_x64() };

	if (!pebAddr)
		return false;

	std::vector<Process::ModuleInformationA> newModuleList{};

#ifdef _WIN64

	const LIST_ENTRY64* const pFirstEntry{ reinterpret_cast<LIST_ENTRY64*>(reinterpret_cast<PEB_LDR_DATA64*>(reinterpret_cast<PEB64*>(pebAddr)->Ldr)->InLoadOrderModuleList.Flink) };

	const LIST_ENTRY64* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY64*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			const std::wstring moduleName{ reinterpret_cast<wchar_t*>(currentLoaderEntry.BaseDllName.WideStringAddress) };

			Process::ModuleInformationA currentModule{};

			currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::string{ moduleName.begin(), moduleName.end() };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);
		}

		pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

		if (pCurrEntry == pFirstEntry)
			break;
	}

#else

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return false;
	}

	PEB_LDR_DATA64 ldrData{};

	if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		return false;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			return false;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == firstEntryAddr)
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

			if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			{
				const std::wstring moduleName{ reinterpret_cast<wchar_t*>(pModuleName) };
				const std::string currModName{ moduleName.begin(), moduleName.end() };

				Process::ModuleInformationA currentModule{};

				currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				currentModule.modName = currModName;
				currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				currentModule.procID = m_processInfo.procID;
				currentModule.procName = m_processInfo.procName;

				newModuleList.push_back(currentModule);
			}
			else
			{
				delete[] pModuleName;
				pModuleName = nullptr;
				return false;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == firstEntryAddr)
			break;
	}

#endif

	m_x64Modules = newModuleList;

	return true;
}

/*
QWORD LocalProcessA::getPatternAddress_x86(const Process::ModuleSignatureA& signature, bool& patternFound) const noexcept
{
	patternFound = false;

#ifdef _WIN64

	return 0;

#else

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return 0;

	QWORD result{};

	MEMORY_BASIC_INFORMATION mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			break;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			break;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			break;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			break;

		if (signature.readable)
		{
			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer);
				break;
			}
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer);
					break;
				}
			}
		}
	}

	return result;

#endif
}

QWORD LocalProcessA::getPatternAddress_x64(const Process::ModuleSignatureA& signature, bool& patternFound) const noexcept
{
	patternFound = false;

#ifndef _WIN64

	static QWORD _NtWow64QVM{ getNativeProcAddressWow64("NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = getNativeProcAddressWow64("NtQueryVirtualMemory");
		return 0;
	}

	static QWORD _NtWow64PVM{ getNativeProcAddressWow64("NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = getNativeProcAddressWow64("NtProtectVirtualMemory");
		return 0;
	}

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return 0;
	}

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return 0;

	QWORD result{};

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
#ifdef _WIN64

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), reinterpret_cast<MEMORY_BASIC_INFORMATION*>(&mbi), sizeof(mbi)))
			break;

#else

		QWORD returnLength{};

		if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
			break;

#endif

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			break;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			break;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			break;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			break;

#ifdef _WIN64

		if (signature.readable)
		{

			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer);
				break;
			}
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer);
					break;
				}
			}
		}

#else

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
			
		if (!pScanBuffer)
			break;

		if (signature.readable)
		{
			if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				break;
			}

			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer) - reinterpret_cast<QWORD>(pScanBuffer) + currAddress;
				break;
			}
		}
		else
		{
			DWORD oldProtect{};
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				{
					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					break;
				}

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer) - reinterpret_cast<QWORD>(pScanBuffer) + currAddress;
					break;
				}
			}
		}

#endif
	}

	return result;
}
*/


#ifndef _WIN64

void LocalProcessA::initShellcodeMemory() noexcept
{
	if (LocalProcessA::s_instance.m_initState == LocalProcess::InitState::uninitialized)
	{
		LocalProcessA::s_instance.m_initState = LocalProcess::InitState::initializing;
		LocalProcessA::s_instance.m_shellcodeMemory = 0;

		while (!LocalProcessA::s_instance.m_shellcodeMemory)
			LocalProcessA::s_instance.m_shellcodeMemory = reinterpret_cast<DWORD>(VirtualAlloc(nullptr, LocalProcess::shellcode::shellcodeMemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		char* pMemory{ reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory) };

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::getNativeModuleX64SetupCode, sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode));
		*reinterpret_cast<DWORD*>(&pMemory[0x0D]) = reinterpret_cast<DWORD>(pMemory + 0x17);
		*reinterpret_cast<DWORD*>(&pMemory[0x12]) = LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeModule;
		*reinterpret_cast<DWORD*>(&pMemory[0x23]) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode));
		pMemory += sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeModule);
		memcpy(pMemory, LocalProcess::shellcode::getNativeModuleX64Shellcode, sizeof(LocalProcess::shellcode::getNativeModuleX64Shellcode));

		pMemory = reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress);

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::getNativeProcAddressX64SetupCode, sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode));
		*reinterpret_cast<DWORD*>(&pMemory[0x14]) = reinterpret_cast<DWORD>(pMemory + 0x1E);
		*reinterpret_cast<DWORD*>(&pMemory[0x19]) = LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeProcAddress;
		*reinterpret_cast<DWORD*>(&pMemory[0x2A]) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode));
		pMemory += sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeProcAddress);
		memcpy(pMemory, LocalProcess::shellcode::getNativeProcAddressX64Shellcode, sizeof(LocalProcess::shellcode::getNativeProcAddressX64Shellcode));

		pMemory = reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction);

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::callNativeFunctionX64Shellcode, sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode));
		*reinterpret_cast<DWORD*>(pMemory + (sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode) - 10)) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode));
		pMemory += sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessA::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGet64BitPEB);
		memcpy(pMemory, LocalProcess::shellcode::x86_64_readPEBFromReg, sizeof(LocalProcess::shellcode::x86_64_readPEBFromReg));

		DWORD oldProtect{};
		VirtualProtect(reinterpret_cast<LPVOID>(LocalProcessA::s_instance.m_shellcodeMemory), LocalProcess::shellcode::shellcodeMemorySize, PAGE_EXECUTE_READ, &oldProtect);

		LocalProcessA::s_instance.m_initState = LocalProcess::InitState::initialized;
	}
}

void LocalProcessA::deleteShellcodeMemory() noexcept
{
	while (LocalProcessA::s_instance.m_initState == LocalProcess::InitState::initializing)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	if (LocalProcessA::s_instance.m_initState == LocalProcess::InitState::uninitialized)
		return;
	else
	{
		VirtualFree(reinterpret_cast<LPVOID>(LocalProcessA::s_instance.m_shellcodeMemory), 0, MEM_RELEASE);
		LocalProcessA::s_instance.m_shellcodeMemory = 0;
		LocalProcessA::s_instance.m_initState = LocalProcess::InitState::uninitialized;
	}
}

#endif


LocalProcessA::LocalProcessA() noexcept
{
#ifdef _WIN64

	m_processInfo.wow64Process = false;

#else

	m_processInfo.wow64Process = true;
	initShellcodeMemory();

#endif

	BOOL wow64Proc{ FALSE };
	if (IsWow64Process(GetCurrentProcess(), &wow64Proc))
		m_processInfo.wow64Process = static_cast<bool>(wow64Proc);

	while (!validHandle(m_hProc))
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	LocalProcessA::s_instance.updateProcessInfo();
	LocalProcessA::s_instance.updateModuleInfo();

}

LocalProcessA::~LocalProcessA()
{
#ifndef _WIN64

	deleteShellcodeMemory();

#endif

	if (validHandle(m_hProc))
	{
		CloseHandle(m_hProc);
		m_hProc = INVALID_HANDLE_VALUE;
	}
		
}

/*
LocalProcessA& LocalProcessA::getInstance() noexcept
{
#ifndef _WIN64

	while (s_instance.m_initState == LocalProcess::InitState::initializing)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	if (s_instance.m_initState == LocalProcess::InitState::uninitialized)
		initShellcodeMemory();

#endif

	return s_instance;
}
*/

uintptr_t LocalProcessA::getNativeProcAddress(const std::string& functionName) const noexcept
{
	std::map<std::string, uintptr_t>::const_iterator it{ m_nativeFunctions.find(functionName) };

	if (it != m_nativeFunctions.end())
	{
		return (*it).second;
	}
	else
	{
		return static_cast<uintptr_t>(getProcAddress("ntdll.dll", functionName));
	}
}

uintptr_t LocalProcessA::getNativeProcAddress(const std::string& functionName) noexcept
{
	const uintptr_t procAddr{ const_cast<const LocalProcessA* const>(this)->getNativeProcAddress(functionName) };

	if (procAddr)
		m_nativeFunctions[functionName] = procAddr;

	return procAddr;
}


#ifndef _WIN64

QWORD LocalProcessA::getNativeProcAddressWow64(const std::string& functionName) const noexcept
{
	std::map<std::string, QWORD>::const_iterator it{ m_nativeFunctionsWow64.find(functionName) };

	if (it != m_nativeFunctionsWow64.end())
	{
		return (*it).second;
	}
	else
	{
		return getProcAddress_x64("ntdll.dll", functionName);
	}
}

QWORD LocalProcessA::getNativeProcAddressWow64(const std::string& functionName) noexcept
{
	const QWORD procAddr{ const_cast<const LocalProcessA* const>(this)->getNativeProcAddressWow64(functionName) };

	if (procAddr)
		m_nativeFunctionsWow64[functionName] = procAddr;

	return procAddr;
}

#endif


bool LocalProcessA::updateProcessInfo() noexcept
{
	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(getNativeProcAddress("NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(getNativeProcAddress("NtQuerySystemInformation"));

		return false;
	}

	const DWORD currProcID{ GetCurrentProcessId() };

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return false;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return false;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return false;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};
	
	do
	{
		if (reinterpret_cast<uintptr_t>(pSPI->UniqueProcessId) == static_cast<uintptr_t>(currProcID))
		{
			m_processInfo.procID = currProcID;
			m_processInfo.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			m_processInfo.threadBasePriority = pSPI->BasePriority;
			m_processInfo.threadCount = pSPI->NumberOfThreads;

			if (pSPI->ImageName.Length <= 0 ||
				pSPI->ImageName.MaximumLength <= 0 ||
				pSPI->ImageName.Length > 256 ||
				pSPI->ImageName.MaximumLength > 256)
			{
				VirtualFree(pBuffer, 0, MEM_RELEASE);
				return true;
			}

			std::wstring nameBuffer{ pSPI->ImageName.Buffer };
			m_processInfo.procName = std::string{ nameBuffer.begin(), nameBuffer.end() };

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return true;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return false;
}

bool LocalProcessA::updateModuleInfo() noexcept
{
	bool status{ updateModuleInfo_x64() };

	return ((m_processInfo.wow64Process) ? updateModuleInfo_x86() && status : status);
}


QWORD LocalProcessA::getPEBAddress_x86() const noexcept
{
#ifdef _WIN64
	return 0;
#else
	return static_cast<QWORD>(__readfsdword(0x30));
#endif
}

QWORD LocalProcessA::getPEBAddress_x64() const noexcept
{
#ifdef _WIN64
	return static_cast<QWORD>(__readgsqword(0x60));
#else
	return call64BitFunction(static_cast<QWORD>(m_shellcodeMemory) + LocalProcess::shellcode::offsetGet64BitPEB, 1, 0);
#endif
}


Process::ModuleInformationA LocalProcessA::getModuleInfo_x86(const std::string& modName) const noexcept
{
#ifdef _WIN64

	return Process::ModuleInformationA{};

#else

	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationA newModule{};
	
	const QWORD pebAddr{ getPEBAddress_x86() };

	if (!pebAddr)
		return newModule;

	const LIST_ENTRY* const pFirstEntry{ reinterpret_cast<PEB*>(pebAddr)->Ldr->InLoadOrderModuleList.Flink };
	const LIST_ENTRY* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.Buffer)
		{
			const std::wstring moduleName{ currentLoaderEntry.BaseDllName.Buffer };
			const std::string currModName{ moduleName.begin(), moduleName.end() };

			if (!_strcmpi(currModName.c_str(), modName.c_str()))
			{
				newModule.modBA.x64Addr = reinterpret_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = currModName;
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}
		}

		pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (pCurrEntry == pFirstEntry)
			break;
	}

	return newModule;

#endif
}

Process::ModuleInformationA LocalProcessA::getModuleInfo_x64(const std::string& modName) const noexcept
{
	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationA newModule{};
	
	const QWORD pebAddr{ getPEBAddress_x64() };

	if (!pebAddr)
		return newModule;

#ifdef _WIN64

	const LIST_ENTRY64* const pFirstEntry{ reinterpret_cast<LIST_ENTRY64*>(reinterpret_cast<PEB_LDR_DATA64*>(reinterpret_cast<PEB64*>(pebAddr)->Ldr)->InLoadOrderModuleList.Flink) };

	const LIST_ENTRY64* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY64*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			const std::wstring moduleName{ reinterpret_cast<wchar_t*>(currentLoaderEntry.BaseDllName.WideStringAddress) };
			const std::string currModName{ moduleName.begin(), moduleName.end() };

			if (!_strcmpi(currModName.c_str(), modName.c_str()))
			{
				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = currModName;
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}
		}

		pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

		if (pCurrEntry == pFirstEntry)
			break;
	}

#else

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return newModule;
	}
	
	PEB_LDR_DATA64 ldrData{};

	if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		return newModule;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			break;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == firstEntryAddr)
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

			if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			{
				const std::wstring moduleName{ reinterpret_cast<wchar_t*>(pModuleName) };
				const std::string currModName{ moduleName.begin(), moduleName.end() };

				if (!_strcmpi(currModName.c_str(), modName.c_str()))
				{
					delete[] pModuleName;
					pModuleName = nullptr;

					newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
					newModule.modName = currModName;
					newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
					newModule.procID = m_processInfo.procID;
					newModule.procName = m_processInfo.procName;

					break;
				}
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == firstEntryAddr)
			break;
	}

#endif

	return newModule;
}


QWORD LocalProcessA::getProcAddress_x86(const QWORD modBA, const std::string& functionName) const noexcept
{
#ifdef _WIN64

	return 0;

#else

	if (!modBA || modBA > 0xFFFFFFFF || functionName.empty())
		return 0;

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x10B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	QWORD procAddress{};

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!_stricmp(reinterpret_cast<const char*>(modBA + pNameArray[iterator]), functionName.c_str()))
		{
			const WORD ordinal{ pOrdinalArray[iterator] };
			procAddress = modBA + static_cast<QWORD>(pExportTable[ordinal]);

			if (procAddress > static_cast<QWORD>(0xFFFFFFFF))
				return 0;

			break;
		}
	}

	return procAddress;

#endif
}

QWORD LocalProcessA::getProcAddress_x64(const QWORD modBA, const std::string& functionName) const noexcept
{

	if (!modBA || functionName.empty())
		return 0;

#ifdef _WIN64

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x20B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	QWORD procAddress{};

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!_stricmp(reinterpret_cast<const char*>(modBA + pNameArray[iterator]), functionName.c_str()))
		{
			const WORD ordinal{ pOrdinalArray[iterator] };
			procAddress = modBA + static_cast<QWORD>(pExportTable[ordinal]);

			break;
		}
	}

	return procAddress;

#else

	return reinterpret_cast<QWORD(__cdecl*)(QWORD, QWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress)(modBA, reinterpret_cast<QWORD>(functionName.c_str()));

#endif
}

QWORD LocalProcessA::getProcAddress_x86(const std::string modName, const std::string& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD LocalProcessA::getProcAddress_x64(const std::string modName, const std::string& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getProcAddress_x64(modBA, functionName) : 0;
}


Process::ModuleInformationA LocalProcessA::getModuleInfo_x86(const std::string& modName) noexcept
{
#ifdef _WIN64

	return Process::ModuleInformationA{};

#else

	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationA modInfo{ const_cast<const LocalProcessA* const>(this)->getModuleInfo_x86(modName) };

	if (validModule(modInfo))
		m_x86Modules.push_back(modInfo);

	return modInfo;

#endif
}

Process::ModuleInformationA LocalProcessA::getModuleInfo_x64(const std::string& modName) noexcept
{
	std::vector<Process::ModuleInformationA>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return (!_strcmpi(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationA modInfo{ const_cast<const LocalProcessA* const>(this)->getModuleInfo_x64(modName) };

	if (validModule(modInfo))
		m_x64Modules.push_back(modInfo);

	return modInfo;
}


QWORD LocalProcessA::scanPattern(const Process::SignatureA& signature) const noexcept
{
	QWORD result{};

#ifndef _WIN64

	for (const Process::ModuleInformationA& currModule : m_x86Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x86({ signature, currModule.modName })))
		{
			return result;
		}
	}

#endif

	for (const Process::ModuleInformationA& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x64({ signature, currModule.modName })))
		{
			return result;
		}
	}

	return result;
}

QWORD LocalProcessA::scanPattern_x86(const Process::ModuleSignatureA& signature) const noexcept
{
#ifdef _WIN64

	return 0;

#else

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
		result = static_cast<QWORD>(*reinterpret_cast<DWORD*>(result + currOffset));
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x86(signature.moduleName);

	return result;

#endif
}

QWORD LocalProcessA::scanPattern_x64(const Process::ModuleSignatureA& signature) const noexcept
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
#ifdef _WIN64

		result = static_cast<QWORD>(*reinterpret_cast<QWORD*>(result + currOffset));

#else

		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
			return 0;
		}

		if (_NtWow64RVM(m_hProc, result + currOffset, &result, sizeof(result), nullptr) != STATUS_SUCCESS)
			return 0;

#endif
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
}


int LocalProcessA::patternCount(const Process::SignatureA& signature) const noexcept
{
	return findGadgets(signature).size();
}

int LocalProcessA::patternCount_x86(const Process::ModuleSignatureA& signature) const noexcept
{
	return findGadgets_x86(signature).size();
}

int LocalProcessA::patternCount_x64(const Process::ModuleSignatureA& signature) const noexcept
{
	return findGadgets_x64(signature).size();
}


std::vector<Process::FoundGadgetA> LocalProcessA::findGadgets(const Process::SignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

#ifndef _WIN64

	for (const Process::ModuleInformationA& currModule : m_x86Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty())
		{
			std::vector<Process::FoundGadgetA> moduleGadgets{ findGadgets_x86({signature, currModule.modName }) };

			if (moduleGadgets.size())
				result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
		}
	}

#endif

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

std::vector<Process::FoundGadgetA> LocalProcessA::findGadgets_x86(const Process::ModuleSignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

#ifdef _WIN64

	return result;

#else

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		if (signature.readable)
		{
			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetA currGadget{};

					currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);
			}
		}
	}

	return result;

#endif
}

std::vector<Process::FoundGadgetA> LocalProcessA::findGadgets_x64(const Process::ModuleSignatureA& signature) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

#ifndef _WIN64

	static QWORD _NtWow64QVM{ getNativeProcAddressWow64("NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = getNativeProcAddressWow64("NtQueryVirtualMemory");
		return result;
	}

	static QWORD _NtWow64PVM{ getNativeProcAddressWow64("NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = getNativeProcAddressWow64("NtProtectVirtualMemory");
		return result;
	}

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return result;
	}

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
#ifdef _WIN64

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), reinterpret_cast<MEMORY_BASIC_INFORMATION*>(&mbi), sizeof(mbi)))
			break;

#else

		QWORD returnLength{};

		if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
			break;

#endif

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

#ifdef _WIN64

		if (signature.readable)
		{
			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetA currGadget{};

					currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);
			}
		}

#else

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
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
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				{
					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

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

#endif
	}

	return result;
}


#ifndef _WIN64

BOOL LocalProcessA::callNativeFunction(const std::string& funcName, const DWORD argCount, ...) const noexcept
{
	const QWORD funcAddr{ getNativeProcAddressWow64(funcName) };

	if (!funcAddr || !argCount)
		return FALSE;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}

BOOL LocalProcessA::callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr || !argCount)
		return FALSE;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}


QWORD LocalProcessA::call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr || !argCount)
		return 0;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}

#endif




bool LocalProcessW::updateModuleInfo_x86() noexcept
{
#ifdef _WIN64

	return false;

#else

	const QWORD pebAddr{ getPEBAddress_x86() };

	if (!pebAddr)
		return false;

	const LIST_ENTRY* const pFirstEntry{ reinterpret_cast<PEB*>(pebAddr)->Ldr->InLoadOrderModuleList.Flink };
	const LIST_ENTRY* pCurrEntry{ pFirstEntry };

	std::vector<Process::ModuleInformationW> newModuleList{};

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.Buffer)
		{
			Process::ModuleInformationW currentModule{};

			currentModule.modBA.x64Addr = reinterpret_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::wstring{ currentLoaderEntry.BaseDllName.Buffer };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);
		}

		pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (pCurrEntry == pFirstEntry)
			break;
	}

	m_x86Modules = newModuleList;

	return true;

#endif
}

bool LocalProcessW::updateModuleInfo_x64() noexcept
{
	const QWORD pebAddr{ getPEBAddress_x64() };

	if (!pebAddr)
		return false;

	std::vector<Process::ModuleInformationW> newModuleList{};

#ifdef _WIN64

	const LIST_ENTRY64* const pFirstEntry{ reinterpret_cast<LIST_ENTRY64*>(reinterpret_cast<PEB_LDR_DATA64*>(reinterpret_cast<PEB64*>(pebAddr)->Ldr)->InLoadOrderModuleList.Flink) };

	const LIST_ENTRY64* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY64*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			Process::ModuleInformationW currentModule{};

			currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
			currentModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(currentLoaderEntry.BaseDllName.WideStringAddress) };
			currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
			currentModule.procID = m_processInfo.procID;
			currentModule.procName = m_processInfo.procName;

			newModuleList.push_back(currentModule);
		}

		pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

		if (pCurrEntry == pFirstEntry)
			break;
	}

#else

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return false;
	}

	PEB_LDR_DATA64 ldrData{};

	if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		return false;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			return false;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == firstEntryAddr)
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

			if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			{
				Process::ModuleInformationW currentModule{};

				currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				currentModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
				currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				currentModule.procID = m_processInfo.procID;
				currentModule.procName = m_processInfo.procName;

				newModuleList.push_back(currentModule);
			}
			else
			{
				delete[] pModuleName;
				pModuleName = nullptr;
				return false;
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == firstEntryAddr)
			break;
	}

#endif

	m_x64Modules = newModuleList;

	return true;
}

/*
QWORD LocalProcessW::getPatternAddress_x86(const Process::ModuleSignatureW& signature, bool& patternFound) const noexcept
{
	patternFound = false;

#ifdef _WIN64

	return 0;

#else

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return 0;

	QWORD result{};

	MEMORY_BASIC_INFORMATION mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			break;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			break;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			break;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			break;

		if (signature.readable)
		{
			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer);
				break;
			}
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer);
					break;
				}
			}
		}
	}

	return result;

#endif
}

QWORD LocalProcessW::getPatternAddress_x64(const Process::ModuleSignatureW& signature, bool& patternFound) const noexcept
{
	patternFound = false;

#ifndef _WIN64

	static QWORD _NtWow64QVM{ getNativeProcAddressWow64(L"NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = getNativeProcAddressWow64(L"NtQueryVirtualMemory");
		return 0;
	}

	static QWORD _NtWow64PVM{ getNativeProcAddressWow64(L"NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = getNativeProcAddressWow64(L"NtProtectVirtualMemory");
		return 0;
	}

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return 0;
	}

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return 0;

	QWORD result{};

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
#ifdef _WIN64

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), reinterpret_cast<MEMORY_BASIC_INFORMATION*>(&mbi), sizeof(mbi)))
			break;

#else

		QWORD returnLength{};

		if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
			break;

#endif

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			break;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			break;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			break;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			break;

#ifdef _WIN64

		if (signature.readable)
		{

			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer);
				break;
			}
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer);
					break;
				}
			}
		}

#else

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			break;

		if (signature.readable)
		{
			if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
			{
				VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				break;
			}

			const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);

			if (patternFound)
			{
				result = reinterpret_cast<QWORD>(addrBuffer) - reinterpret_cast<QWORD>(pScanBuffer) + currAddress;
				break;
			}
		}
		else
		{
			DWORD oldProtect{};
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				{
					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					break;
				}

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

				const char* const addrBuffer{ findPatternInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern, patternFound) };

				VirtualFree(pScanBuffer, 0, MEM_RELEASE);

				if (patternFound)
				{
					result = reinterpret_cast<QWORD>(addrBuffer) - reinterpret_cast<QWORD>(pScanBuffer) + currAddress;
					break;
				}
			}
		}

#endif
	}

	return result;
}
*/


#ifndef _WIN64

void LocalProcessW::initShellcodeMemory() noexcept
{
	if (LocalProcessW::s_instance.m_initState == LocalProcess::InitState::uninitialized)
	{
		LocalProcessW::s_instance.m_initState = LocalProcess::InitState::initializing;
		LocalProcessW::s_instance.m_shellcodeMemory = 0;

		while (!LocalProcessW::s_instance.m_shellcodeMemory)
			LocalProcessW::s_instance.m_shellcodeMemory = reinterpret_cast<DWORD>(VirtualAlloc(nullptr, LocalProcess::shellcode::shellcodeMemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		char* pMemory{ reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory) };

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::getNativeModuleX64SetupCode, sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode));
		*reinterpret_cast<DWORD*>(&pMemory[0x0D]) = reinterpret_cast<DWORD>(pMemory + 0x17);
		*reinterpret_cast<DWORD*>(&pMemory[0x12]) = LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeModule;
		*reinterpret_cast<DWORD*>(&pMemory[0x23]) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode));
		pMemory += sizeof(LocalProcess::shellcode::getNativeModuleX64SetupCode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeModule);
		memcpy(pMemory, LocalProcess::shellcode::getNativeModuleX64Shellcode, sizeof(LocalProcess::shellcode::getNativeModuleX64Shellcode));

		pMemory = reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress);

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::getNativeProcAddressX64SetupCode, sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode));
		*reinterpret_cast<DWORD*>(&pMemory[0x14]) = reinterpret_cast<DWORD>(pMemory + 0x1E);
		*reinterpret_cast<DWORD*>(&pMemory[0x19]) = LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeProcAddress;
		*reinterpret_cast<DWORD*>(&pMemory[0x2A]) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode));
		pMemory += sizeof(LocalProcess::shellcode::getNativeProcAddressX64SetupCode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGetNativeProcAddress);
		memcpy(pMemory, LocalProcess::shellcode::getNativeProcAddressX64Shellcode, sizeof(LocalProcess::shellcode::getNativeProcAddressX64Shellcode));

		pMemory = reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction);

		memcpy(pMemory, LocalProcess::shellcode::x86_EnterStackFrame, sizeof(LocalProcess::shellcode::x86_EnterStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_EnterStackFrame);

		*reinterpret_cast<QWORD*>(pMemory) = LocalProcess::generateSwitchToLongMode(reinterpret_cast<DWORD>(pMemory) + sizeof(QWORD));
		pMemory += sizeof(QWORD);

		memcpy(pMemory, LocalProcess::shellcode::callNativeFunctionX64Shellcode, sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode));
		*reinterpret_cast<DWORD*>(pMemory + (sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode) - 10)) = reinterpret_cast<DWORD>(pMemory + sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode));
		pMemory += sizeof(LocalProcess::shellcode::callNativeFunctionX64Shellcode);

		memcpy(pMemory, LocalProcess::shellcode::x86_LeaveStackFrame, sizeof(LocalProcess::shellcode::x86_LeaveStackFrame));
		pMemory += sizeof(LocalProcess::shellcode::x86_LeaveStackFrame);

		*pMemory = LocalProcess::shellcode::x86_64_cdeclRet;

		pMemory = reinterpret_cast<char*>(LocalProcessW::s_instance.m_shellcodeMemory + LocalProcess::shellcode::offsetGet64BitPEB);
		memcpy(pMemory, LocalProcess::shellcode::x86_64_readPEBFromReg, sizeof(LocalProcess::shellcode::x86_64_readPEBFromReg));

		DWORD oldProtect{};
		VirtualProtect(reinterpret_cast<LPVOID>(LocalProcessW::s_instance.m_shellcodeMemory), LocalProcess::shellcode::shellcodeMemorySize, PAGE_EXECUTE_READ, &oldProtect);

		LocalProcessW::s_instance.m_initState = LocalProcess::InitState::initialized;
	}
}

void LocalProcessW::deleteShellcodeMemory() noexcept
{
	while (LocalProcessW::s_instance.m_initState == LocalProcess::InitState::initializing)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	if (LocalProcessW::s_instance.m_initState == LocalProcess::InitState::uninitialized)
		return;
	else
	{
		VirtualFree(reinterpret_cast<LPVOID>(LocalProcessW::s_instance.m_shellcodeMemory), 0, MEM_RELEASE);
		LocalProcessW::s_instance.m_shellcodeMemory = 0;
		LocalProcessW::s_instance.m_initState = LocalProcess::InitState::uninitialized;
	}
}

#endif


LocalProcessW::LocalProcessW() noexcept
{
#ifdef _WIN64

	m_processInfo.wow64Process = false;

#else

	m_processInfo.wow64Process = true;
	initShellcodeMemory();

#endif

	BOOL wow64Proc{ FALSE };
	if (IsWow64Process(GetCurrentProcess(), &wow64Proc))
		m_processInfo.wow64Process = static_cast<bool>(wow64Proc);

	while (!validHandle(m_hProc))
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	LocalProcessW::s_instance.updateProcessInfo();
	LocalProcessW::s_instance.updateModuleInfo();

}

LocalProcessW::~LocalProcessW()
{
#ifndef _WIN64

	deleteShellcodeMemory();

#endif

	if (validHandle(m_hProc))
	{
		CloseHandle(m_hProc);
		m_hProc = INVALID_HANDLE_VALUE;
	}

}

/*
LocalProcessW& LocalProcessW::getInstance() noexcept
{
#ifndef _WIN64

	while (s_instance.m_initState == LocalProcess::InitState::initializing)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	if (s_instance.m_initState == LocalProcess::InitState::uninitialized)
		initShellcodeMemory();

#endif

	return s_instance;
}
*/

uintptr_t LocalProcessW::getNativeProcAddress(const std::wstring& functionName) const noexcept
{
	std::map<std::wstring, uintptr_t>::const_iterator it{ m_nativeFunctions.find(functionName) };

	if (it != m_nativeFunctions.end())
	{
		return (*it).second;
	}
	else
	{
		return static_cast<uintptr_t>(getProcAddress(L"ntdll.dll", functionName));
	}
}

uintptr_t LocalProcessW::getNativeProcAddress(const std::wstring& functionName) noexcept
{
	const uintptr_t procAddr{ const_cast<const LocalProcessW* const>(this)->getNativeProcAddress(functionName) };

	if (procAddr)
		m_nativeFunctions[functionName] = procAddr;

	return procAddr;
}


#ifndef _WIN64

QWORD LocalProcessW::getNativeProcAddressWow64(const std::wstring& functionName) const noexcept
{
	std::map<std::wstring, QWORD>::const_iterator it{ m_nativeFunctionsWow64.find(functionName) };

	if (it != m_nativeFunctionsWow64.end())
	{
		return (*it).second;
	}
	else
	{
		return getProcAddress_x64(L"ntdll.dll", functionName);
	}
}

QWORD LocalProcessW::getNativeProcAddressWow64(const std::wstring& functionName) noexcept
{
	const QWORD procAddr{ const_cast<const LocalProcessW* const>(this)->getNativeProcAddressWow64(functionName) };

	if (procAddr)
		m_nativeFunctionsWow64[functionName] = procAddr;

	return procAddr;
}

#endif


bool LocalProcessW::updateProcessInfo() noexcept
{
	static tNtQuerySystemInformation _NtQSI{ reinterpret_cast<const tNtQuerySystemInformation>(getNativeProcAddress(L"NtQuerySystemInformation")) };

	if (!_NtQSI)
	{
		_NtQSI = reinterpret_cast<const tNtQuerySystemInformation>(getNativeProcAddress(L"NtQuerySystemInformation"));

		return false;
	}

	const DWORD currProcID{ GetCurrentProcessId() };

	DWORD allocSize{ 0x10000 };

	LPVOID pBuffer{ VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!pBuffer)
		return false;

	ULONG dummyBuffer{};

	NTSTATUS status{};

	while ((status = _NtQSI(SystemProcessInformation, pBuffer, allocSize, &dummyBuffer)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		pBuffer = nullptr;
		allocSize += 0x10000;
		pBuffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!pBuffer)
			return false;
	}

	if (status != STATUS_SUCCESS)
	{
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return false;
	}

	const SYSTEM_PROCESS_INFORMATION* pSPI{ static_cast<SYSTEM_PROCESS_INFORMATION*>(pBuffer) };
	ULONG nextEntryOffset{};

	do
	{
		if (reinterpret_cast<uintptr_t>(pSPI->UniqueProcessId) == static_cast<uintptr_t>(currProcID))
		{
			m_processInfo.procID = currProcID;
			m_processInfo.parentProcID = reinterpret_cast<DWORD>(pSPI->InheritedFromUniqueProcessId);
			m_processInfo.threadBasePriority = pSPI->BasePriority;
			m_processInfo.threadCount = pSPI->NumberOfThreads;

			if (pSPI->ImageName.Length <= 0 ||
				pSPI->ImageName.MaximumLength <= 0 ||
				pSPI->ImageName.Length > 256 ||
				pSPI->ImageName.MaximumLength > 256)
			{
				VirtualFree(pBuffer, 0, MEM_RELEASE);
				return true;
			}

			m_processInfo.procName = std::wstring{ pSPI->ImageName.Buffer };

			VirtualFree(pBuffer, 0, MEM_RELEASE);
			return true;
		}

		nextEntryOffset = pSPI->NextEntryOffset;
		pSPI = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<const char*>(pSPI) + pSPI->NextEntryOffset);

	} while (nextEntryOffset);

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return false;
}

bool LocalProcessW::updateModuleInfo() noexcept
{
	bool status{ updateModuleInfo_x64() };

	return ((m_processInfo.wow64Process) ? updateModuleInfo_x86() && status : status);
}


QWORD LocalProcessW::getPEBAddress_x86() const noexcept
{
#ifdef _WIN64
	return 0;
#else
	return static_cast<QWORD>(__readfsdword(0x30));
#endif
}

QWORD LocalProcessW::getPEBAddress_x64() const noexcept
{
#ifdef _WIN64
	return static_cast<QWORD>(__readgsqword(0x60));
#else
	return call64BitFunction(static_cast<QWORD>(m_shellcodeMemory) + LocalProcess::shellcode::offsetGet64BitPEB, 1, 0);
#endif
}


Process::ModuleInformationW LocalProcessW::getModuleInfo_x86(const std::wstring& modName) const noexcept
{
#ifdef _WIN64

	return Process::ModuleInformationW{};

#else

	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationW newModule{};

	const QWORD pebAddr{ getPEBAddress_x86() };

	if (!pebAddr)
		return newModule;

	const LIST_ENTRY* const pFirstEntry{ reinterpret_cast<PEB*>(pebAddr)->Ldr->InLoadOrderModuleList.Flink };
	const LIST_ENTRY* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.Buffer)
		{
			const std::wstring moduleName{ currentLoaderEntry.BaseDllName.Buffer };

			if (!_wcsicmp(moduleName.c_str(), modName.c_str()))
			{
				newModule.modBA.x64Addr = reinterpret_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = moduleName;
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}
		}

		pCurrEntry = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (pCurrEntry == pFirstEntry)
			break;
	}

	return newModule;

#endif
}

Process::ModuleInformationW LocalProcessW::getModuleInfo_x64(const std::wstring& modName) const noexcept
{
	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationW newModule{};

	const QWORD pebAddr{ getPEBAddress_x64() };

	if (!pebAddr)
		return newModule;

#ifdef _WIN64

	const LIST_ENTRY64* const pFirstEntry{ reinterpret_cast<LIST_ENTRY64*>(reinterpret_cast<PEB_LDR_DATA64*>(reinterpret_cast<PEB64*>(pebAddr)->Ldr)->InLoadOrderModuleList.Flink) };

	const LIST_ENTRY64* pCurrEntry{ pFirstEntry };

	while (pCurrEntry)
	{
		const LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{ *reinterpret_cast<const LDR_DATA_TABLE_ENTRY64*>(pCurrEntry) };

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

			if (pCurrEntry == pFirstEntry)
				break;

			continue;
		}

		if (currentLoaderEntry.BaseDllName.Length && currentLoaderEntry.BaseDllName.MaximumLength && currentLoaderEntry.BaseDllName.WideStringAddress)
		{
			const std::wstring moduleName{ reinterpret_cast<wchar_t*>(currentLoaderEntry.BaseDllName.WideStringAddress) };

			if (!_wcsicmp(moduleName.c_str(), modName.c_str()))
			{
				newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				newModule.modName = moduleName;
				newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				newModule.procID = m_processInfo.procID;
				newModule.procName = m_processInfo.procName;

				break;
			}
		}

		pCurrEntry = reinterpret_cast<LIST_ENTRY64*>(currentLoaderEntry.InLoadOrderLinks.Flink);

		if (pCurrEntry == pFirstEntry)
			break;
	}

#else

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return newModule;
	}

	PEB_LDR_DATA64 ldrData{};

	if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		return newModule;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			break;

		if (currentLoaderEntry.BaseDllName.Length <= 0 ||
			currentLoaderEntry.BaseDllName.MaximumLength <= 0 ||
			currentLoaderEntry.BaseDllName.Length > 256 ||
			currentLoaderEntry.BaseDllName.MaximumLength > 256)
		{
			currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

			if (currEntryAddr == firstEntryAddr)
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

			if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			{
				const std::wstring moduleName{ reinterpret_cast<wchar_t*>(pModuleName) };

				if (!_wcsicmp(moduleName.c_str(), modName.c_str()))
				{
					delete[] pModuleName;
					pModuleName = nullptr;

					newModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
					newModule.modName = moduleName;
					newModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
					newModule.procID = m_processInfo.procID;
					newModule.procName = m_processInfo.procName;

					break;
				}
			}

			delete[] pModuleName;
			pModuleName = nullptr;
		}

		currEntryAddr = currentLoaderEntry.InLoadOrderLinks.Flink;

		if (currEntryAddr == firstEntryAddr)
			break;
	}

#endif

	return newModule;
}


QWORD LocalProcessW::getProcAddress_x86(const QWORD modBA, const std::wstring& functionName) const noexcept
{
#ifdef _WIN64

	return 0;

#else

	if (!modBA || modBA > 0xFFFFFFFF || functionName.empty())
		return 0;

	const std::string aFuncName{ functionName.begin(), functionName.end() };

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x10B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	QWORD procAddress{};

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!_strcmpi(reinterpret_cast<const char*>(modBA + pNameArray[iterator]), aFuncName.c_str()))
		{
			const WORD ordinal{ pOrdinalArray[iterator] };
			procAddress = modBA + static_cast<QWORD>(pExportTable[ordinal]);

			if (procAddress > static_cast<QWORD>(0xFFFFFFFF))
				return 0;

			break;
		}
	}

	return procAddress;

#endif
}

QWORD LocalProcessW::getProcAddress_x64(const QWORD modBA, const std::wstring& functionName) const noexcept
{

	if (!modBA || functionName.empty())
		return 0;

	const std::string aFuncName{ functionName.begin(), functionName.end() };

#ifdef _WIN64

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return 0;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x20B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	QWORD procAddress{};

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!_strcmpi(reinterpret_cast<const char*>(modBA + pNameArray[iterator]), aFuncName.c_str()))
		{
			const WORD ordinal{ pOrdinalArray[iterator] };
			procAddress = modBA + static_cast<QWORD>(pExportTable[ordinal]);

			break;
		}
	}

	return procAddress;

#else

	return reinterpret_cast<QWORD(__cdecl*)(QWORD, QWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress)(modBA, reinterpret_cast<QWORD>(aFuncName.c_str()));

#endif
}

QWORD LocalProcessW::getProcAddress_x86(const std::wstring modName, const std::wstring& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD LocalProcessW::getProcAddress_x64(const std::wstring modName, const std::wstring& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getProcAddress_x64(modBA, functionName) : 0;
}


Process::ModuleInformationW LocalProcessW::getModuleInfo_x86(const std::wstring& modName) noexcept
{
#ifdef _WIN64

	return Process::ModuleInformationW{};

#else

	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x86Modules.end())
		return *it;

	Process::ModuleInformationW modInfo{ const_cast<const LocalProcessW* const>(this)->getModuleInfo_x86(modName) };

	if (validModule(modInfo))
		m_x86Modules.push_back(modInfo);

	return modInfo;

#endif
}

Process::ModuleInformationW LocalProcessW::getModuleInfo_x64(const std::wstring& modName) noexcept
{
	std::vector<Process::ModuleInformationW>::const_iterator it{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return (!_wcsicmp(mod.modName.c_str(), modName.c_str())); }) };

	if (it != m_x64Modules.end())
		return *it;

	Process::ModuleInformationW modInfo{ const_cast<const LocalProcessW* const>(this)->getModuleInfo_x64(modName) };

	if (validModule(modInfo))
		m_x64Modules.push_back(modInfo);

	return modInfo;
}


QWORD LocalProcessW::scanPattern(const Process::SignatureW& signature) const noexcept
{
	QWORD result{};

#ifndef _WIN64

	for (const Process::ModuleInformationW& currModule : m_x86Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x86({ signature, currModule.modName })))
		{
			return result;
		}
	}

#endif

	for (const Process::ModuleInformationW& currModule : m_x64Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty() && (result = scanPattern_x64({ signature, currModule.modName })))
		{
			return result;
		}
	}

	return result;
}

QWORD LocalProcessW::scanPattern_x86(const Process::ModuleSignatureW& signature) const noexcept
{
#ifdef _WIN64

	return 0;

#else

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
		result = static_cast<QWORD>(*reinterpret_cast<DWORD*>(result + currOffset));
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x86(signature.moduleName);

	return result;

#endif
}

QWORD LocalProcessW::scanPattern_x64(const Process::ModuleSignatureW& signature) const noexcept
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
#ifdef _WIN64

		result = static_cast<QWORD>(*reinterpret_cast<QWORD*>(result + currOffset));

#else

		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
			return 0;
		}

		if (_NtWow64RVM(m_hProc, result + currOffset, &result, sizeof(result), nullptr) != STATUS_SUCCESS)
			return 0;

#endif
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
}


int LocalProcessW::patternCount(const Process::SignatureW& signature) const noexcept
{
	return findGadgets(signature).size();
}

int LocalProcessW::patternCount_x86(const Process::ModuleSignatureW& signature) const noexcept
{
	return findGadgets_x86(signature).size();
}

int LocalProcessW::patternCount_x64(const Process::ModuleSignatureW& signature) const noexcept
{
	return findGadgets_x64(signature).size();
}


std::vector<Process::FoundGadgetW> LocalProcessW::findGadgets(const Process::SignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

#ifndef _WIN64

	for (const Process::ModuleInformationW& currModule : m_x86Modules)
	{
		if (validModule(currModule) && !currModule.modName.empty())
		{
			std::vector<Process::FoundGadgetW> moduleGadgets{ findGadgets_x86({signature, currModule.modName }) };

			if (moduleGadgets.size())
				result.insert(result.end(), moduleGadgets.begin(), moduleGadgets.end());
		}
	}

#endif

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

std::vector<Process::FoundGadgetW> LocalProcessW::findGadgets_x86(const Process::ModuleSignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

#ifdef _WIN64

	return result;

#else

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x86(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION mbi{};

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress += mbi.RegionSize)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
			break;

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

		if (signature.readable)
		{
			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetW currGadget{};

					currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);
			}
		}
	}

	return result;

#endif
}

std::vector<Process::FoundGadgetW> LocalProcessW::findGadgets_x64(const Process::ModuleSignatureW& signature) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

#ifndef _WIN64

	static QWORD _NtWow64QVM{ getNativeProcAddressWow64(L"NtQueryVirtualMemory") };

	if (!_NtWow64QVM)
	{
		_NtWow64QVM = getNativeProcAddressWow64(L"NtQueryVirtualMemory");
		return result;
	}

	static QWORD _NtWow64PVM{ getNativeProcAddressWow64(L"NtProtectVirtualMemory") };

	if (!_NtWow64PVM)
	{
		_NtWow64PVM = getNativeProcAddressWow64(L"NtProtectVirtualMemory");
		return result;
	}

	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return result;
	}

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress += mbi.RegionSize)
	{
#ifdef _WIN64

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), reinterpret_cast<MEMORY_BASIC_INFORMATION*>(&mbi), sizeof(mbi)))
			break;

#else

		QWORD returnLength{};

		if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
			break;

#endif

		if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
			continue;

		if (signature.executable && !(mbi.Protect & PAGE_EXECUTE) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			continue;

		if (signature.readable && (mbi.Protect & PAGE_EXECUTE))
			continue;

		if (signature.writable && ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY)))
			continue;

#ifdef _WIN64

		if (signature.readable)
		{
			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetW currGadget{};

					currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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
		}
		else
		{
			DWORD oldProtect{};

			if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
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

				VirtualProtect(reinterpret_cast<LPVOID>(currAddress), mbi.RegionSize, oldProtect, &oldProtect);
			}
		}

#else

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
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
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				{
					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					continue;
				}

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

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

#endif
	}

	return result;
}


#ifndef _WIN64

BOOL LocalProcessW::callNativeFunction(const std::wstring& funcName, const DWORD argCount, ...) const noexcept
{
	const QWORD funcAddr{ getNativeProcAddressWow64(funcName) };

	if (!funcAddr || !argCount)
		return FALSE;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}

BOOL LocalProcessW::callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr || !argCount)
		return FALSE;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}


QWORD LocalProcessW::call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr || !argCount)
		return 0;

	QWORD* pArgList{ nullptr };

	while (!pArgList)
		pArgList = new QWORD[argCount];

	std::va_list list{};

	va_start(list, argCount);

	for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
	{
		pArgList[iterator] = va_arg(list, QWORD);
	}

	va_end(list);

	const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) };

	delete[] pArgList;
	pArgList = nullptr;

	return retVal;
}

#endif