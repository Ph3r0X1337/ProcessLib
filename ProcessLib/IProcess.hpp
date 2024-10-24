#pragma once

#include "ProcessUtils.hpp"

template <class T>
class IProcess
{

protected:

	HANDLE m_hProc{ INVALID_HANDLE_VALUE };
	Process::ProcessInformation<T> m_processInfo{};
	std::vector<Process::ModuleInformation<T>> m_x86Modules{};
	std::vector<Process::ModuleInformation<T>> m_x64Modules{};

	virtual bool updateModuleInfo_x86() noexcept = 0;
	virtual bool updateModuleInfo_x64() noexcept = 0;

	std::vector<char*> findPatternsInBuffer(const char* const pStart, const DWORD scanSize, const std::vector<Process::SigByte>& signature) const noexcept
	{
		std::vector<char*> result{};

		if (!pStart || !scanSize || !signature.size() || scanSize < signature.size())
			return result;

		for (const char* pCurrChar{ const_cast<const char*>(pStart) }; pCurrChar < (pStart + (scanSize - signature.size())); ++pCurrChar)
		{
			const char* pCharIt{ pCurrChar };
			bool found{ true };

			for (const Process::SigByte& currSigByte : signature)
			{
				if (!found)
					break;

				switch (currSigByte.maskChar)
				{
				case 'x':
				{
					if (currSigByte.patternChar != *pCharIt++)
					{
						found = false;
					}
					continue;
				}
				case '?':
				{
					++pCharIt;
					continue;
				}
				default:
				{
					return result;
				}
				}
			}

			if (found)
			{
				result.push_back(const_cast<char*>(pCurrChar));
			}
		}

		return result;
	}

public:

	IProcess() = default;
	IProcess(const HANDLE hProc) noexcept : m_hProc{ hProc } {}
	IProcess(const Process::ProcessInformation<T>& procInfo, const HANDLE hProc = INVALID_HANDLE_VALUE) noexcept : m_processInfo{ procInfo } , m_hProc{ hProc } {}
	virtual ~IProcess() = default;

	virtual bool updateProcessInfo() noexcept = 0;
	virtual bool updateModuleInfo() noexcept = 0;

	Process::ProcessInformation<T> getProcessInfo() const noexcept { return m_processInfo; }
	DWORD getProcessID() const noexcept { return m_processInfo.procID; }
	DWORD getParentProcessID() const noexcept { return m_processInfo.parentProcID; }
	T getProcessName() const noexcept { return m_processInfo.procName; }
	DWORD getProcessThreadCount() const noexcept { return m_processInfo.threadCount; }
	LONG getProcessThreadBasePriority() const noexcept { return m_processInfo.threadBasePriority; }
	HANDLE getProcessHandle() const noexcept { return m_hProc; }

	bool isWow64Process() const noexcept { return m_processInfo.wow64Process; }
	bool isModuleAddress(const QWORD address, Process::ModuleInformation<T>* const pOutModInfo) const noexcept
	{
		for (const Process::ModuleInformation<T>& mod : m_x86Modules)
		{
			if (address >= mod.modBA.x64Addr && address < (mod.modBA.x64Addr + mod.modSize))
			{
				if (pOutModInfo)
					*pOutModInfo = mod;
				return true;
			}
		}

		for (const Process::ModuleInformation<T>& mod : m_x64Modules)
		{
			if (address >= mod.modBA.x64Addr && address < (mod.modBA.x64Addr + mod.modSize))
			{
				if (pOutModInfo)
					*pOutModInfo = mod;
				return true;
			}
		}

		return false;
	}

	std::vector<Process::ModuleInformation<T>> getModuleList() const noexcept { return ((m_processInfo.wow64Process) ? m_x86Modules : m_x64Modules); }
	std::vector<Process::ModuleInformation<T>> getModuleListX86() const noexcept { return m_x86Modules; }
	std::vector<Process::ModuleInformation<T>> getModuleListX64() const noexcept { return m_x64Modules; }

	QWORD getPEBAddress() const noexcept { return ((m_processInfo.wow64Process) ? getPEBAddress_x86() : getPEBAddress_x64()); }
	virtual QWORD getPEBAddress_x86() const noexcept = 0;
	virtual QWORD getPEBAddress_x64() const noexcept = 0;

	Process::ModuleInformation<T> getModuleInfo(const T& modName) const noexcept { return ((m_processInfo.wow64Process) ? getModuleInfo_x86(modName) : getModuleInfo_x64(modName)); }
	virtual Process::ModuleInformation<T> getModuleInfo_x86(const T& modName) const noexcept = 0;
	virtual Process::ModuleInformation<T> getModuleInfo_x64(const T& modName) const noexcept = 0;

	QWORD getModBA(const T& modName) const noexcept { return getModuleInfo(modName).modBA.x64Addr; }
	QWORD getModBA_x86(const T& modName) const noexcept { return getModuleInfo_x86(modName).modBA.x64Addr; }
	QWORD getModBA_x64(const T& modName) const noexcept { return getModuleInfo_x64(modName).modBA.x64Addr; }

	QWORD getModSize(const T& modName) const noexcept { return static_cast<QWORD>(getModuleInfo(modName).modSize); }
	QWORD getModSize_x86(const T& modName) const noexcept { return static_cast<QWORD>(getModuleInfo_x86(modName).modSize); }
	QWORD getModSize_x64(const T& modName) const noexcept { return static_cast<QWORD>(getModuleInfo_x64(modName).modSize); }

	std::vector<Process::ModuleExport<T>> getModuleExports(const QWORD modBA) const noexcept { return ((m_processInfo.wow64Process) ? getModuleExports_x86(modBA) : getModuleExports_x64(modBA)); }
	virtual std::vector<Process::ModuleExport<T>> getModuleExports_x86(const QWORD modBA) const noexcept = 0;
	virtual std::vector<Process::ModuleExport<T>> getModuleExports_x64(const QWORD modBA) const noexcept = 0;

	std::vector<Process::ModuleExport<T>> getModuleExports(const T& modName) const noexcept { return ((m_processInfo.wow64Process) ? getModuleExports_x86(modName) : getModuleExports_x64(modName)); }
	virtual std::vector<Process::ModuleExport<T>> getModuleExports_x86(const T& modName) const noexcept = 0;
	virtual std::vector<Process::ModuleExport<T>> getModuleExports_x64(const T& modName) const noexcept = 0;

	QWORD getProcAddress(const QWORD modBA, const T& functionName) const noexcept { return ((m_processInfo.wow64Process) ? getProcAddress_x86(modBA, functionName) : getProcAddress_x64(modBA, functionName)); }
	virtual QWORD getProcAddress_x86(const QWORD modBA, const T& functionName) const noexcept = 0;
	virtual QWORD getProcAddress_x64(const QWORD modBA, const T& functionName) const noexcept = 0;

	QWORD getProcAddress(const T& modName, const T& functionName) const noexcept { return ((m_processInfo.wow64Process) ? getProcAddress_x86(modName, functionName) : getProcAddress_x64(modName, functionName)); }
	virtual QWORD getProcAddress_x86(const T& modName, const T& functionName) const noexcept = 0;
	virtual QWORD getProcAddress_x64(const T& modName, const T& functionName) const noexcept = 0;

	Process::ModuleInformation<T> getModuleInfo(const T& modName) noexcept { return ((m_processInfo.wow64Process) ? getModuleInfo_x86(modName) : getModuleInfo_x64(modName)); }
	virtual Process::ModuleInformation<T> getModuleInfo_x86(const T& modName) noexcept = 0;
	virtual Process::ModuleInformation<T> getModuleInfo_x64(const T& modName) noexcept = 0;

	QWORD getModBA(const T& modName) noexcept { return getModuleInfo(modName).modBA.x64Addr; }
	QWORD getModBA_x86(const T& modName) noexcept { return getModuleInfo_x86(modName).modBA.x64Addr; }
	QWORD getModBA_x64(const T& modName) noexcept { return getModuleInfo_x64(modName).modBA.x64Addr; }

	QWORD getModSize(const T& modName) noexcept { return static_cast<QWORD>(getModuleInfo(modName).modSize); }
	QWORD getModSize_x86(const T& modName) noexcept { return static_cast<QWORD>(getModuleInfo_x86(modName).modSize); }
	QWORD getModSize_x64(const T& modName) noexcept { return static_cast<QWORD>(getModuleInfo_x64(modName).modSize); }

	virtual QWORD scanPattern(const Process::Signature<T>& signature) const noexcept = 0;
	QWORD scanPattern(const Process::ModuleSignature<T>& signature) const noexcept { return ((m_processInfo.wow64Process) ? scanPattern_x86(signature) : scanPattern_x64(signature)); }
	QWORD scanPattern(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept
	{
		if (!signature.size() || !startAddress || !endAddress)
			return 0;
		std::vector<Process::FoundGadget<T>> foundPatterns{ findGadgets(signature, startAddress, endAddress) };
		return ((foundPatterns.size()) ? foundPatterns.front().absoluteAddress : 0);
	}
	QWORD scanPattern(const std::vector<short>& signature, const QWORD startAddress, const DWORD regionSize) const noexcept { return scanPattern(signature, startAddress, startAddress + regionSize); }
	virtual QWORD scanPattern_x86(const Process::ModuleSignature<T>& signature) const noexcept = 0;
	virtual QWORD scanPattern_x64(const Process::ModuleSignature<T>& signature) const noexcept = 0;

	int patternCount(const Process::Signature<T>& signature) const noexcept { return static_cast<int>(findGadgets(signature).size()); }
	int patternCount(const Process::ModuleSignature<T>& signature) const noexcept { return ((m_processInfo.wow64Process) ? patternCount_x86(signature) : patternCount_x64(signature)); }
	int patternCount(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept { return static_cast<int>(findGadgets(signature, startAddress, endAddress).size()); }
	int patternCount(const std::vector<short>& signature, const QWORD startAddress, const DWORD regionSize) const noexcept { return static_cast<int>(findGadgets(signature, startAddress, startAddress + regionSize).size()); }
	int patternCount_x86(const Process::ModuleSignature<T>& signature) const noexcept { return static_cast<int>(findGadgets_x86(signature).size()); }
	int patternCount_x64(const Process::ModuleSignature<T>& signature) const noexcept { return static_cast<int>(findGadgets_x64(signature).size()); }

	virtual std::vector<Process::FoundGadget<T>> findGadgets(const Process::Signature<T>& signature) const noexcept = 0;
	std::vector<Process::FoundGadget<T>> findGadgets(const Process::ModuleSignature<T>& signature) const noexcept { return ((m_processInfo.wow64Process) ? findGadgets_x86(signature) : findGadgets_x64(signature)); }
	virtual std::vector<Process::FoundGadget<T>> findGadgets(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept = 0;
	std::vector<Process::FoundGadget<T>> findGadgets(const std::vector<short>& signature, const QWORD startAddress, const DWORD regionSize) const noexcept { return findGadgets(signature, startAddress, startAddress + regionSize); }
	virtual std::vector<Process::FoundGadget<T>> findGadgets_x86(const Process::ModuleSignature<T>& signature) const noexcept = 0;
	virtual std::vector<Process::FoundGadget<T>> findGadgets_x64(const Process::ModuleSignature<T>& signature) const noexcept = 0;

	static bool validHandle(const HANDLE handle) noexcept { return (handle && handle != INVALID_HANDLE_VALUE); }
	static bool validProcess(const Process::ProcessInformation<T>& process) noexcept { return (process.procID && process.threadCount); }
	static bool validModule(const Process::ModuleInformation<T>& mod) noexcept { return (mod.modBA.x64Addr && mod.modSize && mod.procID); }

};

using IProcessA = IProcess<std::string>;
using IProcessW = IProcess<std::wstring>;