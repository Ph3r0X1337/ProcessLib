#pragma once

#include "IProcess.hpp"


namespace ExtProcess
{

}

class ExtProcessA : public IProcessA
{
private:

	DWORD m_handleFlags{};
	bool m_attached{ false };

	bool m_closeHandleOnDetach{ false };
	bool m_reattachByName{ false };


	bool updateModuleInfo_x86() noexcept override final;
	bool updateModuleInfo_x64() noexcept override final;

#ifndef _WIN64

	BOOL RPM_Wow64(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept;
	BOOL WPM_Wow64(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept;

	QWORD AVM_Wow64(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept;
	BOOL FVM_Wow64(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept;

	BOOL PVM_Wow64(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept;
	SIZE_T QVM_Wow64(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept;

	template <typename T>
	T RPM_Wow64(const QWORD readAddr) const noexcept
	{
		T buffer{};

		if (!readAddr)
			return buffer;

		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64"));
			return buffer;
		}

		_NtWow64RVM(m_hProc, readAddr, &buffer, sizeof(buffer), nullptr);

		return buffer;
	}

	template <typename T>
	BOOL WPM_Wow64(const QWORD writeAddr, const T& value) const noexcept
	{
		if (!writeAddr)
			return FALSE;

		static tNtWow64WriteVirtualMemory64 _NtWow64WVM{ reinterpret_cast<tNtWow64WriteVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64WriteVirtualMemory64")) };

		if (!_NtWow64WVM)
		{
			_NtWow64WVM = reinterpret_cast<tNtWow64WriteVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64WriteVirtualMemory64"));
			return FALSE;
		}

		return static_cast<BOOL>(_NtWow64WVM(m_hProc, writeAddr, &value, sizeof(value), nullptr) == STATUS_SUCCESS);
	}

#endif

	ExtProcessA(const ExtProcessA&) {}
	void operator=(const ExtProcessA&) {}

public:

	ExtProcessA() noexcept;
	ExtProcessA(const std::string& procName, const DWORD handleFlags = PROCESS_ALL_ACCESS) noexcept;
	ExtProcessA(const DWORD procID, const DWORD handleFlags = PROCESS_ALL_ACCESS) noexcept;
	ExtProcessA(const HANDLE duplicatedHandle, bool reattachByName = false, bool closeHandleOnDetach = false) noexcept;
	virtual ~ExtProcessA();

	bool attach(const std::string& procName) noexcept;
	bool attach(const DWORD procID) noexcept;
	bool attach(const HANDLE hProc, bool reattachByName = false, bool closeHandleOnDetach = false) noexcept;
	bool detach() noexcept;
	bool reattach() noexcept;

	bool updateProcessInfo() noexcept override final;
	bool updateModuleInfo() noexcept override final;

	DWORD getHandleFlags() const noexcept { return m_handleFlags; }

	bool isAttached() const noexcept { return m_attached; }

	QWORD getPEBAddress_x86() const noexcept override final;
	QWORD getPEBAddress_x64() const noexcept override final;

	Process::ModuleInformationA getModuleInfo_x86(const std::string& modName) const noexcept override final;
	Process::ModuleInformationA getModuleInfo_x64(const std::string& modName) const noexcept override final;

	QWORD getProcAddress_x86(const QWORD modBA, const std::string& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const QWORD modBA, const std::string& functionName) const noexcept override final;

	QWORD getProcAddress_x86(const std::string modName, const std::string& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const std::string modName, const std::string& functionName) const noexcept override final;

	Process::ModuleInformationA getModuleInfo_x86(const std::string& modName) noexcept override final;
	Process::ModuleInformationA getModuleInfo_x64(const std::string& modName) noexcept override final;

	QWORD scanPattern(const Process::SignatureA& signature) const noexcept override final;
	QWORD scanPattern_x86(const Process::ModuleSignatureA& signature) const noexcept override final;
	QWORD scanPattern_x64(const Process::ModuleSignatureA& signature) const noexcept override final;

	int patternCount(const Process::SignatureA& signature) const noexcept override final;
	int patternCount_x86(const Process::ModuleSignatureA& signature) const noexcept override final;
	int patternCount_x64(const Process::ModuleSignatureA& signature) const noexcept override final;

	std::vector<Process::FoundGadgetA> findGadgets(const Process::SignatureA& signature) const noexcept override final;
	std::vector<Process::FoundGadgetA> findGadgets_x86(const Process::ModuleSignatureA& signature) const noexcept override final;
	std::vector<Process::FoundGadgetA> findGadgets_x64(const Process::ModuleSignatureA& signature) const noexcept override final;

	static bool validProcessHandle(const HANDLE handle) noexcept;
	static DWORD getHandleFlags(const HANDLE handle) noexcept;

	static Process::ProcessInformationA getProcess(const std::string& procName) noexcept;
	static Process::ProcessInformationA getProcess(const DWORD procID) noexcept;
	static Process::ProcessInformationA getProcess(const HANDLE hProc) noexcept;
	static std::vector<Process::ProcessInformationA> getProcessList() noexcept;

	BOOL RPM(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept;
	BOOL WPM(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept;

	QWORD AVM(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept;
	BOOL FVM(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept;

	BOOL PVM(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept;
	SIZE_T QVM(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept;

	BOOL QIP(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept;

#ifndef _WIN64
	BOOL QIP_Wow64(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept;
#endif

	template <typename T>
	T RPM(const QWORD readAddr) const noexcept
	{

		T buffer{};

		if (!readAddr)
			return buffer;

#ifdef _WIN64
		ReadProcessMemory(m_hProc, reinterpret_cast<void*>(readAddr), &buffer, sizeof(buffer), nullptr);
		return buffer;
#else
		return RPM_Wow64<T>(readAddr);
#endif
	}

	template <typename T>
	BOOL WPM(const QWORD writeAddr, const T& value) const noexcept
	{
		if (!writeAddr)
			return FALSE;

#ifdef _WIN64
		return WriteProcessMemory(m_hProc, reinterpret_cast<void*>(writeAddr), &value, sizeof(value), nullptr);
#else
		return WPM_Wow64<T>(writeAddr, value);
#endif	
	}

};


class ExtProcessW : public IProcessW
{
private:

	DWORD m_handleFlags{};
	bool m_attached{ false };

	bool m_closeHandleOnDetach{ false };
	bool m_reattachByName{ false };


	bool updateModuleInfo_x86() noexcept override final;
	bool updateModuleInfo_x64() noexcept override final;

#ifndef _WIN64

	BOOL RPM_Wow64(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept;
	BOOL WPM_Wow64(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept;

	QWORD AVM_Wow64(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept;
	BOOL FVM_Wow64(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept;

	BOOL PVM_Wow64(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept;
	SIZE_T QVM_Wow64(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept;

	template <typename T>
	T RPM_Wow64(const QWORD readAddr) const noexcept
	{
		T buffer{};

		if (!readAddr)
			return buffer;

		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64"));
			return buffer;
		}

		_NtWow64RVM(m_hProc, readAddr, &buffer, sizeof(buffer), nullptr);

		return buffer;
	}

	template <typename T>
	BOOL WPM_Wow64(const QWORD writeAddr, const T& value) const noexcept
	{
		if (!writeAddr)
			return FALSE;

		static tNtWow64WriteVirtualMemory64 _NtWow64WVM{ reinterpret_cast<tNtWow64WriteVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64WriteVirtualMemory64")) };

		if (!_NtWow64WVM)
		{
			_NtWow64WVM = reinterpret_cast<tNtWow64WriteVirtualMemory64>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64WriteVirtualMemory64"));
			return FALSE;
		}

		return static_cast<BOOL>(_NtWow64WVM(m_hProc, writeAddr, &value, sizeof(value), nullptr) == STATUS_SUCCESS);
	}

#endif

	ExtProcessW(const ExtProcessW&) {}
	void operator=(const ExtProcessW&) {}

public:

	ExtProcessW() noexcept;
	ExtProcessW(const std::wstring& procName, const DWORD handleFlags = PROCESS_ALL_ACCESS) noexcept;
	ExtProcessW(const DWORD procID, const DWORD handleFlags = PROCESS_ALL_ACCESS) noexcept;
	ExtProcessW(const HANDLE duplicatedHandle, bool reattachByName = false, bool closeHandleOnDetach = false) noexcept;
	virtual ~ExtProcessW();

	bool attach(const std::wstring& procName) noexcept;
	bool attach(const DWORD procID) noexcept;
	bool attach(const HANDLE hProc, bool reattachByName = false, bool closeHandleOnDetach = false) noexcept;
	bool detach() noexcept;
	bool reattach() noexcept;

	bool updateProcessInfo() noexcept override final;
	bool updateModuleInfo() noexcept override final;

	DWORD getHandleFlags() const noexcept { return m_handleFlags; }

	bool isAttached() const noexcept { return m_attached; }

	QWORD getPEBAddress_x86() const noexcept override final;
	QWORD getPEBAddress_x64() const noexcept override final;

	Process::ModuleInformationW getModuleInfo_x86(const std::wstring& modName) const noexcept override final;
	Process::ModuleInformationW getModuleInfo_x64(const std::wstring& modName) const noexcept override final;

	QWORD getProcAddress_x86(const QWORD modBA, const std::wstring& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const QWORD modBA, const std::wstring& functionName) const noexcept override final;

	QWORD getProcAddress_x86(const std::wstring modName, const std::wstring& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const std::wstring modName, const std::wstring& functionName) const noexcept override final;
																   
	Process::ModuleInformationW getModuleInfo_x86(const std::wstring& modName) noexcept override final;
	Process::ModuleInformationW getModuleInfo_x64(const std::wstring& modName) noexcept override final;

	QWORD scanPattern(const Process::SignatureW& signature) const noexcept override final;
	QWORD scanPattern_x86(const Process::ModuleSignatureW& signature) const noexcept override final;
	QWORD scanPattern_x64(const Process::ModuleSignatureW& signature) const noexcept override final;

	int patternCount(const Process::SignatureW& signature) const noexcept override final;
	int patternCount_x86(const Process::ModuleSignatureW& signature) const noexcept override final;
	int patternCount_x64(const Process::ModuleSignatureW& signature) const noexcept override final;

	std::vector<Process::FoundGadgetW> findGadgets(const Process::SignatureW& signature) const noexcept override final;
	std::vector<Process::FoundGadgetW> findGadgets_x86(const Process::ModuleSignatureW& signature) const noexcept override final;
	std::vector<Process::FoundGadgetW> findGadgets_x64(const Process::ModuleSignatureW& signature) const noexcept override final;

	static bool validProcessHandle(const HANDLE handle) noexcept;
	static DWORD getHandleFlags(const HANDLE handle) noexcept;

	static Process::ProcessInformationW getProcess(const std::wstring& procName) noexcept;
	static Process::ProcessInformationW getProcess(const DWORD procID) noexcept;
	static Process::ProcessInformationW getProcess(const HANDLE hProc) noexcept;
	static std::vector<Process::ProcessInformationW> getProcessList() noexcept;

	BOOL RPM(const QWORD readAddr, void* const pBuffer, const QWORD size, QWORD* const pBytesRead) const noexcept;
	BOOL WPM(const QWORD writeAddr, const void* const pBuffer, const QWORD size, QWORD* const pBytesWritten) const noexcept;

	QWORD AVM(const QWORD allocAddr, const QWORD size, const DWORD allocType, const DWORD protectionFlags) const noexcept;
	BOOL FVM(const QWORD freeAddr, const QWORD size, const DWORD freeType) const noexcept;

	BOOL PVM(const QWORD protectAddr, const QWORD protectLength, const DWORD protectFlags, DWORD* const pOldProtect) const noexcept;
	SIZE_T QVM(const QWORD baseAddr, MEMORY_BASIC_INFORMATION64* const pMBI) const noexcept;

	BOOL QIP(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept;

#ifndef _WIN64
	BOOL QIP_Wow64(const PROCESSINFOCLASS processInfoClass, void* const pProcessInfo, const DWORD size, QWORD* const pReturnLength) const noexcept;
#endif

	template <typename T>
	T RPM(const QWORD readAddr) const noexcept
	{

		T buffer{};

		if (!readAddr)
			return buffer;

#ifdef _WIN64
		ReadProcessMemory(m_hProc, reinterpret_cast<void*>(readAddr), &buffer, sizeof(buffer), nullptr);
		return buffer;
#else
		return RPM_Wow64<T>(readAddr);
#endif
	}

	template <typename T>
	BOOL WPM(const QWORD writeAddr, const T& value) const noexcept
	{
		if (!writeAddr)
			return FALSE;

#ifdef _WIN64
		return WriteProcessMemory(m_hProc, reinterpret_cast<void*>(writeAddr), &value, sizeof(value), nullptr);
#else
		return WPM_Wow64<T>(writeAddr, value);
#endif	
	}

};