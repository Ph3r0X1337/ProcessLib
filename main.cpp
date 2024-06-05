#include <iostream>
#include "Process.hpp"

int main()
{
	LocalProcessW& localProc{ LocalProcessW::getInstance() };

	std::cout << "32-bit PEB address: 0x" << std::hex << localProc.getPEBAddress_x86() << '\n';
	std::cout << "64-bit PEB address: 0x" << std::hex << localProc.getPEBAddress_x64() << '\n';

#ifndef _WIN64

	std::cout << "NtQuerySystemInformation 32-bit: 0x" << std::hex << localProc.getNativeProcAddress(L"NtQuerySystemInformation") << '\n';
	std::cout << "NtQuerySystemInformation 64-bit: 0x" << std::hex << localProc.getNativeProcAddressWow64(L"NtQuerySystemInformation") << '\n';

#endif

	Process::ModuleSignatureW mySig{};
	mySig.executable = true;
	mySig.readable = true;
	mySig.writable = false;
	mySig.relativeAddress = false;
	mySig.extra = 0;
	mySig.moduleName = L"ntdll.dll";
	mySig.offsets = {};
	mySig.pattern = { 0x8B, 0xE5, 0x5D, 0xC3 };
	mySig.sigName = L"callGadget";

	std::wcout << "Trying to find signature: " << mySig.sigName << " in: " << mySig.moduleName << '\n';

	const QWORD found{ localProc.scanPattern(mySig) };

	if (found)
		std::cout << "Signature was found: 0x" << std::hex << found << '\n';
	else
		std::cout << "Couldn't find the signature!\n";

	std::wcout << "Trying to find signature: " << mySig.sigName << " in process: " << localProc.getProcessName() << '\n';

	Process::SignatureW mySig2{ static_cast<Process::SignatureW>(mySig) };

	const QWORD found2{ localProc.scanPattern(mySig2) };
	
	std::cout << "Signature count in process: " << std::dec << localProc.patternCount(mySig2) << '\n';

	if (found2)
		std::cout << "Signature was found: 0x" << std::hex << found2 << '\n';
	else
		std::cout << "Couldn't find the signature!\n";

	localProc.updateProcessInfo();
	localProc.updateModuleInfo();

	std::vector<Process::ProcessInformationW> procList{ ExtProcessW::getProcessList() };
	std::cout << "Number of active processes: " << std::dec << procList.size() << '\n';

	ExtProcessA myProc{ "processd86.exe" };
	Process::ProcessInformationW myProc2{ ExtProcessW::getProcess(L"processd86.exe") };

	getchar();

	return 0;
}