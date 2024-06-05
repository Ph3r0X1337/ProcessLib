#pragma once

#include "ntdll.h"
#include "peb.hpp"
#include <Windows.h>
#include <string>
#include <vector>

namespace Process
{
	struct DW_TUPLE
	{
		DWORD dw1{};	// low order DWORD
		DWORD dw2{};	// high order DWORD
	};

	union AddressBuffer
	{
		QWORD x64Addr{};
		DW_TUPLE x86Addr;
	};

	struct SigByte
	{
		char patternChar{};
		char maskChar{};
	};

	template <class T>
	struct ProcessInformation
	{
		DWORD procID{};
		DWORD parentProcID{};
		T procName{};
		DWORD threadCount{};
		LONG threadBasePriority{};
		bool wow64Process{ false };
	};

	using ProcessInformationA = ProcessInformation<std::string>;
	using ProcessInformationW = ProcessInformation<std::wstring>;

	/*
	struct ProcessInformationA
	{
		DWORD procID{};
		DWORD parentProcID{};
		std::string procName{};
		DWORD threadCount{};
		LONG threadBasePriority{};
		bool wow64Process{ false };
	};

	struct ProcessInformationW
	{
		DWORD procID{};
		DWORD parentProcID{};
		std::wstring procName{};
		DWORD threadCount{};
		LONG threadBasePriority{};
		bool wow64Process{ false };
	};
	*/

	template <class T>
	struct ModuleInformation
	{
		DWORD procID{};
		AddressBuffer modBA{};
		DWORD modSize{};
		T modName{};
		T procName{};
	};

	using ModuleInformationA = ModuleInformation<std::string>;
	using ModuleInformationW = ModuleInformation<std::wstring>;

	/*
	struct ModuleInformationA
	{
		DWORD procID{};
		AddressBuffer modBA{};
		DWORD modSize{};
		std::string modName{};
		std::string procName{};
	};

	struct ModuleInformationW
	{
		DWORD procID{};
		AddressBuffer modBA{};
		DWORD modSize{};
		std::wstring modName{};
		std::wstring procName{};
	};
	*/

	template <class T>
	struct Signature
	{
		T sigName{};
		//T moduleName{};
		std::vector<short> pattern{};
		std::vector<DWORD> offsets{};
		DWORD extra{};
		bool relativeAddress{ false };
		bool executable{ true };
		bool readable{ true };
		bool writable{ false };
	};

	using SignatureA = Signature<std::string>;
	using SignatureW = Signature<std::wstring>;

	template <class T>
	struct ModuleSignature : public Signature<T>
	{
		T moduleName{};
	};

	using ModuleSignatureA = ModuleSignature<std::string>;
	using ModuleSignatureW = ModuleSignature<std::wstring>;

	/*
	struct SignatureA
	{
		std::string sigName{};
		std::string moduleName{};
		std::vector<int> pattern{};
		std::vector<DWORD> offsets{};
		DWORD extra{};
		bool relativeAddress{ false };
	};

	struct SignatureW
	{
		std::wstring sigName{};
		std::wstring moduleName{};
		std::vector<int> pattern{};
		std::vector<DWORD> offsets{};
		DWORD extra{};
		bool relativeAddress{ false };
	};
	*/

	template <class T>
	struct FoundGadget
	{
		T moduleName{};
		std::vector<SigByte> pattern{};
		std::vector<char> bytes{};
		QWORD absoluteAddress{};
		DWORD relativeAdddress{};
		bool readable{ false };
		bool writable{ false };
	};

	using FoundGadgetA = FoundGadget<std::string>;
	using FoundGadgetW = FoundGadget<std::wstring>;

	/*
	struct FoundGadgetA
	{
		std::string moduleName{};
		std::vector<SigByte> pattern{};
		std::vector<char> bytes{};
		QWORD absoluteAddress{};
		DWORD relativeAdddress{};
		bool readable{ false };
		bool writable{ false };
	};

	struct FoundGadgetW
	{
		std::wstring moduleName{};
		std::vector<SigByte> pattern{};
		std::vector<char> bytes{};
		QWORD absoluteAddress{};
		DWORD relativeAdddress{};
		bool readable{ false };
		bool writable{ false };
	};
	*/

	bool setDebugPrivilege() noexcept;

	template <typename T>
	std::vector<SigByte> getSigBytePattern(const Signature<T>& signature)
	{
		std::vector<SigByte> result{};

		for (const short currByte : signature.pattern)
		{
			if (currByte < 0 || currByte > 0xFF)
			{
				result.push_back({ static_cast<char>(0x0), '?' });
			}
			else
			{
				result.push_back({ static_cast<char>(currByte), 'x' });
			}
		}

		return result;
	}

	inline constexpr std::vector<SigByte>(*getSigBytePatternA)(const Signature<std::string>&) = getSigBytePattern<std::string>;
	inline constexpr std::vector<SigByte>(*getSigBytePatternW)(const Signature<std::wstring>&) = getSigBytePattern<std::wstring>;

}
