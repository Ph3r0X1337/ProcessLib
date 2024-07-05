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

	template <class T>
	struct Signature
	{
		T sigName{};
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

	template <class T>
	struct FoundGadget
	{
		T moduleName{};
		std::vector<SigByte> pattern{};
		std::vector<BYTE> bytes{};
		QWORD absoluteAddress{};
		DWORD relativeAdddress{};
		bool readable{ false };
		bool writable{ false };
	};

	using FoundGadgetA = FoundGadget<std::string>;
	using FoundGadgetW = FoundGadget<std::wstring>;

	template <class T>
	struct ModuleExport
	{
		T moduleName{};
		T exportName{};
		QWORD absoluteAddress{};
		DWORD relativeAddress{};
		WORD ordinal{};
	};

	using ModuleExportA = ModuleExport<std::string>;
	using ModuleExportW = ModuleExport<std::wstring>;

	bool setDebugPrivilege() noexcept;

	std::vector<SigByte> getSigBytePattern(const std::vector<short>& pattern);

	template <typename T>
	std::vector<SigByte> getSigBytePattern(const Signature<T>& signature)
	{
		return getSigBytePattern(signature.pattern);
	}

	inline constexpr std::vector<SigByte>(*getSigBytePatternA)(const Signature<std::string>&) = getSigBytePattern<std::string>;
	inline constexpr std::vector<SigByte>(*getSigBytePatternW)(const Signature<std::wstring>&) = getSigBytePattern<std::wstring>;

	inline constexpr WORD ordinalBaseOffset{ 8 };

}
