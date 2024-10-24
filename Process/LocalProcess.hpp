#pragma once

#define USE_UNORDERED_MAP

#include "IProcess.hpp"

#ifdef USE_UNORDERED_MAP
#include <unordered_map>
#else
#include <map>
#endif

namespace LocalProcess
{
	/*
	enum class InitState
	{
		uninitialized,
		initializing,
		initialized
	};
	*/

	enum class SCROPGadgetType : DWORD
	{
		jmp_rbx = 0,
		jmp_rbx_ptr = 1,
		jmp_rdi = 2,
		jmp_rdi_ptr = 3,
		jmp_rsi = 4,
		jmp_rsi_ptr = 5
	};

	struct PROCESS_INSTRUMENTATION_CALLBACK
	{
		DWORD version{};
		DWORD reserved{};
		QWORD callbackAddr{};
	};

	/*
	struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL CONTEXT64
	{
		DWORD64 P1Home;         //0x000
		DWORD64 P2Home;         //0x008
		DWORD64 P3Home;         //0x010
		DWORD64 P4Home;         //0x018
		DWORD64 P5Home;         //0x020
		DWORD64 P6Home;         //0x028

		DWORD ContextFlags;     //0x030
		DWORD MxCsr;            //0x034

		WORD   SegCs;           //0x038
		WORD   SegDs;           //0x03A
		WORD   SegEs;           //0x03C
		WORD   SegFs;           //0x03E
		WORD   SegGs;           //0x040
		WORD   SegSs;           //0x042
		DWORD EFlags;           //0x044

		DWORD64 Dr0;
		DWORD64 Dr1;
		DWORD64 Dr2;
		DWORD64 Dr3;
		DWORD64 Dr6;
		DWORD64 Dr7;

		DWORD64 Rax;
		DWORD64 Rcx;
		DWORD64 Rdx;
		DWORD64 Rbx;
		DWORD64 Rsp;
		DWORD64 Rbp;
		DWORD64 Rsi;
		DWORD64 Rdi;
		DWORD64 R8;
		DWORD64 R9;
		DWORD64 R10;
		DWORD64 R11;
		DWORD64 R12;
		DWORD64 R13;
		DWORD64 R14;
		DWORD64 R15;

		DWORD64 Rip;

		union {
			//XMM_SAVE_AREA32 FltSave;
			struct {
				M128A Header[2];
				M128A Legacy[8];
				M128A Xmm0;
				M128A Xmm1;
				M128A Xmm2;
				M128A Xmm3;
				M128A Xmm4;
				M128A Xmm5;
				M128A Xmm6;
				M128A Xmm7;
				M128A Xmm8;
				M128A Xmm9;
				M128A Xmm10;
				M128A Xmm11;
				M128A Xmm12;
				M128A Xmm13;
				M128A Xmm14;
				M128A Xmm15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;

		M128A VectorRegister[26];
		DWORD64 VectorControl;

		DWORD64 DebugControl;
		DWORD64 LastBranchToRip;
		DWORD64 LastBranchFromRip;
		DWORD64 LastExceptionToRip;
		DWORD64 LastExceptionFromRip;
	};
	*/

	QWORD generateSwitchToLongMode(const DWORD farJumpAddress32Bit) noexcept;

	inline const Process::ModuleSignatureA syscallSignatureA
	{
		"x64_Syscall_Sig",
		{ 0x4C, 0x8B, 0xD1, 0xB8, -1, -1, -1, -1, 0xF6, 0x04, 0x25, -1, -1, -1, -1, -1, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, -1, 0xC3 },
		{},
		0,
		false,
		true,
		true,
		false,
		"ntdll.dll"
	};

	inline const Process::ModuleSignatureW syscallSignatureW
	{
		L"x64_Syscall_Sig",
		{ 0x4C, 0x8B, 0xD1, 0xB8, -1, -1, -1, -1, 0xF6, 0x04, 0x25, -1, -1, -1, -1, -1, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, -1, 0xC3 },
		{},
		0,
		false,
		true,
		true,
		false,
		L"ntdll.dll"
	};

	inline const std::vector<short> syscallGadget{ 0x0F, 0x05, 0xC3 };

	inline const std::vector<short> jmp_rdi_gadget{ 0xFF, 0xE7 };
	inline const std::vector<short> jmp_rdi_deref_gadget{ 0xFF, 0x27 };
	inline const std::vector<short> jmp_rsi_gadget{ 0xFF, 0xE6 };
	inline const std::vector<short> jmp_rsi_deref_gadget{ 0xFF, 0x26 };
	inline const std::vector<short> jmp_rbx_gadget{ 0xFF, 0xE3 };
	inline const std::vector<short> jmp_rbx_deref_gadget{ 0xFF, 0x23 };


	namespace shellcode
	{
		inline constexpr BYTE x86_EnterStackFrame[3]
		{
			0x55,			//push ebp
			0x8B, 0xEC		//mov ebp,esp
		};

		inline constexpr BYTE x86_LeaveStackFrame[3]
		{
			0x8B, 0xE5,		//mov esp,ebp
			0x5D			//pop ebp
		};

		inline constexpr BYTE x86_64_stdcallRet[3]
		{
			0xC2, 0x00, 0x00	//ret n (n stands for a WORD value that holds parameter bytesize on stack)
		};

		inline constexpr BYTE x86_64_cdeclRet{ 0xC3 };		//pops return address from stack and jumps there

		inline constexpr BYTE getNativeModuleX64SetupCode[45]
		{
			0x48, 0x8B, 0x45, 0x08,			//mov rax,[rbp+8] -> fetch QWORD parameter from stack
			0x66, 0x81, 0xE4, 0xF0, 0xFF,	//and sp,0xFFF0 -> align stack to 16 byte border
			0x48, 0x8B, 0xC8,				//mov rcx,rax -> parameter for x64 function call -> stdcall is ignored
			0x68, 0x00, 0x00, 0x00, 0x00,	//push address of the instruction after the "manual jump" -> offset 0x0D
			0x68, 0x00, 0x00, 0x00, 0x00,	//manual jump to function, push function address and "ret" to that address -> offset 0x12
			0xC3,
			0x48, 0x8B, 0xC8,				//mov rcx,rax -> temporarily store return value in rcx -> offset 0x17
			0x48, 0xC1, 0xE8, 0x20,			//shr rax -> store high order DWORD in rax
			0x8B, 0xD0,						//mov edx,eax -> move high order DWORD to edx
			0x8B, 0xC1,						//mov eax,ecx -> move low order DWORD to eax
			0x68, 0x00, 0x00, 0x00, 0x00,	//push 32 bit address after retf -> offset 0x23
			0x83, 0x44, 0x24, 0x04, 0x23,	//add dword ptr [rsp+4],23 -> put segment value in high order DWORD
			0xCB							//retf -> far return
		};

		inline constexpr BYTE getNativeModuleX64Shellcode[218]
		{
			0x48, 0x83, 0xEC, 0x38, 0x45, 0x33, 0xD2, 0x48, 0x85, 0xC9, 0x0F, 0x84,
			0xC3, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x18, 0x48, 0x85, 0xC0, 0x0F,
			0x84, 0xB6, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x58, 0x10, 0xBA, 0x6C, 0x00,
			0x00, 0x00, 0xC7, 0x44, 0x24, 0x10, 0x6E, 0x00, 0x74, 0x00, 0xC7, 0x44,
			0x24, 0x14, 0x64, 0x00, 0x6C, 0x00, 0xC7, 0x44, 0x24, 0x18, 0x6C, 0x00,
			0x2E, 0x00, 0xC7, 0x44, 0x24, 0x1C, 0x64, 0x00, 0x6C, 0x00, 0x66, 0x89,
			0x54, 0x24, 0x20, 0x4D, 0x85, 0xDB, 0x74, 0x5E, 0x48, 0x89, 0x5C, 0x24,
			0x30, 0x4D, 0x8B, 0xCB, 0xBB, 0x12, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x00,
			0x41, 0x0F, 0x10, 0x41, 0x58, 0x66, 0x0F, 0x7E, 0xC0, 0x0F, 0x11, 0x04,
			0x24, 0x66, 0x3B, 0xD8, 0x77, 0x49, 0x4C, 0x8B, 0x44, 0x24, 0x08, 0x48,
			0x8D, 0x4C, 0x24, 0x10, 0x4C, 0x2B, 0xC1, 0x48, 0x8D, 0x44, 0x24, 0x10,
			0x41, 0x8B, 0xD2, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x41, 0x0F, 0xB7, 0x0C, 0x00, 0x66, 0x39, 0x08, 0x75, 0x1C, 0xFF, 0xC2,
			0x48, 0x83, 0xC0, 0x02, 0x83, 0xFA, 0x09, 0x72, 0xEB, 0x4D, 0x8B, 0x51,
			0x30, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x49, 0x8B, 0xC2, 0x48, 0x83, 0xC4,
			0x38, 0xC3, 0x4D, 0x39, 0x19, 0x74, 0xEE, 0x49, 0x8B, 0x01, 0x4C, 0x8B,
			0xC8, 0x48, 0x85, 0xC0, 0x75, 0x9A, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x49,
			0x8B, 0xC2, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0x33, 0xC0, 0x48, 0x83, 0xC4,
			0x38, 0xC3
		};

		inline constexpr BYTE getNativeProcAddressX64SetupCode[52]
		{
			0x48, 0x8B, 0x45, 0x08,			//mov rax,[rbp+8] -> fetch first QWORD parameter from stack
			0x48, 0x8B, 0xC8,				//mov rcx,rax -> parameter for x64 function call -> stdcall is ignored
			0x48, 0x8B, 0x45, 0x10,			//mov rax,[rbp+16] -> fetch second QWORD parameter from stack
			0x48, 0x8B, 0xD0,				//mov rdx,rax -> parameter for x64 function call -> stdcall is ignored
			0x66, 0x81, 0xE4, 0xF0, 0xFF,	//and sp,0xFFF0 -> align stack to 16 byte border
			0x68, 0x00, 0x00, 0x00, 0x00,	//push address of the instruction after the "manual jump" -> offset 0x14
			0x68, 0x00, 0x00, 0x00, 0x00,	//manual jump to function, push function address and "ret" to that address -> offset 0x19
			0xC3,
			0x48, 0x8B, 0xC8,				//mov rcx,rax -> temporarily store return value in rcx -> offset 0x1E
			0x48, 0xC1, 0xE8, 0x20,			//shr rax -> store high order DWORD in rax
			0x8B, 0xD0,						//mov edx,eax -> move high order DWORD to edx
			0x8B, 0xC1,						//mov eax,ecx -> move low order DWORD to eax
			0x68, 0x00, 0x00, 0x00, 0x00,	//push 32 bit address after retf -> offset 0x2A
			0x83, 0x44, 0x24, 0x04, 0x23,	//add dword ptr [rsp+4],23 -> put segment value in high order DWORD
			0xCB							//retf -> far return
		};

		inline constexpr BYTE getNativeProcAddressX64Shellcode[294]
		{
			0x40, 0x57, 0x48, 0x83, 0xEC, 0x38/*fix*/, 0x33, 0xFF, 0x4C, 0x8B, 0xCA, 0x4C,
			0x8B, 0xD9, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0x07, 0x01, 0x00, 0x00, 0x48,
			0x85, 0xD2, 0x0F, 0x84, 0xFE, 0x00, 0x00, 0x00, 0xB8, 0x4D, 0x5A, 0x00,
			0x00, 0x66, 0x39, 0x01, 0x0F, 0x85, 0xF0, 0x00, 0x00, 0x00, 0x48, 0x63,
			0x41, 0x3C, 0x48, 0x03, 0xC1, 0x81, 0x38, 0x50, 0x45, 0x00, 0x00, 0x0F,
			0x85, 0xDD, 0x00, 0x00, 0x00, 0xB9, 0x0B, 0x02, 0x00, 0x00, 0x66, 0x39,
			0x48, 0x18, 0x0F, 0x85, 0xCE, 0x00, 0x00, 0x00, 0xB9, 0x64, 0x86, 0x00,
			0x00, 0x66, 0x39, 0x48, 0x04, 0x0F, 0x85, 0xBF, 0x00, 0x00, 0x00, 0xB9,
			0x00, 0x20, 0x00, 0x00, 0x66, 0x85, 0x48, 0x16, 0x0F, 0x84, 0xB0, 0x00,
			0x00, 0x00, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x44, 0x8B, 0xD7, 0x49,
			0x03, 0xC3, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x6C, 0x24, 0x28,
			0x4C, 0x89, 0x74, 0x24, 0x08, 0x4C, 0x89, 0x3C, 0x24, 0x8B, 0x58, 0x20,
			0x44, 0x8B, 0x70, 0x24, 0x49, 0x03, 0xDB, 0x44, 0x8B, 0x78, 0x1C, 0x4D,
			0x03, 0xF3, 0x8B, 0x68, 0x18, 0x4D, 0x03, 0xFB, 0x85, 0xED, 0x74, 0x5A,
			0x48, 0x89, 0x74, 0x24, 0x30, 0x0F, 0xB6, 0x32, 0x44, 0x8B, 0x03, 0x8B,
			0xD7, 0x4D, 0x03, 0xC3, 0x41, 0x3A, 0x30, 0x75, 0x15, 0x40, 0x0F, 0xB6,
			0xC6, 0x84, 0xC0, 0x74, 0x0D, 0xFF, 0xC2, 0x42, 0x0F, 0xB6, 0x04, 0x0A,
			0x42, 0x3A, 0x04, 0x02, 0x74, 0xEF, 0x8B, 0xC2, 0x42, 0x38, 0x3C, 0x08,
			0x75, 0x06, 0x42, 0x38, 0x3C, 0x00, 0x74, 0x0E, 0x41, 0xFF, 0xC2, 0x48,
			0x83, 0xC3, 0x04, 0x44, 0x3B, 0xD5, 0x72, 0xC4, 0xEB, 0x0F, 0x41, 0x8B,
			0xC2, 0x41, 0x0F, 0xB7, 0x0C, 0x46, 0x41, 0x8B, 0x3C, 0x8F, 0x49, 0x03,
			0xFB, 0x48, 0x8B, 0x74, 0x24, 0x30, 0x4C, 0x8B, 0x3C, 0x24, 0x48, 0x8B,
			0xC7, 0x4C, 0x8B, 0x74, 0x24, 0x08, 0x48, 0x8B, 0x6C, 0x24, 0x28, 0x48,
			0x8B, 0x5C, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x38/*fix*/, 0x5F, 0xC3, 0x33, 0xC0,
			0x48, 0x83, 0xC4, 0x38/*fix*/, 0x5F, 0xC3
		};

		inline constexpr BYTE callNativeFunctionX64Shellcode[203]
		{
			0x53, 0x57, 0x56, 0x55, 0x48, 0x31, 0xC0, 0x48, 0x31, 0xD2, 0x48, 0x31,
			0xFF, 0x48, 0x31, 0xF6, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x5D,
			0x08, 0x48, 0x85, 0xDB, 0x74, 0x9C, 0x8B, 0x7D, 0x14, 0x85, 0xFF, 0x74,
			0x95, 0x8B, 0x75, 0x10, 0x85, 0xF6, 0x74, 0x8E, 0x48, 0x8B, 0xEC, 0x48,
			0x31, 0xC0, 0xB8, 0x20, 0x00, 0x00, 0x00, 0x83, 0xFF, 0x04, 0x7E, 0x08,
			0x67, 0x8D, 0x04, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xC4, 0x48,
			0x31, 0xC0, 0xB0, 0x0F, 0x48, 0xF7, 0xD0, 0x48, 0x21, 0xC4, 0xC7, 0x04,
			0x24, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00,
			0x00, 0xC7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24,
			0x18, 0x00, 0x00, 0x00, 0x00, 0x83, 0xFF, 0x04, 0x7E, 0x17, 0xFF, 0xCF,
			0x67, 0x48, 0x8D, 0x04, 0xFE, 0x48, 0x8B, 0x08, 0x67, 0x48, 0x8D, 0x04,
			0xFC, 0x48, 0x89, 0x08, 0xE9, 0xE4, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x0E,
			0xFF, 0xCF, 0x85, 0xFF, 0x74, 0x1A, 0x48, 0x8B, 0x56, 0x08, 0xFF, 0xCF,
			0x85, 0xFF, 0x74, 0x10, 0x4C, 0x8B, 0x46, 0x10, 0xFF, 0xCF, 0x85, 0xFF,
			0x74, 0x06, 0x4C, 0x8B, 0x4E, 0x18, 0xFF, 0xCF, 0xFF, 0xD3, 0x48, 0x8B,
			0xD0, 0x48, 0xC1, 0xEA, 0x32, 0x48, 0x8B, 0xE5, 0x5D, 0x5E, 0x5F, 0x5B,
			0x68, 0x00, 0x00, 0x00, 0x00, 0x83, 0x44, 0x24, 0x04, 0x23, 0xCB
		};

		inline constexpr BYTE x86_64_memcpy[165]
		{
			0x4D, 0x8B, 0xD0, 0x4C, 0x8B, 0xCA, 0x4C, 0x8B, 0xD9, 0x49, 0x83, 0xF8,
			0x08, 0x72, 0x25, 0x49, 0x8B, 0xD0, 0x48, 0xC1, 0xEA, 0x03, 0x48, 0x6B,
			0xC2, 0xF8, 0x4C, 0x03, 0xD0, 0x0F, 0x1F, 0x00, 0x49, 0x8B, 0x01, 0x49,
			0x83, 0xC1, 0x08, 0x48, 0x89, 0x01, 0x48, 0x83, 0xC1, 0x08, 0x48, 0x83,
			0xEA, 0x01, 0x75, 0xEC, 0x49, 0x83, 0xFA, 0x04, 0x72, 0x29, 0x49, 0x8B,
			0xD2, 0x48, 0xC1, 0xEA, 0x02, 0x48, 0x6B, 0xC2, 0xFC, 0x4C, 0x03, 0xD0,
			0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x01, 0x49,
			0x83, 0xC1, 0x04, 0x89, 0x01, 0x48, 0x83, 0xC1, 0x04, 0x48, 0x83, 0xEA,
			0x01, 0x75, 0xED, 0x49, 0x83, 0xFA, 0x02, 0x72, 0x2C, 0x4D, 0x8B, 0xC2,
			0x49, 0xD1, 0xE8, 0x49, 0x6B, 0xC0, 0xFE, 0x4C, 0x03, 0xD0, 0x66, 0x66,
			0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xB7, 0x11,
			0x49, 0x83, 0xC1, 0x02, 0x66, 0x89, 0x11, 0x48, 0x83, 0xC1, 0x02, 0x49,
			0x83, 0xE8, 0x01, 0x75, 0xEB, 0x49, 0x8B, 0xC3, 0x49, 0x83, 0xFA, 0x01,
			0x72, 0x06, 0x41, 0x0F, 0xB6, 0x11, 0x88, 0x11, 0xC3
		};

		inline constexpr BYTE x86_64_ReadPEBFromReg[10]{ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 };

		inline constexpr BYTE x86_64_ReadByte[3]{ 0x8A, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_ReadWord[4]{ 0x66, 0x8B, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_ReadDword[3]{ 0x8B, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_ReadQword[4]{ 0x48, 0x8B, 0x01, 0xC3 };

		inline constexpr BYTE x86_64_WriteByte[14]{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x88, 0x11, 0xB0, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_WriteWord[15]{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x66, 0x89, 0x11, 0xB0, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_WriteDword[14]{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x89, 0x11, 0xB0, 0x01, 0xC3 };
		inline constexpr BYTE x86_64_WriteQword[15]{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x48, 0x89, 0x11, 0xB0, 0x01, 0xC3 };

		inline constexpr DWORD shellcodeMemorySize{ 0x10000 };
		inline constexpr DWORD offsetFunctionGetNativeModule{ 0x0 };
		inline constexpr DWORD offsetFunctionGetNativeProcAddress{ 0x400 };
		inline constexpr DWORD offsetFunctionCallNativeFunction{ 0x800 };
		inline constexpr DWORD offsetMemcpy{ 0xC00 };
		inline constexpr DWORD offsetGet64BitPEB{ 0xB00 };
		inline constexpr DWORD offsetReadByte{ offsetGet64BitPEB + sizeof(x86_64_ReadPEBFromReg) };
		inline constexpr DWORD offsetReadWord{ offsetReadByte + sizeof(x86_64_ReadByte) };
		inline constexpr DWORD offsetReadDword{ offsetReadWord + sizeof(x86_64_ReadWord) };
		inline constexpr DWORD offsetReadQword{ offsetReadDword + sizeof(x86_64_ReadDword) };
		inline constexpr DWORD offsetWriteByte{ offsetReadQword + sizeof(x86_64_ReadQword) };
		inline constexpr DWORD offsetWriteWord{ offsetWriteByte + sizeof(x86_64_WriteByte) };
		inline constexpr DWORD offsetWriteDword{ offsetWriteWord + sizeof(x86_64_WriteWord) };
		inline constexpr DWORD offsetWriteQword{ offsetWriteDword + sizeof(x86_64_WriteDword) };
		inline constexpr DWORD offsetGetNativeModule{ 0x100 };
		inline constexpr DWORD offsetGetNativeProcAddress{ 0x500 };
		inline constexpr DWORD offsetCallNativeFunction{ 0x900 };

	}
}

class LocalProcessA : public IProcessA
{
private:

#ifdef USE_UNORDERED_MAP
	using mapQ = std::unordered_map<std::string, QWORD>;
	using mapD = std::unordered_map<std::string, DWORD>;
	using map = std::unordered_map<std::string, uintptr_t>;
#else
	using mapQ = std::map<std::string, QWORD>;
	using mapD = std::map<std::string, DWORD>;
	using map = std::map<std::string, uintptr_t>;
#endif

#ifndef _WIN64

	mapQ m_nativeFunctionsWow64{};

#endif

	map m_nativeFunctions{};
	mapD m_syscallIDs{};

#ifdef _WIN64
	DWORD m_ICTlsIndex{ TLS_OUT_OF_INDEXES };
	QWORD m_addrICHandler{};
	QWORD m_addrPrevIC{};
#endif

	static LocalProcessA s_instance;

	bool updateModuleInfo_x86() noexcept override final;
	bool updateModuleInfo_x64() noexcept override final;

	bool updateSyscallIDs() noexcept;

	LocalProcessA() noexcept;
	LocalProcessA(const LocalProcessA&) {}
	void operator=(const LocalProcessA&) {}
	virtual ~LocalProcessA();

public:

	using IProcessA::scanPattern;
	using IProcessA::findGadgets;

	static LocalProcessA& getInstance() noexcept { return s_instance; }

#ifdef _WIN64
	bool installInstrumentationCallback(const QWORD callbackHandler = 0) noexcept;
	bool removeInstrumentationCallback() noexcept;
	bool setInstrumentationCallback() const noexcept;
	bool setICHandler(const QWORD callbackHandler = 0) noexcept;
	bool isInstrumentationCallbackSet() const noexcept { return m_ICTlsIndex < TLS_OUT_OF_INDEXES; }
	bool isICHandlerSet() const noexcept { return m_addrICHandler != 0; }
	static void instrumentationCallbackThunk(CONTEXT* const pContext) noexcept;
#endif

	uintptr_t getNativeProcAddress(const std::string& functionName) const noexcept;
	uintptr_t getNativeProcAddress(const std::string& functionName) noexcept;

	std::vector<std::pair<DWORD, Process::ModuleExportA>> getSyscallIDs(const bool assumeHooked = false) const noexcept;
	DWORD getSyscallID(const std::string& exportName) const noexcept;
	NTSTATUS invokeSyscall(const DWORD syscallID, const DWORD argCount, ...) const noexcept;
	NTSTATUS invokeSpoofedSyscall(const DWORD syscallID, const DWORD argCount, const LocalProcess::SCROPGadgetType ropGadgetType, const QWORD ropGadgetAddress, ...);

#ifndef _WIN64

	QWORD getNativeProcAddressWow64(const std::string& functionName) const noexcept;
	QWORD getNativeProcAddressWow64(const std::string& functionName) noexcept;

#endif

	bool updateProcessInfo() noexcept override final;
	bool updateModuleInfo() noexcept override final;

	QWORD getPEBAddress_x86() const noexcept override final;
	QWORD getPEBAddress_x64() const noexcept override final;

	Process::ModuleInformationA getModuleInfo_x86(const std::string& modName) const noexcept override final;
	Process::ModuleInformationA getModuleInfo_x64(const std::string& modName) const noexcept override final;

	std::vector<Process::ModuleExportA> getModuleExports_x86(const QWORD modBA) const noexcept override final;
	std::vector<Process::ModuleExportA> getModuleExports_x64(const QWORD modBA) const noexcept override final;

	std::vector<Process::ModuleExportA> getModuleExports_x86(const std::string& modName) const noexcept override final;
	std::vector<Process::ModuleExportA> getModuleExports_x64(const std::string& modName) const noexcept override final;

	QWORD getProcAddress_x86(const QWORD modBA, const std::string& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const QWORD modBA, const std::string& functionName) const noexcept	override final;

	QWORD getProcAddress_x86(const std::string& modName, const std::string& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const std::string& modName, const std::string& functionName) const noexcept	override final;

	Process::ModuleInformationA getModuleInfo_x86(const std::string& modName) noexcept override final;
	Process::ModuleInformationA getModuleInfo_x64(const std::string& modName) noexcept override final;

	QWORD scanPattern(const Process::SignatureA& signature) const noexcept override final;
	QWORD scanPattern_x86(const Process::ModuleSignatureA& signature) const noexcept override final;
	QWORD scanPattern_x64(const Process::ModuleSignatureA& signature) const noexcept override final;

	std::vector<Process::FoundGadgetA> findGadgets(const Process::SignatureA& signature) const noexcept override final;
	std::vector<Process::FoundGadgetA> findGadgets(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept override final;
	std::vector<Process::FoundGadgetA> findGadgets_x86(const Process::ModuleSignatureA& signature) const noexcept override final;
	std::vector<Process::FoundGadgetA> findGadgets_x64(const Process::ModuleSignatureA& signature) const noexcept override final;

#ifndef _WIN64

	BOOL callNativeFunction(const std::string& funcName, const DWORD argCount, ...) const noexcept;
	BOOL callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept;

	QWORD call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept;
	QWORD call64BitFunction(const QWORD funcAddr) const noexcept { return call64BitFunction(funcAddr, 1, 0); }
	QWORD call64BitFunction(const QWORD funcAddr, const QWORD argument) const noexcept { return call64BitFunction(funcAddr, 1, argument); }

	BYTE readByte64Bit(const QWORD address) const noexcept;
	WORD readWord64Bit(const QWORD address) const noexcept;
	DWORD readDword64Bit(const QWORD address) const noexcept;
	QWORD readQword64Bit(const QWORD address) const noexcept;

	bool writeByte64Bit(const QWORD address, const BYTE value) const noexcept;
	bool writeWord64Bit(const QWORD address, const WORD value) const noexcept;
	bool writeDword64Bit(const QWORD address, const DWORD value) const noexcept;
	bool writeQword64Bit(const QWORD address, const QWORD value) const noexcept;

	QWORD memcpy64Bit(const QWORD pDst, const QWORD pSrc, const QWORD size) const noexcept;

#endif

};


class LocalProcessW : public IProcessW
{
private:

#ifdef USE_UNORDERED_MAP
	using mapQ = std::unordered_map<std::wstring, QWORD>;
	using mapD = std::unordered_map<std::wstring, DWORD>;
	using map = std::unordered_map<std::wstring, uintptr_t>;
#else
	using mapQ = std::map<std::wstring, QWORD>;
	using mapD = std::map<std::wstring, DWORD>;
	using map = std::map<std::wstring, uintptr_t>;
#endif

#ifndef _WIN64

	mapQ m_nativeFunctionsWow64{};

#endif

	map m_nativeFunctions{};
	mapD m_syscallIDs{};

#ifdef _WIN64
	DWORD m_ICTlsIndex{ TLS_OUT_OF_INDEXES };
	QWORD m_addrICHandler{};
	QWORD m_addrPrevIC{};
#endif

	static LocalProcessW s_instance;

	bool updateModuleInfo_x86() noexcept override final;
	bool updateModuleInfo_x64() noexcept override final;

	bool updateSyscallIDs() noexcept;

	LocalProcessW() noexcept;
	LocalProcessW(const LocalProcessW&) {}
	void operator=(const LocalProcessW&) {}
	virtual ~LocalProcessW();

public:

	using IProcessW::scanPattern;
	using IProcessW::findGadgets;

	static LocalProcessW& getInstance() noexcept { return s_instance; }

#ifdef _WIN64
	bool installInstrumentationCallback(const QWORD callbackHandler = 0) noexcept;
	bool removeInstrumentationCallback() noexcept;
	bool setInstrumentationCallback() const noexcept;
	bool setICHandler(const QWORD callbackHandler = 0) noexcept;
	bool isInstrumentationCallbackSet() const noexcept { return m_ICTlsIndex < TLS_OUT_OF_INDEXES; }
	bool isICHandlerSet() const noexcept { return m_addrICHandler != 0; }
	static void instrumentationCallbackThunk(CONTEXT* const pContext) noexcept;
#endif

	uintptr_t getNativeProcAddress(const std::wstring& functionName) const noexcept;
	uintptr_t getNativeProcAddress(const std::wstring& functionName) noexcept;

	std::vector<std::pair<DWORD, Process::ModuleExportW>> getSyscallIDs(const bool assumeHooked = false) const noexcept;
	DWORD getSyscallID(const std::wstring& exportName) const noexcept;
	NTSTATUS invokeSyscall(const DWORD syscallID, const DWORD argCount, ...) const noexcept;
	NTSTATUS invokeSpoofedSyscall(const DWORD syscallID, const DWORD argCount, const LocalProcess::SCROPGadgetType ropGadgetType, const QWORD ropGadgetAddress, ...);

#ifndef _WIN64

	QWORD getNativeProcAddressWow64(const std::wstring& functionName) const noexcept;
	QWORD getNativeProcAddressWow64(const std::wstring& functionName) noexcept;

#endif

	bool updateProcessInfo() noexcept override final;
	bool updateModuleInfo() noexcept override final;

	QWORD getPEBAddress_x86() const noexcept override final;
	QWORD getPEBAddress_x64() const noexcept override final;

	Process::ModuleInformationW getModuleInfo_x86(const std::wstring& modName) const noexcept override final;
	Process::ModuleInformationW getModuleInfo_x64(const std::wstring& modName) const noexcept override final;

	std::vector<Process::ModuleExportW> getModuleExports_x86(const QWORD modBA) const noexcept override final;
	std::vector<Process::ModuleExportW> getModuleExports_x64(const QWORD modBA) const noexcept override final;

	std::vector<Process::ModuleExportW> getModuleExports_x86(const std::wstring& modName) const noexcept override final;
	std::vector<Process::ModuleExportW> getModuleExports_x64(const std::wstring& modName) const noexcept override final;

	QWORD getProcAddress_x86(const QWORD modBA, const std::wstring& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const QWORD modBA, const std::wstring& functionName) const noexcept override final;

	QWORD getProcAddress_x86(const std::wstring& modName, const std::wstring& functionName) const noexcept override final;
	QWORD getProcAddress_x64(const std::wstring& modName, const std::wstring& functionName) const noexcept	override final;

	Process::ModuleInformationW getModuleInfo_x86(const std::wstring& modName) noexcept override final;
	Process::ModuleInformationW getModuleInfo_x64(const std::wstring& modName) noexcept override final;

	QWORD scanPattern(const Process::SignatureW& signature) const noexcept override final;
	QWORD scanPattern_x86(const Process::ModuleSignatureW& signature) const noexcept override final;
	QWORD scanPattern_x64(const Process::ModuleSignatureW& signature) const noexcept override final;

	std::vector<Process::FoundGadgetW> findGadgets(const Process::SignatureW& signature) const noexcept override final;
	std::vector<Process::FoundGadgetW> findGadgets(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept override final;
	std::vector<Process::FoundGadgetW> findGadgets_x86(const Process::ModuleSignatureW& signature) const noexcept override final;
	std::vector<Process::FoundGadgetW> findGadgets_x64(const Process::ModuleSignatureW& signature) const noexcept override final;

#ifndef _WIN64

	BOOL callNativeFunction(const std::wstring& funcName, const DWORD argCount, ...) const noexcept;
	BOOL callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept;

	QWORD call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept;
	QWORD call64BitFunction(const QWORD funcAddr) const noexcept { return call64BitFunction(funcAddr, 1, 0); }
	QWORD call64BitFunction(const QWORD funcAddr, const QWORD argument) const noexcept { return call64BitFunction(funcAddr, 1, argument); }

	BYTE readByte64Bit(const QWORD address) const noexcept;
	WORD readWord64Bit(const QWORD address) const noexcept;
	DWORD readDword64Bit(const QWORD address) const noexcept;
	QWORD readQword64Bit(const QWORD address) const noexcept;

	bool writeByte64Bit(const QWORD address, const BYTE value) const noexcept;
	bool writeWord64Bit(const QWORD address, const WORD value) const noexcept;
	bool writeDword64Bit(const QWORD address, const DWORD value) const noexcept;
	bool writeQword64Bit(const QWORD address, const QWORD value) const noexcept;

	QWORD memcpy64Bit(const QWORD pDst, const QWORD pSrc, const QWORD size) const noexcept;

#endif

};