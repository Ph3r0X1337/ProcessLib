#include "LocalProcess.hpp"
#include <algorithm>
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


#pragma section(".text")	//#pragma section(".text", read, execute) -> Use this from now on

extern const unsigned char x86_64_Call32BitICThunkA[];
extern const unsigned char x86_64_Call32BitICThunkW[];

// BYTE readByte_x64(QWORD readAddr) -> 3
__declspec(allocate(".text")) const unsigned char x86_64_ReadByte[]
{ 0x8A, 0x01, 0xC3 };

// WORD readWord_x64(QWORD readAddr) -> 4
__declspec(allocate(".text")) const unsigned char x86_64_ReadWord[]
{ 0x66, 0x8B, 0x01, 0xC3 };

// DWORD readDword_x64(QWORD readAddr) -> 3
__declspec(allocate(".text")) const unsigned char x86_64_ReadDword[]
{ 0x8B, 0x01, 0xC3 };

// QWORD readWord_x64(QWORD readAddr) -> 4
__declspec(allocate(".text")) const unsigned char x86_64_ReadQword[]
{ 0x48, 0x8B, 0x01, 0xC3 };

// bool writeByte_x64(QWORD readAddr, (QWORD)BYTE value) -> 14
__declspec(allocate(".text")) const unsigned char x86_64_WriteByte[]
{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x88, 0x11, 0xB0, 0x01, 0xC3 };

// bool writeWord_x64(QWORD readAddr, (QWORD)WORD value) -> 15
__declspec(allocate(".text")) const unsigned char x86_64_WriteWord[]
{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x66, 0x89, 0x11, 0xB0, 0x01, 0xC3 };

// bool writeDword_x64(QWORD readAddr, (QWORD)DWORD value) -> 14
__declspec(allocate(".text")) const unsigned char x86_64_WriteDword[]
{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x89, 0x11, 0xB0, 0x01, 0xC3 };

// bool writeQword_x64(QWORD readAddr, QWORD value) -> 15
__declspec(allocate(".text")) const unsigned char x86_64_WriteQword[]
{ 0x48, 0x31, 0xC0, 0x48, 0x85, 0xC9, 0x75, 0x01, 0xC3, 0x48, 0x89, 0x11, 0xB0, 0x01, 0xC3 };

// QWORD getPEB_x64() -> 10
__declspec(allocate(".text")) const unsigned char x86_64_ReadPEBFromReg[]
{ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 };

// Instrumentation Callback Assembly Bridge
__declspec(allocate(".text")) const unsigned char x86_64_ICBridgeA[]
{ 
	0x55,											// push rbp				
	0x48, 0x89, 0xE5,								// mov rbp,rsp

	0x9C, 											// pushfq					

	0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00,		// sub rsp,0x4D0				
	0x48, 0x83, 0xE4, 0xF0,							// and rsp,-0x10				

	0x48, 0x89, 0x44, 0x24, 0x78,					// mov qword ptr[rsp + 0x78],rax		
	0x48, 0x89, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x80],rcx		
	0x48, 0x89, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x88],rdx		
	0x48, 0x89, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x90],rbx		
	0x48, 0x8D, 0x45, 0x08,							// lea rax,[rbp + 0x08]			
	0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x98],rax		
	0x48, 0x8B, 0x45, 0x00,							// mov rax,qword ptr[rbp + 0x00]		
	0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xA0],rax		
	0x48, 0x89, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xA8],rsi		
	0x48, 0x89, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xB0],rdi		
	0x4C, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xB8],r8		
	0x4C, 0x89, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xC0],r9		
	0x4C, 0x89, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xC8],r10		
	0x4C, 0x89, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xD0],r11		
	0x4C, 0x89, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xD8],r12		
	0x4C, 0x89, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xE0],r13		
	0x4C, 0x89, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xE8],r14		
	0x4C, 0x89, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xF0],r15		
	0x4C, 0x89, 0x94, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xF8],r10		

	0x0F, 0xAE, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00,	// fxsave[rsp + 0x100]			

	0x8C, 0x4C, 0x24, 0x38,							// mov word ptr[rsp + 0x38],cs		
	0x8C, 0x5C, 0x24, 0x3A,							// mov word ptr[rsp + 0x3A],ds		
	0x8C, 0x44, 0x24, 0x3C,							// mov word ptr[rsp + 0x3C],es		
	0x8C, 0x64, 0x24, 0x3E,							// mov word ptr[rsp + 0x3E],fs		
	0x8C, 0x6C, 0x24, 0x40,							// mov word ptr[rsp + 0x40],gs		
	0x8C, 0x54, 0x24, 0x42,							// mov word ptr[rsp + 0x42],ss		

	0x0F, 0xAE, 0x5C, 0x24, 0x34,					// stmxcsr dword ptr[rsp + 0x34]		

	0x8B, 0x45, 0xF8,								// mov eax,dword ptr[rbp - 0x08]		
	0x89, 0x44, 0x24, 0x44,							// mov dword ptr[rsp + 0x44],eax		
	0xC7, 0x44, 0x24, 0x30, 0x0F, 0x00, 0x10, 0x00,	// mov dword ptr[rsp + 0x30],0x10000F	

	0x48, 0x89, 0xE1,											// mov rcx,rsp				

	0x48, 0x83, 0xEC, 0x20,										// sub rsp,0x20				
	
	0xE8, 0x00, 0x00, 0x00, 0x00,								// call 0x???????? -> index 217

	0x48, 0x83, 0xC4, 0x20,							// add rsp,0x20				

	0x48, 0x8B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov rax,qword ptr[rsp + 0xF8]		
	0x48, 0x89, 0x45, 0x00,							// mov qword ptr[rbp + 0x00],rax		
	0x48, 0x8B, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,	// mov rax,qword ptr[rsp + 0xA0]		
	0x48, 0x89, 0x45, 0xF8,							// mov qword ptr[rbp - 0x08],rax		

	0x0F, 0xAE, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00,	// fxrstor [rsp + 0x100]			
	0x0F, 0xAE, 0x54, 0x24, 0x34,					// ldmxcsr dword ptr[rsp + 0x34]		
	
	0x8E, 0x5C, 0x24, 0x3A,							// mov ds,word ptr[rsp + 0x3A]		
	0x8E, 0x44, 0x24, 0x3C,							// mov es,word ptr[rsp + 0x3C]		
	0x8E, 0x64, 0x24, 0x3E,							// mov fs,word ptr[rsp + 0x3E]		
	0x8E, 0x6C, 0x24, 0x40,							// mov gs,word ptr[rsp + 0x40]		
	0x8E, 0x54, 0x24, 0x42,							// mov ss,word ptr[rsp + 0x42]		

	0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,	// mov rcx,qword ptr[rsp + 0x80]		
	0x48, 0x8B, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,	// mov rdx,qword ptr[rsp + 0x88]		
	0x48, 0x8B, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,	// mov rbx,qword ptr[rsp + 0x90]		
	0x48, 0x8B, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,	// mov rsi,qword ptr[rsp + 0xA8]		
	0x48, 0x8B, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,	// mov rdi,qword ptr[rsp + 0xB0]		
	0x4C, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,	// mov r8,qword ptr[rsp + 0xB8]		
	0x4C, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,	// mov r9,qword ptr[rsp + 0xC0]		
	0x4C, 0x8B, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,	// mov r10,qword ptr[rsp + 0xC8]		
	0x4C, 0x8B, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,	// mov r11,qword ptr[rsp + 0xD0]		
	0x4C, 0x8B, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,	// mov r12,qword ptr[rsp + 0xD8]		
	0x4C, 0x8B, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,	// mov r13,qword ptr[rsp + 0xE0]		
	0x4C, 0x8B, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,	// mov r14,qword ptr[rsp + 0xE8]		
	0x4C, 0x8B, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,	// mov r15,qword ptr[rsp + 0xF0]		
	0x4C, 0x8B, 0x94, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov r10,qword ptr[rsp + 0xF8]		

	0x48, 0x8B, 0x45, 0xF8,							// mov rax,qword ptr[rbp - 0x08]
	0x8B, 0x44, 0x24, 0x44,							// mov eax,dword ptr[rsp + 0x44]
	0x50,											// push rax				
	0x9D,											// popfq					

	0x48, 0x8B, 0x44, 0x24, 0x78,					// mov rax,qword ptr[rsp + 0x78]		

	0x48, 0x8D, 0x65, 0xF8,							// lea rsp,[rbp - 0x08]			
	0x5D,											// pop rbp					
	0xC3											// retn					
};

// Instrumentation Callback Assembly Bridge
__declspec(allocate(".text")) const unsigned char x86_64_ICBridgeW[]
{
	0x55,											// push rbp				
	0x48, 0x89, 0xE5,								// mov rbp,rsp

	0x9C, 											// pushfq					

	0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00,		// sub rsp,0x4D0				
	0x48, 0x83, 0xE4, 0xF0,							// and rsp,-0x10				

	0x48, 0x89, 0x44, 0x24, 0x78,					// mov qword ptr[rsp + 0x78],rax		
	0x48, 0x89, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x80],rcx		
	0x48, 0x89, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x88],rdx		
	0x48, 0x89, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x90],rbx		
	0x48, 0x8D, 0x45, 0x08,							// lea rax,[rbp + 0x08]			
	0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0x98],rax		
	0x48, 0x8B, 0x45, 0x00,							// mov rax,qword ptr[rbp + 0x00]		
	0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xA0],rax		
	0x48, 0x89, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xA8],rsi		
	0x48, 0x89, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xB0],rdi		
	0x4C, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xB8],r8		
	0x4C, 0x89, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xC0],r9		
	0x4C, 0x89, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xC8],r10		
	0x4C, 0x89, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xD0],r11		
	0x4C, 0x89, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xD8],r12		
	0x4C, 0x89, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xE0],r13		
	0x4C, 0x89, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xE8],r14		
	0x4C, 0x89, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xF0],r15		
	0x4C, 0x89, 0x94, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov qword ptr[rsp + 0xF8],r10		

	0x0F, 0xAE, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00,	// fxsave[rsp + 0x100]			

	0x8C, 0x4C, 0x24, 0x38,							// mov word ptr[rsp + 0x38],cs		
	0x8C, 0x5C, 0x24, 0x3A,							// mov word ptr[rsp + 0x3A],ds		
	0x8C, 0x44, 0x24, 0x3C,							// mov word ptr[rsp + 0x3C],es		
	0x8C, 0x64, 0x24, 0x3E,							// mov word ptr[rsp + 0x3E],fs		
	0x8C, 0x6C, 0x24, 0x40,							// mov word ptr[rsp + 0x40],gs		
	0x8C, 0x54, 0x24, 0x42,							// mov word ptr[rsp + 0x42],ss		

	0x0F, 0xAE, 0x5C, 0x24, 0x34,					// stmxcsr dword ptr[rsp + 0x34]		

	0x8B, 0x45, 0xF8,								// mov eax,dword ptr[rbp - 0x08]		
	0x89, 0x44, 0x24, 0x44,							// mov dword ptr[rsp + 0x44],eax		
	0xC7, 0x44, 0x24, 0x30, 0x0F, 0x00, 0x10, 0x00,	// mov dword ptr[rsp + 0x30],0x10000F	

	0x48, 0x89, 0xE1,											// mov rcx,rsp				

	0x48, 0x83, 0xEC, 0x20,										// sub rsp,0x20				
	
	0xE8, 0x00, 0x00, 0x00, 0x00,								// call 0x???????? -> index 217

	0x48, 0x83, 0xC4, 0x20,							// add rsp,0x20				

	0x48, 0x8B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov rax,qword ptr[rsp + 0xF8]		
	0x48, 0x89, 0x45, 0x00,							// mov qword ptr[rbp + 0x00],rax		
	0x48, 0x8B, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,	// mov rax,qword ptr[rsp + 0xA0]		
	0x48, 0x89, 0x45, 0xF8,							// mov qword ptr[rbp - 0x08],rax		

	0x0F, 0xAE, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00,	// fxrstor [rsp + 0x100]			
	0x0F, 0xAE, 0x54, 0x24, 0x34,					// ldmxcsr dword ptr[rsp + 0x34]		
	
	0x8E, 0x5C, 0x24, 0x3A,							// mov ds,word ptr[rsp + 0x3A]		
	0x8E, 0x44, 0x24, 0x3C,							// mov es,word ptr[rsp + 0x3C]		
	0x8E, 0x64, 0x24, 0x3E,							// mov fs,word ptr[rsp + 0x3E]		
	0x8E, 0x6C, 0x24, 0x40,							// mov gs,word ptr[rsp + 0x40]		
	0x8E, 0x54, 0x24, 0x42,							// mov ss,word ptr[rsp + 0x42]		

	0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,	// mov rcx,qword ptr[rsp + 0x80]		
	0x48, 0x8B, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,	// mov rdx,qword ptr[rsp + 0x88]		
	0x48, 0x8B, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,	// mov rbx,qword ptr[rsp + 0x90]		
	0x48, 0x8B, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,	// mov rsi,qword ptr[rsp + 0xA8]		
	0x48, 0x8B, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,	// mov rdi,qword ptr[rsp + 0xB0]		
	0x4C, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,	// mov r8,qword ptr[rsp + 0xB8]		
	0x4C, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,	// mov r9,qword ptr[rsp + 0xC0]		
	0x4C, 0x8B, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,	// mov r10,qword ptr[rsp + 0xC8]		
	0x4C, 0x8B, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,	// mov r11,qword ptr[rsp + 0xD0]		
	0x4C, 0x8B, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,	// mov r12,qword ptr[rsp + 0xD8]		
	0x4C, 0x8B, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,	// mov r13,qword ptr[rsp + 0xE0]		
	0x4C, 0x8B, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,	// mov r14,qword ptr[rsp + 0xE8]		
	0x4C, 0x8B, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,	// mov r15,qword ptr[rsp + 0xF0]		
	0x4C, 0x8B, 0x94, 0x24, 0xF8, 0x00, 0x00, 0x00,	// mov r10,qword ptr[rsp + 0xF8]		

	0x48, 0x8B, 0x45, 0xF8,							// mov rax,qword ptr[rbp - 0x08]
	0x8B, 0x44, 0x24, 0x44,							// mov eax,dword ptr[rsp + 0x44]
	0x50,											// push rax				
	0x9D,											// popfq					

	0x48, 0x8B, 0x44, 0x24, 0x78,					// mov rax,qword ptr[rsp + 0x78]		

	0x48, 0x8D, 0x65, 0xF8,							// lea rsp,[rbp - 0x08]			
	0x5D,											// pop rbp					
	0xC3											// retn					
};

// QWORD memcpy_x64(QWORD dst, QWORD src, QWORD size) -> 165
__declspec(allocate(".text")) const unsigned char x86_64_memcpy[]
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

// NTSTATUS invokeSyscallx64(QWORD funcAddr @rcx, (DWORD)QWORD syscallID @rdx, (DWORD)QWORD argCount @r8, QWORD pArgList @r9) -> 186
__declspec(allocate(".text")) const unsigned char x86_64_PrepareForSyscall[]
{
	0x53,													// push rbx
	0x56,													// push rsi
	0x57,													// push rdi

	0x41, 0x54,												// push r12
	0x41, 0x55,												// push r13
	0x41, 0x56,												// push r14
	0x41, 0x57,												// push r15

	0x55,													// push rbp
	0x48, 0x89, 0xE5,										// mov rbp,rsp

	0x4D, 0x31, 0xE4,										// xor r12,r12
	0x41, 0x89, 0xD4,										// mov r12d,edx
	0x49, 0x89, 0xCF,										// mov r15,rcx
	0x4D, 0x89, 0xCD,										// mov r13,r9
	0x4D, 0x31, 0xF6,										// xor r14,r14
	0x45, 0x89, 0xC6,										// mov r14d,r8d

	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB8, 0xFF, 0xFF, 0xFF, 0xFF,							// mov eax,FFFFFFFF

	0x4D, 0x85, 0xFF,										// test r15,r15
	0x74, 0x7C,												// jz function_epilogue

	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x05,												// jz calc_stack_space_for_call

	0x4D, 0x85, 0xED,										// test r13,r13
	0x74, 0x72,												// jz function_epilogue

	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB8, 0x20, 0x00, 0x00, 0x00,							// mov eax,20
	0x41, 0x83, 0xFE, 0x04,									// cmp r14d,4
	0x7E, 0x09,												// jle alloc_stack_space_for_call
	0x67, 0x42, 0x8D, 0x04, 0xF5, 0x00, 0x00, 0x00, 0x00,	// lea eax,[r14d * 8 + 0]

	0x48, 0x29, 0xC4,										// sub rsp,rax
	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB0, 0x0F,												// mov al,F
	0x48, 0xF7, 0xD0,										// not rax
	0x48, 0x21, 0xC4,										// and rsp,rax

	0x41, 0x83, 0xFE, 0x04,									// cmp r14d,4
	0x7E, 0x14,												// jle pass_register_args_for_call

	0x41, 0xFF, 0xCE,										// dec r14d
	0x4B, 0x8D, 0x44, 0xF5, 0x00,							// lea rax,[r13 + r14 * 8 + 0]
	0x48, 0x8B, 0x08,										// mov rcx,qword ptr[rax]
	0x4A, 0x8D, 0x04, 0xF4,									// lea rax,[rsp + r14 * 8]
	0x48, 0x89, 0x08,										// mov qword ptr[rax],rcx
	0xEB, 0xE6,												// jmp x64_pass_stack_args_for_call

	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x28,												// jz call_function

	0x49, 0x8B, 0x4D, 0x00,									// mov rcx,qword ptr[r13 + 0]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x1C,												// jz call_function

	0x49, 0x8B, 0x55, 0x08,									// mov rdx,qword ptr[r13 + 8]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x10,												// jz call_function

	0x4D, 0x8B, 0x45, 0x10,									// mov r8,qword ptr[r13 + 10]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x04,												// jz call_function

	0x4D, 0x8B, 0x4D, 0x18,									// mov r9,qword ptr[r13 + 18]

	0x44, 0x89, 0xE0,										// mov eax,r12d

	0x41, 0xFF, 0xD7,										// call r15

	0x48, 0x89, 0xEC,										// mov rsp,rpb
	0x5D,													// pop rbp

	0x41, 0x5F,												// pop r15
	0x41, 0x5E,												// pop r14
	0x41, 0x5D,												// pop r13
	0x41, 0x5C,												// pop r12

	0x5F,													// pop rdi
	0x5E,													// pop rsi
	0x5B,													// pop rbx

	0xC3													// retn
};

// DWORD invokeSpoofedSyscallx64
// (
// 	 QWORD funcAddr @rcx,
// 	 (DWORD)QWORD syscallID @rdx,
//	 (DWORD)QWORD argCount @r8,
//	 QWORD pArgList @r9,
//	 QWORD syscallGadgetAddr @first_stack_arg_after_shadowstore,
//	 QWORD ropGadgetAddr @second_stack_arg_after_shadowstore
//	 (DWORD)QWORD gadgetType @third_stack_arg_after_shadowstore
//)  -> 319
__declspec(allocate(".text")) const unsigned char x86_64_PrepareForSpoofedSyscall[]
{
	0x53,													// push rbx
	0x56,													// push rsi
	0x57,													// push rdi

	0x41, 0x54,												// push r12
	0x41, 0x55,												// push r13
	0x41, 0x56,												// push r14
	0x41, 0x57,												// push r15

	0x55,													// push rbp
	0x48, 0x89, 0xE5,										// mov rbp,rsp

	0x4C, 0x8D, 0x55, 0x68,									// lea r10,[rbp + 68]

	0x4D, 0x31, 0xE4,										// xor r12,r12
	0x41, 0x89, 0xD4,										// mov r12d,edx
	0x49, 0x89, 0xCF,										// mov r15,rcx
	0x4D, 0x89, 0xCD,										// mov r13,r9
	0x4D, 0x31, 0xF6,										// xor r14,r14
	0x45, 0x89, 0xC6,										// mov r14d,r8d

	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB8, 0xFF, 0xFF, 0xFF, 0xFF,							// mov eax,FFFFFFFF

	0x4D, 0x85, 0xFF,										// test r15,r15
	0x0F, 0x84, 0xF9, 0x00, 0x00, 0x00,						// jz function_epilogue
		 
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x09,												// jz verify_rop_gadget

	0x4D, 0x85, 0xED,										// test r13,r13
	0x0F, 0x84, 0xEB, 0x00, 0x00, 0x00,						// jz function_epilogue

	0x41, 0x8B, 0x4A, 0x10,									// mov ecx,dword ptr[r10 + 10]

	0x83, 0xF9, 0x05,										// cmp ecx,5
	0x0F, 0x8F, 0xDE, 0x00, 0x00, 0x00,						// jg function_epilogue

	0x83, 0xF9, 0x05,										// cmp ecx,5
	0x74, 0x51,												// je rop_jmp_[rsi]
		
	0x83, 0xF9, 0x04,										// cmp ecx,4
	0x74, 0x43,												// je rop_jmp_rsi
		
	0x83, 0xF9, 0x03,										// cmp ecx,3
	0x74, 0x2D,												// je rop_jmp_[rdi]
		
	0x83, 0xF9, 0x02,										// cmp ecx,2
	0x74, 0x1F,												// je rop_jmp_rdi
		
	0x83, 0xF9, 0x01,										// cmp ecx,1
	0x74, 0x09,												// je rop_jmp_[rbx]

	0x48, 0x8D, 0x1D, 0xBE, 0x00, 0x00, 0x00,				// lea rbx,[rip + offset_to_retAddr]
	0xEB, 0x43,												// jmp calc_stack_space_for_call

	0x48, 0x8D, 0x1D, 0xB5, 0x00, 0x00, 0x00,				// lea rbx,[rip + offset_to_retAddr]
	0x49, 0x89, 0x5A, 0x10,									// mov qword ptr[r10 + 10],rbx
	0x49, 0x8D, 0x5A, 0x10,									// lea rbx,[r10 + 10]
	0xEB, 0x32,												// jmp calc_stack_space_for_call

	0x48, 0x8D, 0x3D, 0xA4, 0x00, 0x00, 0x00,				// lea rdi,[rip + offset_to_retAddr]
	0xEB, 0x29,												// jmp calc_stack_space_for_call

	0x48, 0x8D, 0x1D, 0x9B, 0x00, 0x00, 0x00,				// lea rbx,[rip + offset_to_retAddr]
	0x49, 0x89, 0x5A, 0x10,									// mov qword ptr[r10 + 10],rbx
	0x49, 0x8D, 0x7A, 0x10,									// lea rdi,[r10 + 10]
	0xEB, 0x18,												// jmp calc_stack_space_for_call

	0x48, 0x8D, 0x35, 0x8A, 0x00, 0x00, 0x00,				// lea rsi,[rip + offset_to_retAddr]
	0xEB, 0x0F,												// jmp calc_stack_space_for_call

	0x48, 0x8D, 0x1D, 0x81, 0x00, 0x00, 0x00,				// lea rbx,[rip + offset_to_retAddr]
	0x49, 0x89, 0x5A, 0x10,									// mov qword ptr[r10 + 10],rbx
	0x49, 0x8D, 0x72, 0x10,									// lea rsi,[r10 + 10]

	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB8, 0x20, 0x00, 0x00, 0x00,							// mov eax,20
	0x41, 0x83, 0xFE, 0x04,									// cmp r14d,4
	0x7E, 0x09,												// jle alloc_stack_space_for_call
	0x67, 0x42, 0x8D, 0x04, 0xF5, 0x00, 0x00, 0x00, 0x00,	// lea eax,[r14d * 8 + 0]

	0x48, 0x29, 0xC4,										// sub rsp,rax
	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB0, 0x0F,												// mov al,F
	0x48, 0xF7, 0xD0,										// not rax
	0x48, 0x21, 0xC4,										// and rsp,rax

	0x41, 0x83, 0xFE, 0x04,									// cmp r14d,4
	0x7E, 0x14,												// jle pass_register_args_for_call

	0x41, 0xFF, 0xCE,										// dec r14d
	0x4B, 0x8D, 0x44, 0xF5, 0x00,							// lea rax,[r13 + r14 * 8 + 0]
	0x48, 0x8B, 0x08,										// mov rcx,qword ptr[rax]
	0x4A, 0x8D, 0x04, 0xF4,									// lea rax,[rsp + r14 * 8]
	0x48, 0x89, 0x08,										// mov qword ptr[rax],rcx
	0xEB, 0xE6,												// jmp x64_pass_stack_args_for_call

	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x28,												// jz call_function

	0x49, 0x8B, 0x4D, 0x00,									// mov rcx,qword ptr[r13 + 0]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x1C,												// jz call_function

	0x49, 0x8B, 0x55, 0x08,									// mov rdx,qword ptr[r13 + 8]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x10,												// jz call_function

	0x4D, 0x8B, 0x45, 0x10,									// mov r8,qword ptr[r13 + 10]
	0x41, 0xFF, 0xCE,										// dec r14d
	0x45, 0x85, 0xF6,										// test r14d,r14d
	0x74, 0x04,												// jz call_function

	0x4D, 0x8B, 0x4D, 0x18,									// mov r9,qword ptr[r13 + 18]

	0x44, 0x89, 0xE0,										// mov eax, r12d
	0x4D, 0x8B, 0x1A,										// mov r11, qword ptr[r10]
		
	0x41, 0xFF, 0x72, 0x08,									// push qword ptr[r10 + 8]
	0x41, 0xFF, 0xE7,										// jmp r15

	0x48, 0x89, 0xEC,										// mov rsp, rpb
	0x5D,													// pop rbp
		
	0x41, 0x5F,												// pop r15
	0x41, 0x5E,												// pop r14
	0x41, 0x5D,												// pop r13
	0x41, 0x5C,												// pop r12
		
	0x5F,													// pop rdi
	0x5E,													// pop rsi
	0x5B,													// pop rbx

	0xC3													// retn
};

// NTSTATUS syscall_x64(DWORD syscallID @RAX, ...) -> 6
__declspec(allocate(".text")) const unsigned char x86_64_SyscallStub[]
{
	0x4C, 0x8B, 0xD1,										// mov r10,rcx
	0x0F, 0x05,												// syscall
	0xC3													// retn
};

// NTSTATUS spoofedSyscall_x64(DWORD syscallID @RAX, QWORD pointerToGadget @R11, ...) -> 6
__declspec(allocate(".text")) const unsigned char x86_64_SpoofedSyscallStub[]
{
	0x4C, 0x8B, 0xD1,										// mov r10, rcx
	0x41, 0xFF, 0xE3										// jmp r11
};

#ifndef _WIN64

// QWORD __cdecl call64BitFunction(QWORD funcAddress @rbp+0x08, DWORD argCount @rbp+0x10, DWORD argListAddress @rbp+0x14) -> 235
__declspec(allocate(".text")) const unsigned char x86_32_Call64BitFunction[]
{
	0x55,													// push ebp
	0x89, 0xE5,												// mov ebp,esp
	0x83, 0xE4, 0xF0,										// and esp,FFFFFFF0

	0xB8, 0x33, 0x00, 0x00, 0x00,							// mov eax,33
	0x50,													// push eax
	0xE8, 0x00, 0x00, 0x00, 0x00,							// call 0
	0x58,													// pop eax
	0x83, 0xC0, 0x06,										// add eax,6
	0x50,													// push eax
	0xCB,													// retf

	0x53,													// push rbx
	0x56,													// push rsi
	0x57,													// push rdi

	0x55,													// push rbp
	0x48, 0x8B, 0xEC,										// mov rbp,rsp

	0x48, 0x31, 0xC0,										// xor rax,rax
	0x48, 0x31, 0xD2,										// xor rdx,rdx
	0x48, 0x31, 0xFF,										// xor rdi,rdi
	0x48, 0x31, 0xF6,										// xor rsi,rsi

	0x48, 0x8B, 0x4D, 0x00,									// mov rcx,qword ptr[rbp + 0]

	0x48, 0x8B, 0x59, 0x08,									// mov rbx,qword ptr[rcx + 8]
	0x48, 0x85, 0xDB,										// test rbx,rbx
	0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,						// jz x64_epilogue

	0x8B, 0x79, 0x10,										// mov edi,dword ptr[rcx + 10]
	0x85, 0xFF,												// test edi,edi
	0x74, 0x07,												// jz x64_calc_stack_space_for_call

	0x8B, 0x71, 0x14,										// mov esi,dword ptr[rcx + 14]
	0x85, 0xF6,												// test esi,esi
	0x74, 0x7D,												// jz x64_epilogue

	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB8, 0x20, 0x00, 0x00, 0x00,							// mov eax,20
	0x83, 0xFF, 0x04,										// cmp edi,4
	0x7E, 0x08,												// jle x64_alloc_stack_space_for_call
	0x67, 0x8D, 0x04, 0xFD, 0x00, 0x00, 0x00, 0x00,			// lea eax,[edi * 8 + 0]

	0x48, 0x29, 0xC4,										// sub rsp,rax
	0x48, 0x31, 0xC0,										// xor rax,rax
	0xB0, 0x0F,												// mov al,F
	0x48, 0xF7, 0xD0,										// not rax
	0x48, 0x21, 0xC4,										// and rsp,rax

	0x83, 0xFF, 0x04,										// cmp edi,4
	0x7E, 0x14,												// jle x64_pass_register_args_for_call

	0xFF, 0xCF,												// dec edi
	0x67, 0x48, 0x8D, 0x04, 0xFE, 							// lea rax,[esi + edi * 8]
	0x48, 0x8B, 0x08,										// mov rcx,qword ptr[rax]
	0x67, 0x48, 0x8D, 0x04, 0xFC,							// lea rax,[esp + edi * 8]
	0x48, 0x89, 0x08,										// mov qword ptr[rax],rcx
	0xEB, 0xE7,												// jmp x64_pass_stack_args_for_call

	0x85, 0xFF,												// test edi,edi
	0x74, 0x34,												// jz x64_call_function

	0x48, 0x8B, 0x0E,										// mov rcx,qword ptr[rsi]
	0xF2, 0x0F, 0x10, 0x06,									// movsd xmm0,qword ptr[rsi]
	0xFF, 0xCF,												// dec edi
	0x85, 0xFF,												// test edi,edi
	0x74, 0x27,												// jz x64_call_function

	0x48, 0x8B, 0x56, 0x08,									// mov rdx,qword ptr[rsi + 8]
	0xF2, 0x0F, 0x10, 0x4E, 0x08,							// movsd xmm1,qword ptr[rsi + 8]
	0xFF, 0xCF,												// dec edi
	0x85, 0xFF,												// test edi,edi
	0x74, 0x18,												// jz x64_call_function
	
	0x4C, 0x8B, 0x46, 0x10,									// mov r8,qword ptr[rsi + 10]
	0xF2, 0x0F, 0x10, 0x56, 0x10,							// movsd xmm2,qword ptr[rsi + 10]
	0xFF, 0xCF,												// dec edi
	0x85, 0xFF,												// test edi,edi
	0x74, 0x09, 											// jz x64_call_function

	0x4C, 0x8B, 0x4E, 0x18,									// mov r9,qword ptr[rsi + 18]
	0xF2, 0x0F, 0x10, 0x5E, 0x18,							// movsd xmm3,qword ptr[rsi + 18]

	0xFF, 0xD3,												// call rbx; call function directly through register

	0x48, 0x8B, 0xD0,										// mov rdx,rax; copy return value(QWORD) to rdx
	0x48, 0xC1, 0xEA, 0x32,									// shr rdx,32

	0x48, 0x8B, 0xE5,										// mov rsp,rpb
	0x5D,													// pop rbp
	
	0x5F,													// pop rdi
	0x5E,													// pop rsi
	0x5B,													// pop rbx

	0xE8, 0x00, 0x00, 0x00, 0x00,							// call 0
	0x59,													// pop rcx
	0x83, 0xC1, 0x15,										// add ecx,15
	0x48, 0x83, 0xEC, 0x08,									// sub rsp,8
	0x89, 0x0C, 0x24,										// mov dword ptr[rsp],ecx
	0xB9, 0x23, 0x00, 0x00, 0x00,							// mov ecx,23
	0x89, 0x4C, 0x24, 0x04,									// mov dword ptr[rsp + 4],ecx
	0xCB,													// retf

	0x89, 0xEC,												// mov esp, ebp
	0x5D,													// pop ebp
	
	0xC3													// retn
};

#endif


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
	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return false;
	}
	*/

	PEB_LDR_DATA64 ldrData{};

	memcpy64Bit(reinterpret_cast<QWORD>(&ldrData), reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<QWORD>(sizeof(ldrData)));

	//if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		//return false;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		memcpy64Bit(reinterpret_cast<QWORD>(&currentLoaderEntry), currEntryAddr, static_cast<QWORD>(sizeof(currentLoaderEntry)));

		//if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			//return false;

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

			memcpy64Bit(reinterpret_cast<QWORD>(pModuleName), currentLoaderEntry.BaseDllName.WideStringAddress, static_cast<QWORD>(moduleStringLength));

			//if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			//{
				const std::wstring moduleName{ reinterpret_cast<wchar_t*>(pModuleName) };
				const std::string currModName{ moduleName.begin(), moduleName.end() };

				Process::ModuleInformationA currentModule{};

				currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				currentModule.modName = currModName;
				currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				currentModule.procID = m_processInfo.procID;
				currentModule.procName = m_processInfo.procName;

				newModuleList.push_back(currentModule);
			//}
			//else
			//{
				//delete[] pModuleName;
				//pModuleName = nullptr;
				//return false;
			//}

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


bool LocalProcessA::updateSyscallIDs() noexcept
{
	const std::vector<std::pair<DWORD, Process::ModuleExportA>> syscallIDs{ getSyscallIDs() };

	if (syscallIDs.empty())
		return false;

	m_syscallIDs.clear();

	for (const std::pair<DWORD, Process::ModuleExportA>& currSyscallID : syscallIDs)
	{
		m_syscallIDs[currSyscallID.second.exportName] = currSyscallID.first;
	}

	return true;
}


LocalProcessA::LocalProcessA() noexcept
{
#ifdef _WIN64

	m_processInfo.wow64Process = false;
	const DWORD icRVA{ static_cast<DWORD>(reinterpret_cast<QWORD>(LocalProcessA::instrumentationCallbackThunk) - reinterpret_cast<QWORD>(&x86_64_ICBridgeA[221])) };

	DWORD oldProtect{};
	if (VirtualProtect(const_cast<unsigned char*>(&x86_64_ICBridgeA[217]), sizeof(icRVA), PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		*reinterpret_cast<DWORD*>(const_cast<unsigned char*>(&x86_64_ICBridgeA[217])) = icRVA;

		VirtualProtect(const_cast<unsigned char*>(&x86_64_ICBridgeA[217]), sizeof(icRVA), oldProtect, &oldProtect);
	}

#endif

	BOOL wow64Proc{ FALSE };
	if (IsWow64Process(GetCurrentProcess(), &wow64Proc))
		m_processInfo.wow64Process = static_cast<bool>(wow64Proc);

	while (!validHandle(m_hProc))
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	LocalProcessA::s_instance.updateProcessInfo();
	LocalProcessA::s_instance.updateModuleInfo();
	LocalProcessA::s_instance.updateSyscallIDs();

}

LocalProcessA::~LocalProcessA()
{
#ifndef _WIN64

	//deleteShellcodeMemory();

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

#ifdef _WIN64
bool LocalProcessA::installInstrumentationCallback(const QWORD callbackHandler) noexcept
{
	if (isInstrumentationCallbackSet())
		return false;

	const QWORD pNtQIP{ getNativeProcAddress("NtQueryInformationProcess") };
	const QWORD pNtSIP{ getNativeProcAddress("NtSetInformationProcess") };

	if (!pNtQIP || !pNtSIP)
		return false;

	LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{};
	ULONG dummy{};

	reinterpret_cast<tNtQueryInformationProcess>(pNtQIP)(m_hProc, ProcessInstrumentationCallback, &pic, sizeof(pic), &dummy);

	const DWORD tlsSlot{ TlsAlloc() };

	if (tlsSlot >= TLS_OUT_OF_INDEXES)
		return false;

	m_addrPrevIC = pic.callbackAddr;
	m_ICTlsIndex = tlsSlot;
	m_addrICHandler = callbackHandler;

	pic.version = 0;
	pic.reserved = 0;
	pic.callbackAddr = reinterpret_cast<QWORD>(x86_64_ICBridgeA);

	if (reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, &pic, sizeof(pic)) != STATUS_SUCCESS)
	{
		TlsFree(m_ICTlsIndex);
		m_ICTlsIndex = TLS_OUT_OF_INDEXES;
		m_addrPrevIC = 0;
		m_addrICHandler = 0;

		return false;
	}

	return true;
}

bool LocalProcessA::removeInstrumentationCallback() noexcept
{
	if (!isInstrumentationCallbackSet())
		return false;

	const QWORD pNtSIP{ getNativeProcAddress("NtSetInformationProcess") };

	if (!pNtSIP)
		return false;

	const LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{ 0, 0, m_addrPrevIC };

	if (reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, const_cast<LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK*>(&pic), sizeof(pic)) != STATUS_SUCCESS)
	{
		return false;
	}

	TlsFree(m_ICTlsIndex);
	m_ICTlsIndex = TLS_OUT_OF_INDEXES;
	m_addrPrevIC = 0;
	m_addrICHandler = 0;

	return true;
}

bool LocalProcessA::setInstrumentationCallback() const noexcept
{
	const QWORD pNtSIP{ getNativeProcAddress("NtSetInformationProcess") };

	if (!pNtSIP)
		return false;

	const LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{ 0, 0, reinterpret_cast<QWORD>(x86_64_ICBridgeA) };

	return reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, const_cast<LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK*>(&pic), sizeof(pic)) == STATUS_SUCCESS;
}

bool LocalProcessA::setICHandler(const QWORD callbackHandler) noexcept
{
	m_addrICHandler = callbackHandler;

	return isInstrumentationCallbackSet();
}

void LocalProcessA::instrumentationCallbackThunk(CONTEXT* const pContext) noexcept
{
	constexpr DWORD trapMask{ ~static_cast<DWORD>(1 >> 8) };

	pContext->EFlags &= trapMask;

	if (!LocalProcessA::getInstance().m_addrICHandler)
		return;

	const DWORD tlsIndex{ LocalProcessA::getInstance().m_ICTlsIndex };

	if (TlsGetValue(tlsIndex))
		return;

	TlsSetValue(tlsIndex, reinterpret_cast<LPVOID>(1));

	reinterpret_cast<void(*)(CONTEXT* const)>(LocalProcessA::getInstance().m_addrICHandler)(pContext);

	TlsSetValue(tlsIndex, nullptr);
}
#endif


uintptr_t LocalProcessA::getNativeProcAddress(const std::string& functionName) const noexcept
{
	map::const_iterator it{ m_nativeFunctions.find(functionName) };

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


std::vector<std::pair<DWORD, Process::ModuleExportA>> LocalProcessA::getSyscallIDs(const bool assumeHooked) const noexcept
{
	std::vector<std::pair<DWORD, Process::ModuleExportA>> foundSyscalls;

	const std::vector<Process::ModuleExportA> ntdllExports{ getModuleExports_x64("ntdll.dll") };

	if (assumeHooked)
	{
		std::vector<Process::ModuleExportA> syscallExports{};

		for (const Process::ModuleExportA& currExport : ntdllExports)
		{
			if (!_stricmp(currExport.exportName.substr(0, 2).c_str(), "Zw"))
			{
				syscallExports.push_back(currExport);
				Process::ModuleExportA currExportNt{ currExport };
				currExportNt.exportName.replace(0, 2, "Nt");
				syscallExports.push_back(currExportNt);
			}
		}

		std::sort(syscallExports.begin(), syscallExports.end(), [&](const Process::ModuleExportA& a, const Process::ModuleExportA& b) ->bool { return a.absoluteAddress < b.absoluteAddress; });

		foundSyscalls.resize(syscallExports.size());

		for (size_t iterator{ 0 }; iterator < foundSyscalls.size(); ++iterator)
		{
			foundSyscalls.at(iterator) = { static_cast<DWORD>(iterator), syscallExports.at(iterator) };
		}
	}
	else
	{
		for (const Process::ModuleExportA& currExport : ntdllExports)
		{
			bool syscallFound{ true };

			for (DWORD iterator{ 0 }; iterator < LocalProcess::syscallSignatureA.pattern.size(); ++iterator)
			{
#ifdef _WIN64
				if (LocalProcess::syscallSignatureA.pattern.at(iterator) >= 0 && static_cast<short>(*reinterpret_cast<BYTE*>(currExport.absoluteAddress + iterator)) != LocalProcess::syscallSignatureA.pattern.at(iterator))
#else
				if (LocalProcess::syscallSignatureA.pattern.at(iterator) >= 0 && readByte64Bit(currExport.absoluteAddress + iterator) != LocalProcess::syscallSignatureA.pattern.at(iterator))
#endif
				{
					syscallFound = false;
					break;
				}
			}

			if (!syscallFound)
				continue;

#ifdef _WIN64
			const DWORD syscallID{ *reinterpret_cast<DWORD*>(currExport.absoluteAddress + 4) };
#else
			const DWORD syscallID{ readDword64Bit(currExport.absoluteAddress + 4) };
#endif

			foundSyscalls.push_back(std::pair<DWORD, Process::ModuleExportA>{ syscallID, currExport });
		}

		std::sort(foundSyscalls.begin(), foundSyscalls.end(), [&](const std::pair<DWORD, Process::ModuleExportA>& a, const std::pair<DWORD, Process::ModuleExportA>& b) -> bool { return a.first < b.first; });
	}

	return foundSyscalls;
}

DWORD LocalProcessA::getSyscallID(const std::string& exportName) const noexcept
{
	mapD::const_iterator it{ m_syscallIDs.find(exportName) };

	if (it != m_syscallIDs.end())
	{
		return (*it).second;
	}
	
	return static_cast<DWORD>(-1);
}

NTSTATUS LocalProcessA::invokeSyscall(const DWORD syscallID, const DWORD argCount, ...) const noexcept
{
	if (argCount)
	{
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

#ifdef _WIN64
		const NTSTATUS retVal{ (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSyscall)))(reinterpret_cast<QWORD>(x86_64_SyscallStub), syscallID, argCount, reinterpret_cast<QWORD>(pArgList)) };
#else
		const NTSTATUS retVal{ static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSyscall), 4, reinterpret_cast<QWORD>(x86_64_SyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), reinterpret_cast<QWORD>(pArgList))) };
#endif

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
#ifdef _WIN64
		return (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSyscall)))(reinterpret_cast<QWORD>(x86_64_SyscallStub), syscallID, argCount, 0);
#else
		return static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSyscall), 4, reinterpret_cast<QWORD>(x86_64_SyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), 0));
#endif
	}
}

NTSTATUS LocalProcessA::invokeSpoofedSyscall(const DWORD syscallID, const DWORD argCount, const LocalProcess::SCROPGadgetType ropGadgetType, const QWORD ropGadgetAddress, ...)
{
	if (!ropGadgetAddress)
		return static_cast<NTSTATUS>(-1);

	const std::vector<short>* pRopGadgetSig{ nullptr };

	switch (ropGadgetType)
	{
		case LocalProcess::SCROPGadgetType::jmp_rbx:
		{
			pRopGadgetSig = &LocalProcess::jmp_rbx_gadget;
			break;
		}

		case LocalProcess::SCROPGadgetType::jmp_rbx_ptr:
		{
			pRopGadgetSig = &LocalProcess::jmp_rbx_deref_gadget;
			break;
		}

		case LocalProcess::SCROPGadgetType::jmp_rdi:
		{
			pRopGadgetSig = &LocalProcess::jmp_rdi_gadget;
			break;
		}

		case LocalProcess::SCROPGadgetType::jmp_rdi_ptr:
		{
			pRopGadgetSig = &LocalProcess::jmp_rdi_deref_gadget;
			break;
		}

		case LocalProcess::SCROPGadgetType::jmp_rsi:
		{
			pRopGadgetSig = &LocalProcess::jmp_rsi_gadget;
			break;
		}

		case LocalProcess::SCROPGadgetType::jmp_rsi_ptr:
		{
			pRopGadgetSig = &LocalProcess::jmp_rsi_deref_gadget;
			break;
		}

		default:
			return static_cast<NTSTATUS>(-1);
	}

	std::vector<unsigned char> gadgetCopy{};
	gadgetCopy.resize(pRopGadgetSig->size());

#ifdef _WIN64
	memcpy(gadgetCopy.data(), reinterpret_cast<void*>(ropGadgetAddress), gadgetCopy.size());
#else
	memcpy64Bit(reinterpret_cast<QWORD>(gadgetCopy.data()), ropGadgetAddress, gadgetCopy.size());
#endif
	bool gadgetValid{ true };

	for (size_t iterator{ 0 }; iterator < gadgetCopy.size(); ++iterator)
	{
		if (pRopGadgetSig->at(iterator) < 0 || pRopGadgetSig->at(iterator) > 0xFF)
			continue;

		if (static_cast<unsigned char>(pRopGadgetSig->at(iterator)) != gadgetCopy.at(iterator))
		{
			gadgetValid = false;
			break;
		}
	}

	if (!gadgetValid)
		return static_cast<NTSTATUS>(-1);

	const mapD::const_iterator syscallFound{ std::find_if(m_syscallIDs.begin(), m_syscallIDs.end(), [&](const std::pair<std::string, DWORD>& pair)->bool { return pair.second == syscallID; }) };

	if (syscallFound == m_syscallIDs.end())
		return static_cast<NTSTATUS>(-1);

	const std::string funcName{ syscallFound->first };

	const QWORD funcAddress{ getProcAddress_x64("ntdll.dll", funcName) };

	if (!funcAddress)
		return static_cast<NTSTATUS>(-1);

	const QWORD syscallGadgetAddress{ scanPattern(LocalProcess::syscallGadget, funcAddress, static_cast<DWORD>(30)) };

	if (!syscallGadgetAddress)
		return static_cast<NTSTATUS>(-1);

	if (argCount)
	{
		QWORD* pArgList{ nullptr };

		while (!pArgList)
			pArgList = new QWORD[argCount];

		std::va_list list{};

		va_start(list, ropGadgetAddress);

		for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
		{
			pArgList[iterator] = va_arg(list, QWORD);
		}

		va_end(list);

#ifdef _WIN64
		const NTSTATUS retVal{ (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSpoofedSyscall)))(reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), syscallID, argCount, reinterpret_cast<QWORD>(pArgList), syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType)) };
#else
		const NTSTATUS retVal{ static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSpoofedSyscall), 7, reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), reinterpret_cast<QWORD>(pArgList), syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType))) };
#endif

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
#ifdef _WIN64
		return (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSpoofedSyscall)))(reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), syscallID, argCount, 0, syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType));
#else
		return static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSpoofedSyscall), 7, reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), 0, syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType)));
#endif
	}
}


#ifndef _WIN64

QWORD LocalProcessA::getNativeProcAddressWow64(const std::string& functionName) const noexcept
{
	mapQ::const_iterator it{ m_nativeFunctionsWow64.find(functionName) };

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
	//return call64BitFunction(static_cast<QWORD>(m_shellcodeMemory) + LocalProcess::shellcode::offsetGet64BitPEB);
	return call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadPEBFromReg));
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
	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return newModule;
	}
	*/
	
	PEB_LDR_DATA64 ldrData{};

	memcpy64Bit(reinterpret_cast<QWORD>(&ldrData), reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<QWORD>(sizeof(ldrData)));

	//if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		//return newModule;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		memcpy64Bit(reinterpret_cast<QWORD>(&currentLoaderEntry), currEntryAddr, static_cast<QWORD>(sizeof(currentLoaderEntry)));

		//if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			//break;

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

			memcpy64Bit(reinterpret_cast<QWORD>(pModuleName), currentLoaderEntry.BaseDllName.WideStringAddress, static_cast<QWORD>(moduleStringLength));

			//if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			//{
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
			//}

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


std::vector<Process::ModuleExportA> LocalProcessA::getModuleExports_x86(const QWORD modBA) const noexcept
{
	std::vector<Process::ModuleExportA> exports{};

#ifdef _WIN64

	return exports;

#else

	if (!modBA || modBA > 0xFFFFFFFF)
		return exports;

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return exports;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x10B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	std::string modName{};

	std::vector<Process::ModuleInformationA>::const_iterator foundModule{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x86Modules.end())
		modName = foundModule->modName;
	else
		modName = "unknown";

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!pNameArray[iterator])
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = pOrdinalArray[iterator];
		currExport.relativeAddress = pExportTable[currExport.ordinal];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = std::string{ reinterpret_cast<const char*>(modBA + pNameArray[iterator]) };

		currExport.ordinal += Process::ordinalBaseOffset;

		if (currExport.absoluteAddress <= 0xFFFFFFFF)
			exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportA& modExport : exports)
		{
			if (modExport.relativeAddress == pExportTable[iterator])
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = pExportTable[iterator];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = "unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		if (currExport.absoluteAddress <= 0xFFFFFFFF)
			exports.push_back(currExport);
	}

	std::sort(exports.begin(), exports.end(), [&](const Process::ModuleExportA& a, const Process::ModuleExportA& b) -> bool { return a.ordinal < b.ordinal; });

	return exports;

#endif
}

std::vector<Process::ModuleExportA> LocalProcessA::getModuleExports_x64(const QWORD modBA) const noexcept
{
	std::vector<Process::ModuleExportA> exports{};

	if (!modBA)
		return exports;

#ifdef _WIN64

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return exports;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x20B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	std::string modName{};

	std::vector<Process::ModuleInformationA>::const_iterator foundModule{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x64Modules.end())
		modName = foundModule->modName;
	else
		modName = "unknown";

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!pNameArray[iterator])
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = pOrdinalArray[iterator];
		currExport.relativeAddress = pExportTable[currExport.ordinal];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = std::string{ reinterpret_cast<const char*>(modBA + pNameArray[iterator]) };

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportA& modExport : exports)
		{
			if (modExport.relativeAddress == pExportTable[iterator])
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = pExportTable[iterator];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = "unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

#else

	IMAGE_DOS_HEADER idh{};
	memcpy64Bit(reinterpret_cast<QWORD>(&idh), modBA, sizeof(idh));

	if (idh.e_magic != 0x5A4D)
		return exports;

	IMAGE_NT_HEADERS64 nth{};
	memcpy64Bit(reinterpret_cast<QWORD>(&nth), modBA + idh.e_lfanew, sizeof(nth));

	if (nth.Signature != 0x4550 || nth.OptionalHeader.Magic != 0x20B || nth.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(nth.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	IMAGE_EXPORT_DIRECTORY ied{};
	memcpy64Bit(reinterpret_cast<QWORD>(&ied), modBA + nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(ied));

	const QWORD pNameArray{ modBA + ied.AddressOfNames };
	const QWORD pOrdinalArray{ modBA + ied.AddressOfNameOrdinals };
	const QWORD pExportTable{ modBA + ied.AddressOfFunctions };

	std::string modName{};

	std::vector<Process::ModuleInformationA>::const_iterator foundModule{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationA& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x64Modules.end())
		modName = foundModule->modName;
	else
		modName = "unknown";

	char nameBuffer[0x102]{};

	for (DWORD iterator{ 0 }; iterator < ied.NumberOfNames; ++iterator)
	{
		const DWORD nameOffset{ readDword64Bit(pNameArray + static_cast<QWORD>(iterator) * sizeof(DWORD)) };

		if (!nameOffset)
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = readWord64Bit(pOrdinalArray + static_cast<QWORD>(iterator) * sizeof(WORD));
		currExport.relativeAddress = readDword64Bit(pExportTable + static_cast<QWORD>(currExport.ordinal) * sizeof(DWORD));
		currExport.absoluteAddress = modBA + currExport.relativeAddress;

		memcpy64Bit(reinterpret_cast<QWORD>(nameBuffer), modBA + nameOffset, 0x100);
		currExport.exportName = std::string{ const_cast<const char*>(nameBuffer) };

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < ied.NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportA& modExport : exports)
		{
			if (modExport.relativeAddress == readDword64Bit(pExportTable + static_cast<QWORD>(iterator) * sizeof(DWORD)))
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportA currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = readDword64Bit(pExportTable + static_cast<QWORD>(iterator) * sizeof(DWORD));
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = "unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

#endif

	std::sort(exports.begin(), exports.end(), [&](const Process::ModuleExportA& a, const Process::ModuleExportA& b) -> bool { return a.ordinal < b.ordinal; });

	return exports;
}


std::vector<Process::ModuleExportA> LocalProcessA::getModuleExports_x86(const std::string& modName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getModuleExports_x86(modBA) : std::vector<Process::ModuleExportA>{};
}

std::vector<Process::ModuleExportA> LocalProcessA::getModuleExports_x64(const std::string& modName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getModuleExports_x64(modBA) : std::vector<Process::ModuleExportA>{};
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

	//return reinterpret_cast<QWORD(__cdecl*)(QWORD, QWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress)(modBA, reinterpret_cast<QWORD>(functionName.c_str()));

	QWORD procAddress{};

	IMAGE_DOS_HEADER dosHeader{};
	memcpy64Bit(reinterpret_cast<QWORD>(&dosHeader), modBA, sizeof(dosHeader));

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	IMAGE_NT_HEADERS64 ntHeader{};
	memcpy64Bit(reinterpret_cast<QWORD>(&ntHeader), modBA + dosHeader.e_lfanew, sizeof(ntHeader));

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x20B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	IMAGE_EXPORT_DIRECTORY exportDirectory{};
	memcpy64Bit(reinterpret_cast<QWORD>(&exportDirectory), modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(exportDirectory));

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	memcpy64Bit(reinterpret_cast<QWORD>(exportTable.data()), exportTableAddr, static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)));
	memcpy64Bit(reinterpret_cast<QWORD>(ordinalTable.data()), ordinalsAddr, static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)));
	memcpy64Bit(reinterpret_cast<QWORD>(nameTable.data()), namesAddr, static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)));

	char nameBuffer[128]{};

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		memcpy64Bit(reinterpret_cast<QWORD>(nameBuffer), modBA + nameTable.at(iterator), sizeof(nameBuffer));

		std::string strTableEntry{ &nameBuffer[0] };

		if (!_stricmp(strTableEntry.c_str(), functionName.c_str()))
		{
			const WORD ordinal{ ordinalTable.at(iterator) };
			procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

			break;
		}
	}

	return procAddress;

#endif
}

QWORD LocalProcessA::getProcAddress_x86(const std::string& modName, const std::string& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD LocalProcessA::getProcAddress_x64(const std::string& modName, const std::string& functionName) const noexcept
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
		/*
		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
			return 0;
		}

		if (_NtWow64RVM(m_hProc, result + currOffset, &result, sizeof(result), nullptr) != STATUS_SUCCESS)
			return 0;
		*/

		result = readQword64Bit(result + currOffset);

#endif
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
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

std::vector<Process::FoundGadgetA> LocalProcessA::findGadgets(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept
{
	std::vector<Process::FoundGadgetA> result{};

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePattern(signature) };

#ifndef _WIN64
	if (startAddress <= 0xFFFFFFFF || endAddress <= 0xFFFFFFFF)
	{
#endif
		MEMORY_BASIC_INFORMATION mbi{};

		for (uintptr_t currAddress{ static_cast<uintptr_t>(startAddress) }; currAddress < static_cast<uintptr_t>(endAddress); currAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + static_cast<uintptr_t>(mbi.RegionSize))
		{
			if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
				break;

			if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
				continue;

			const DWORD scanSize{ (static_cast<QWORD>(currAddress) + mbi.RegionSize > endAddress) ? static_cast<DWORD>(endAddress - currAddress) : static_cast<DWORD>(mbi.RegionSize) };

			if (!(mbi.Protect & PAGE_EXECUTE))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), scanSize, pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};
						Process::ModuleInformationA modInfo{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
						currGadget.readable = true;
						currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
						currGadget.pattern = pattern;
						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
						{
							currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
							currGadget.moduleName = modInfo.modName;
						}

						result.push_back(currGadget);
					}
				}
			}
			else
			{
				DWORD oldProtect{};

				if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), scanSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), scanSize, pattern) };

					if (addrBuffer.size())
					{
						for (const char* const address : addrBuffer)
						{
							Process::FoundGadgetA currGadget{};
							Process::ModuleInformationA modInfo{};

							currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
							currGadget.readable = false;
							currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
							currGadget.pattern = pattern;
							currGadget.bytes.clear();
							currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

							if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
							{
								currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
								currGadget.moduleName = modInfo.modName;
							}

							result.push_back(currGadget);
						}
					}

					VirtualProtect(reinterpret_cast<LPVOID>(currAddress), scanSize, oldProtect, &oldProtect);
				}
			}
		}

#ifndef _WIN64
	}
	else
	{
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

		/*
		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
			return result;
		}
		*/

		MEMORY_BASIC_INFORMATION64 mbi{};

		for (QWORD currAddress{ startAddress }; currAddress < endAddress; currAddress = mbi.BaseAddress + mbi.RegionSize)
		{
			QWORD returnLength{};

			if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
				break;

			if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
				continue;

			const DWORD scanSize{ (currAddress + mbi.RegionSize > endAddress) ? static_cast<DWORD>(endAddress - currAddress) : static_cast<DWORD>(mbi.RegionSize) };

			const LPVOID pScanBuffer{ VirtualAlloc(nullptr, scanSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

			if (!pScanBuffer)
				continue;

			if (!(mbi.Protect & PAGE_EXECUTE))
			{
				//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, scanSize, nullptr) != STATUS_SUCCESS)
				//{
					//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					//continue;
				//}

				memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(scanSize));

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(scanSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};
						Process::ModuleInformationA modInfo{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.readable = true;
						currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
						currGadget.pattern = pattern;
						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
						{
							currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
							currGadget.moduleName = modInfo.modName;
						}

						result.push_back(currGadget);
					}
				}
			}
			else
			{
				DWORD oldProtect{};
				QWORD protectAddress{ currAddress };
				QWORD protectionLength{ scanSize };

				if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
				{
					//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, scanSize, nullptr) != STATUS_SUCCESS)
					//
						//callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
						//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
						//continue;
					//}

					memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(scanSize));

					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

					const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(scanSize), pattern) };

					if (addrBuffer.size())
					{
						for (const char* const address : addrBuffer)
						{
							Process::FoundGadgetA currGadget{};
							Process::ModuleInformationA modInfo{};

							currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
							currGadget.readable = false;
							currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
							currGadget.pattern = pattern;
							currGadget.bytes.clear();
							currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

							if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
							{
								currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
								currGadget.moduleName = modInfo.modName;
							}

							result.push_back(currGadget);
						}
					}
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
	}
#endif

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

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress = reinterpret_cast<DWORD>(mbi.BaseAddress) + mbi.RegionSize)
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
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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

	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress("NtWow64ReadVirtualMemory64"));
		return result;
	}
	*/

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternA(signature) };

	const Process::ModuleInformationA modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress = mbi.BaseAddress + mbi.RegionSize)
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
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, static_cast<SIZE_T>(mbi.RegionSize), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
			//{
				//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				//continue;
			//}

			memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(mbi.RegionSize));

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetA currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				//{
					//callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					//continue;
				//}

				memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(mbi.RegionSize));

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetA currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
		}

		VirtualFree(pScanBuffer, 0, MEM_RELEASE);

#endif
	}

	return result;
}


#ifndef _WIN64

BOOL LocalProcessA::callNativeFunction(const std::string& funcName, const DWORD argCount, ...) const noexcept
{
	const QWORD funcAddr{ getNativeProcAddressWow64(funcName) };

	if (!funcAddr)
		return FALSE;

	if (argCount)
	{
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

		//const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

		const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) == STATUS_SUCCESS) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0) == STATUS_SUCCESS);
	}
}

BOOL LocalProcessA::callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr)
		return FALSE;

	if (argCount)
	{
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

		//const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

		const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) == STATUS_SUCCESS) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0) == STATUS_SUCCESS);
	}
}


QWORD LocalProcessA::call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr)
		return 0;

	if (argCount)
	{
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

		//const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) };

		const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0);
	}
}


BYTE LocalProcessA::readByte64Bit(const QWORD address) const noexcept
{
	return static_cast<BYTE>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadByte), address));
}

WORD LocalProcessA::readWord64Bit(const QWORD address) const noexcept
{
	return static_cast<WORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadWord), address));
}

DWORD LocalProcessA::readDword64Bit(const QWORD address) const noexcept
{
	return static_cast<DWORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadDword), address));
}
QWORD LocalProcessA::readQword64Bit(const QWORD address) const noexcept
{
	return static_cast<QWORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadQword), address));
}


bool LocalProcessA::writeByte64Bit(const QWORD address, const BYTE value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteByte), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessA::writeWord64Bit(const QWORD address, const WORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteWord), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessA::writeDword64Bit(const QWORD address, const DWORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteDword), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessA::writeQword64Bit(const QWORD address, const QWORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteByte), 2, address, value));
}


QWORD LocalProcessA::memcpy64Bit(const QWORD pDst, const QWORD pSrc, const QWORD size) const noexcept
{
	return call64BitFunction(reinterpret_cast<QWORD>(x86_64_memcpy), 3, pDst, pSrc, size);
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

	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return false;
	}
	*/

	PEB_LDR_DATA64 ldrData{};

	memcpy64Bit(reinterpret_cast<QWORD>(&ldrData), reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<QWORD>(sizeof(ldrData)));

	//if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		//return false;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		memcpy64Bit(reinterpret_cast<QWORD>(&currentLoaderEntry), currEntryAddr, static_cast<QWORD>(sizeof(currentLoaderEntry)));

		//if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			//return false;

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

			memcpy64Bit(reinterpret_cast<QWORD>(pModuleName), currentLoaderEntry.BaseDllName.WideStringAddress, static_cast<QWORD>(moduleStringLength));

			//if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			//{
				Process::ModuleInformationW currentModule{};

				currentModule.modBA.x64Addr = static_cast<QWORD>(currentLoaderEntry.DllBase);
				currentModule.modName = std::wstring{ reinterpret_cast<wchar_t*>(pModuleName) };
				currentModule.modSize = static_cast<DWORD>(currentLoaderEntry.SizeOfImage);
				currentModule.procID = m_processInfo.procID;
				currentModule.procName = m_processInfo.procName;

				newModuleList.push_back(currentModule);
			//}
			//else
			//{
				//delete[] pModuleName;
				//pModuleName = nullptr;
				//return false;
			//}

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


bool LocalProcessW::updateSyscallIDs() noexcept
{
	const std::vector<std::pair<DWORD, Process::ModuleExportW>> syscallIDs{ getSyscallIDs() };

	if (syscallIDs.empty())
		return false;

	m_syscallIDs.clear();

	for (const std::pair<DWORD, Process::ModuleExportW>& currSyscallID : syscallIDs)
	{
		m_syscallIDs[currSyscallID.second.exportName] = currSyscallID.first;
	}

	return true;
}


LocalProcessW::LocalProcessW() noexcept
{
#ifdef _WIN64

		m_processInfo.wow64Process = false;
		const DWORD icRVA{ static_cast<DWORD>(reinterpret_cast<QWORD>(LocalProcessW::instrumentationCallbackThunk) - reinterpret_cast<QWORD>(&x86_64_ICBridgeW[221])) };

		DWORD oldProtect{};
		if (VirtualProtect(const_cast<unsigned char*>(&x86_64_ICBridgeW[217]), sizeof(icRVA), PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			*reinterpret_cast<DWORD*>(const_cast<unsigned char*>(&x86_64_ICBridgeW[217])) = icRVA;

			VirtualProtect(const_cast<unsigned char*>(&x86_64_ICBridgeW[217]), sizeof(icRVA), oldProtect, &oldProtect);
		}

#endif

	BOOL wow64Proc{ FALSE };
	if (IsWow64Process(GetCurrentProcess(), &wow64Proc))
		m_processInfo.wow64Process = static_cast<bool>(wow64Proc);

	while (!validHandle(m_hProc))
		m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	LocalProcessW::s_instance.updateProcessInfo();
	LocalProcessW::s_instance.updateModuleInfo();
	LocalProcessW::s_instance.updateSyscallIDs();

}

LocalProcessW::~LocalProcessW()
{
#ifndef _WIN64

	//deleteShellcodeMemory();

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

#ifdef _WIN64
bool LocalProcessW::installInstrumentationCallback(const QWORD callbackHandler) noexcept
{
	if (isInstrumentationCallbackSet())
		return false;

	const QWORD pNtQIP{ getNativeProcAddress(L"NtQueryInformationProcess") };
	const QWORD pNtSIP{ getNativeProcAddress(L"NtSetInformationProcess") };

	if (!pNtQIP || !pNtSIP)
		return false;

	LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{};
	ULONG dummy{};


	reinterpret_cast<tNtQueryInformationProcess>(pNtQIP)(m_hProc, ProcessInstrumentationCallback, &pic, sizeof(pic), &dummy);

	const DWORD tlsSlot{ TlsAlloc() };

	if (tlsSlot >= TLS_OUT_OF_INDEXES)
		return false;

	m_addrPrevIC = pic.callbackAddr;
	m_ICTlsIndex = tlsSlot;
	m_addrICHandler = callbackHandler;

	pic.version = 0;
	pic.reserved = 0;
	pic.callbackAddr = reinterpret_cast<QWORD>(x86_64_ICBridgeW);

	if (reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, &pic, sizeof(pic)) != STATUS_SUCCESS)
	{
		TlsFree(m_ICTlsIndex);
		m_ICTlsIndex = TLS_OUT_OF_INDEXES;
		m_addrPrevIC = 0;
		m_addrICHandler = 0;

		return false;
	}

	return true;
}

bool LocalProcessW::removeInstrumentationCallback() noexcept
{
	if (!isInstrumentationCallbackSet())
		return false;

	const QWORD pNtSIP{ getNativeProcAddress(L"NtSetInformationProcess") };

	if (!pNtSIP)
		return false;

	const LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{ 0, 0, m_addrPrevIC };

	if (reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, const_cast<LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK*>(&pic), sizeof(pic)) != STATUS_SUCCESS)
	{
		return false;
	}

	TlsFree(m_ICTlsIndex);
	m_ICTlsIndex = TLS_OUT_OF_INDEXES;
	m_addrPrevIC = 0;
	m_addrICHandler = 0;

	return true;
}

bool LocalProcessW::setInstrumentationCallback() const noexcept
{
	const QWORD pNtSIP{ getNativeProcAddress(L"NtSetInformationProcess") };

	if (!pNtSIP)
		return false;

	const LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK pic{ 0, 0, reinterpret_cast<QWORD>(x86_64_ICBridgeW) };

	return reinterpret_cast<tNtSetInformationProcess>(pNtSIP)(m_hProc, ProcessInstrumentationCallback, const_cast<LocalProcess::PROCESS_INSTRUMENTATION_CALLBACK*>(&pic), sizeof(pic)) == STATUS_SUCCESS;
}

bool LocalProcessW::setICHandler(const QWORD callbackHandler) noexcept
{
	m_addrICHandler = callbackHandler;

	return isInstrumentationCallbackSet();
}

void LocalProcessW::instrumentationCallbackThunk(CONTEXT* const pContext) noexcept
{
	constexpr DWORD trapMask{ ~static_cast<DWORD>(1 >> 8) };

	pContext->EFlags &= trapMask;

	if (!LocalProcessW::getInstance().m_addrICHandler)
		return;

	const DWORD tlsIndex{ LocalProcessW::getInstance().m_ICTlsIndex };

	if (TlsGetValue(tlsIndex))
		return;

	TlsSetValue(tlsIndex, reinterpret_cast<LPVOID>(1));

	reinterpret_cast<void(*)(CONTEXT* const)>(LocalProcessW::getInstance().m_addrICHandler)(pContext);

	TlsSetValue(tlsIndex, nullptr);
}
#endif


uintptr_t LocalProcessW::getNativeProcAddress(const std::wstring& functionName) const noexcept
{
	map::const_iterator it{ m_nativeFunctions.find(functionName) };

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


std::vector<std::pair<DWORD, Process::ModuleExportW>> LocalProcessW::getSyscallIDs(const bool assumeHooked) const noexcept
{
	std::vector<std::pair<DWORD, Process::ModuleExportW>> foundSyscalls;

	const std::vector<Process::ModuleExportW> ntdllExports{ getModuleExports_x64(L"ntdll.dll") };

	if (assumeHooked)
	{
		std::vector<Process::ModuleExportW> syscallExports{};

		for (const Process::ModuleExportW& currExport : ntdllExports)
		{
			const std::string exportName{ currExport.exportName.begin(), currExport.exportName.end() };

			if (!_stricmp(exportName.substr(0, 2).c_str(), "Zw"))
			{
				syscallExports.push_back(currExport);
				Process::ModuleExportW currExportNt{ currExport };
				currExportNt.exportName.replace(0, 2, L"Nt");
				syscallExports.push_back(currExportNt);
			}
		}

		std::sort(syscallExports.begin(), syscallExports.end(), [&](const Process::ModuleExportW& a, const Process::ModuleExportW& b) ->bool { return a.absoluteAddress < b.absoluteAddress; });

		foundSyscalls.resize(syscallExports.size());

		for (size_t iterator{ 0 }; iterator < foundSyscalls.size(); ++iterator)
		{
			foundSyscalls.at(iterator) = { static_cast<DWORD>(iterator), syscallExports.at(iterator) };
		}
	}
	else
	{
		for (const Process::ModuleExportW& currExport : ntdllExports)
		{
			bool syscallFound{ true };

			for (DWORD iterator{ 0 }; iterator < LocalProcess::syscallSignatureW.pattern.size(); ++iterator)
			{
#ifdef _WIN64
				if (LocalProcess::syscallSignatureW.pattern.at(iterator) >= 0 && static_cast<short>(*reinterpret_cast<BYTE*>(currExport.absoluteAddress + iterator)) != LocalProcess::syscallSignatureA.pattern.at(iterator))
#else
				if (LocalProcess::syscallSignatureW.pattern.at(iterator) >= 0 && readByte64Bit(currExport.absoluteAddress + iterator) != LocalProcess::syscallSignatureW.pattern.at(iterator))
#endif
				{
					syscallFound = false;
					break;
				}
			}

			if (!syscallFound)
				continue;

#ifdef _WIN64
			const DWORD syscallID{ *reinterpret_cast<DWORD*>(currExport.absoluteAddress + 4) };
#else
			const DWORD syscallID{ readDword64Bit(currExport.absoluteAddress + 4) };
#endif

			foundSyscalls.push_back(std::pair<DWORD, Process::ModuleExportW>{ syscallID, currExport });
		}

		std::sort(foundSyscalls.begin(), foundSyscalls.end(), [&](const std::pair<DWORD, Process::ModuleExportW>& a, const std::pair<DWORD, Process::ModuleExportW>& b) -> bool { return a.first < b.first; });
	}

	return foundSyscalls;
}

DWORD LocalProcessW::getSyscallID(const std::wstring& exportName) const noexcept
{
	mapD::const_iterator it{ m_syscallIDs.find(exportName) };

	if (it != m_syscallIDs.end())
	{
		return (*it).second;
	}

	return static_cast<DWORD>(-1);
}

NTSTATUS LocalProcessW::invokeSyscall(const DWORD syscallID, const DWORD argCount, ...) const noexcept
{
	if (argCount)
	{
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

#ifdef _WIN64
		const NTSTATUS retVal{ (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSyscall)))(reinterpret_cast<QWORD>(x86_64_SyscallStub), syscallID, argCount, reinterpret_cast<QWORD>(pArgList)) };
#else
		const NTSTATUS retVal{ static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSyscall), 4, reinterpret_cast<QWORD>(x86_64_SyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), reinterpret_cast<QWORD>(pArgList))) };
#endif

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
#ifdef _WIN64
		return (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSyscall)))(reinterpret_cast<QWORD>(x86_64_SyscallStub), syscallID, argCount, 0);
#else
		return static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSyscall), 4, reinterpret_cast<QWORD>(x86_64_SyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), 0));
#endif
	}
}

NTSTATUS LocalProcessW::invokeSpoofedSyscall(const DWORD syscallID, const DWORD argCount, const LocalProcess::SCROPGadgetType ropGadgetType, const QWORD ropGadgetAddress, ...)
{
	if (!ropGadgetAddress)
		return static_cast<NTSTATUS>(-1);

	const std::vector<short>* pRopGadgetSig{ nullptr };

	switch (ropGadgetType)
	{
	case LocalProcess::SCROPGadgetType::jmp_rbx:
	{
		pRopGadgetSig = &LocalProcess::jmp_rbx_gadget;
		break;
	}

	case LocalProcess::SCROPGadgetType::jmp_rbx_ptr:
	{
		pRopGadgetSig = &LocalProcess::jmp_rbx_deref_gadget;
		break;
	}

	case LocalProcess::SCROPGadgetType::jmp_rdi:
	{
		pRopGadgetSig = &LocalProcess::jmp_rdi_gadget;
		break;
	}

	case LocalProcess::SCROPGadgetType::jmp_rdi_ptr:
	{
		pRopGadgetSig = &LocalProcess::jmp_rdi_deref_gadget;
		break;
	}

	case LocalProcess::SCROPGadgetType::jmp_rsi:
	{
		pRopGadgetSig = &LocalProcess::jmp_rsi_gadget;
		break;
	}

	case LocalProcess::SCROPGadgetType::jmp_rsi_ptr:
	{
		pRopGadgetSig = &LocalProcess::jmp_rsi_deref_gadget;
		break;
	}

	default:
		return static_cast<NTSTATUS>(-1);
	}

	std::vector<unsigned char> gadgetCopy{};
	gadgetCopy.resize(pRopGadgetSig->size());

#ifdef _WIN64
	memcpy(gadgetCopy.data(), reinterpret_cast<void*>(ropGadgetAddress), gadgetCopy.size());
#else
	memcpy64Bit(reinterpret_cast<QWORD>(gadgetCopy.data()), ropGadgetAddress, gadgetCopy.size());
#endif
	bool gadgetValid{ true };

	for (size_t iterator{ 0 }; iterator < gadgetCopy.size(); ++iterator)
	{
		if (pRopGadgetSig->at(iterator) < 0 || pRopGadgetSig->at(iterator) > 0xFF)
			continue;

		if (static_cast<unsigned char>(pRopGadgetSig->at(iterator)) != gadgetCopy.at(iterator))
		{
			gadgetValid = false;
			break;
		}
	}

	if (!gadgetValid)
		return static_cast<NTSTATUS>(-1);

	const mapD::const_iterator syscallFound{ std::find_if(m_syscallIDs.begin(), m_syscallIDs.end(), [&](const std::pair<std::wstring, DWORD>& pair)->bool { return pair.second == syscallID; }) };

	if (syscallFound == m_syscallIDs.end())
		return static_cast<NTSTATUS>(-1);

	const std::wstring funcName{ syscallFound->first };

	const QWORD funcAddress{ getProcAddress_x64(L"ntdll.dll", funcName) };

	if (!funcAddress)
		return static_cast<NTSTATUS>(-1);

	const QWORD syscallGadgetAddress{ scanPattern(LocalProcess::syscallGadget, funcAddress, static_cast<DWORD>(30)) };

	if (!syscallGadgetAddress)
		return static_cast<NTSTATUS>(-1);

	if (argCount)
	{
		QWORD* pArgList{ nullptr };

		while (!pArgList)
			pArgList = new QWORD[argCount];

		std::va_list list{};

		va_start(list, ropGadgetAddress);

		for (DWORD iterator{ 0 }; iterator < argCount; ++iterator)
		{
			pArgList[iterator] = va_arg(list, QWORD);
		}

		va_end(list);

#ifdef _WIN64
		const NTSTATUS retVal{ (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSpoofedSyscall)))(reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), syscallID, argCount, reinterpret_cast<QWORD>(pArgList), syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType)) };
#else
		const NTSTATUS retVal{ static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSpoofedSyscall), 7, reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), reinterpret_cast<QWORD>(pArgList), syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType))) };
#endif

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
#ifdef _WIN64
		return (reinterpret_cast<NTSTATUS(* const)(QWORD, QWORD, QWORD, QWORD, QWORD, QWORD, QWORD)>(reinterpret_cast<const void*>(x86_64_PrepareForSpoofedSyscall)))(reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), syscallID, argCount, 0, syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType));
#else
		return static_cast<NTSTATUS>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_PrepareForSpoofedSyscall), 7, reinterpret_cast<QWORD>(x86_64_SpoofedSyscallStub), static_cast<QWORD>(syscallID), static_cast<QWORD>(argCount), 0, syscallGadgetAddress, ropGadgetAddress, static_cast<QWORD>(ropGadgetType)));
#endif
	}
}


#ifndef _WIN64

QWORD LocalProcessW::getNativeProcAddressWow64(const std::wstring& functionName) const noexcept
{
	mapQ::const_iterator it{ m_nativeFunctionsWow64.find(functionName) };

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
	//return call64BitFunction(static_cast<QWORD>(m_shellcodeMemory) + LocalProcess::shellcode::offsetGet64BitPEB);
	return call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadPEBFromReg));
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

	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return newModule;
	}
	*/

	PEB_LDR_DATA64 ldrData{};

	memcpy64Bit(reinterpret_cast<QWORD>(&ldrData), reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<QWORD>(sizeof(ldrData)));

	//if (_NtWow64RVM(m_hProc, reinterpret_cast<PEB64*>(pebAddr)->Ldr, static_cast<PVOID>(&ldrData), sizeof(ldrData), nullptr) != STATUS_SUCCESS)
		//return newModule;

	const QWORD firstEntryAddr{ ldrData.InLoadOrderModuleList.Flink };
	QWORD currEntryAddr{ firstEntryAddr };

	while (currEntryAddr)
	{
		LDR_DATA_TABLE_ENTRY64 currentLoaderEntry{};

		memcpy64Bit(reinterpret_cast<QWORD>(&currentLoaderEntry), currEntryAddr, static_cast<QWORD>(sizeof(currentLoaderEntry)));

		//if (_NtWow64RVM(m_hProc, currEntryAddr, static_cast<PVOID>(&currentLoaderEntry), sizeof(currentLoaderEntry), nullptr) != STATUS_SUCCESS)
			//break;

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

			memcpy64Bit(reinterpret_cast<QWORD>(pModuleName), currentLoaderEntry.BaseDllName.WideStringAddress, static_cast<QWORD>(moduleStringLength));

			//if (_NtWow64RVM(m_hProc, currentLoaderEntry.BaseDllName.WideStringAddress, pModuleName, moduleStringLength, nullptr) == STATUS_SUCCESS)
			//{
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
			//}

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


std::vector<Process::ModuleExportW> LocalProcessW::getModuleExports_x86(const QWORD modBA) const noexcept
{
	std::vector<Process::ModuleExportW> exports{};

#ifdef _WIN64

	return exports;

#else

	if (!modBA || modBA > 0xFFFFFFFF)
		return exports;

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return exports;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x10B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	std::wstring modName{};

	std::vector<Process::ModuleInformationW>::const_iterator foundModule{ std::find_if(m_x86Modules.begin(), m_x86Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x86Modules.end())
		modName = foundModule->modName;
	else
		modName = L"unknown";

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!pNameArray[iterator])
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = pOrdinalArray[iterator];
		currExport.relativeAddress = pExportTable[currExport.ordinal];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;

		std::string ansiString{ reinterpret_cast<const char*>(modBA + pNameArray[iterator]) };
		currExport.exportName = std::wstring{ ansiString.begin(), ansiString.end() };

		currExport.ordinal += Process::ordinalBaseOffset;

		if (currExport.absoluteAddress <= 0xFFFFFFFF)
			exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportW& modExport : exports)
		{
			if (modExport.relativeAddress == pExportTable[iterator])
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = pExportTable[iterator];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = L"unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		if (currExport.absoluteAddress <= 0xFFFFFFFF)
			exports.push_back(currExport);
	}

	std::sort(exports.begin(), exports.end(), [&](const Process::ModuleExportW& a, const Process::ModuleExportW& b) -> bool { return a.ordinal < b.ordinal; });

	return exports;

#endif
}

std::vector<Process::ModuleExportW> LocalProcessW::getModuleExports_x64(const QWORD modBA) const noexcept
{
	std::vector<Process::ModuleExportW> exports{};

	if (!modBA)
		return exports;

#ifdef _WIN64

	const IMAGE_DOS_HEADER* const pIDH{ reinterpret_cast<IMAGE_DOS_HEADER*>(modBA) };

	if (pIDH->e_magic != 0x5A4D)
		return exports;

	const IMAGE_NT_HEADERS* const pNTH{ reinterpret_cast<const IMAGE_NT_HEADERS*>(modBA + pIDH->e_lfanew) };

	if (pNTH->Signature != 0x4550 || pNTH->OptionalHeader.Magic != 0x20B || pNTH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(pNTH->FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	const IMAGE_EXPORT_DIRECTORY* const pIED{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(modBA + pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	const DWORD* const pNameArray{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfNames) };
	const WORD* const pOrdinalArray{ reinterpret_cast<const WORD*>(modBA + pIED->AddressOfNameOrdinals) };
	const DWORD* const pExportTable{ reinterpret_cast<const DWORD*>(modBA + pIED->AddressOfFunctions) };

	std::wstring modName{};

	std::vector<Process::ModuleInformationW>::const_iterator foundModule{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x64Modules.end())
		modName = foundModule->modName;
	else
		modName = L"unknown";

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfNames; ++iterator)
	{
		if (!pNameArray[iterator])
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = pOrdinalArray[iterator];
		currExport.relativeAddress = pExportTable[currExport.ordinal];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;

		std::string ansiString{ reinterpret_cast<const char*>(modBA + pNameArray[iterator]) };
		currExport.exportName = std::wstring{ ansiString.begin(), ansiString.end() };

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < pIED->NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportW& modExport : exports)
		{
			if (modExport.relativeAddress == pExportTable[iterator])
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = pExportTable[iterator];
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = L"unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

#else

	IMAGE_DOS_HEADER idh{};
	memcpy64Bit(reinterpret_cast<QWORD>(&idh), modBA, sizeof(idh));

	if (idh.e_magic != 0x5A4D)
		return exports;

	IMAGE_NT_HEADERS64 nth{};
	memcpy64Bit(reinterpret_cast<QWORD>(&nth), modBA + idh.e_lfanew, sizeof(nth));

	if (nth.Signature != 0x4550 || nth.OptionalHeader.Magic != 0x20B || nth.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(nth.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return exports;
	}

	exports.reserve(2000);

	IMAGE_EXPORT_DIRECTORY ied{};
	memcpy64Bit(reinterpret_cast<QWORD>(&ied), modBA + nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(ied));

	const QWORD pNameArray{ modBA + ied.AddressOfNames };
	const QWORD pOrdinalArray{ modBA + ied.AddressOfNameOrdinals };
	const QWORD pExportTable{ modBA + ied.AddressOfFunctions };

	std::wstring modName{};

	std::vector<Process::ModuleInformationW>::const_iterator foundModule{ std::find_if(m_x64Modules.begin(), m_x64Modules.end(), [&](const Process::ModuleInformationW& mod) -> bool { return mod.modBA.x64Addr == modBA; }) };

	if (foundModule != m_x64Modules.end())
		modName = foundModule->modName;
	else
		modName = L"unknown";

	char nameBuffer[0x102]{};

	for (DWORD iterator{ 0 }; iterator < ied.NumberOfNames; ++iterator)
	{
		const DWORD nameOffset{ readDword64Bit(pNameArray + static_cast<QWORD>(iterator) * sizeof(DWORD)) };

		if (!nameOffset)
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = readWord64Bit(pOrdinalArray + static_cast<QWORD>(iterator) * sizeof(WORD));
		currExport.relativeAddress = readDword64Bit(pExportTable + static_cast<QWORD>(currExport.ordinal) * sizeof(DWORD));
		currExport.absoluteAddress = modBA + currExport.relativeAddress;

		memcpy64Bit(reinterpret_cast<QWORD>(nameBuffer), modBA + nameOffset, 0x100);
		std::string ansiString{ const_cast<const char*>(nameBuffer) };
		currExport.exportName = std::wstring{ ansiString.begin(), ansiString.end() };

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

	for (DWORD iterator{ 0 }; iterator < ied.NumberOfFunctions; ++iterator)
	{
		bool hasName{ false };

		for (Process::ModuleExportW& modExport : exports)
		{
			if (modExport.relativeAddress == readDword64Bit(pExportTable + static_cast<QWORD>(iterator) * sizeof(DWORD)))
			{
				hasName = true;
				break;
			}
		}

		if (hasName)
			continue;

		Process::ModuleExportW currExport{};

		currExport.moduleName = modName;
		currExport.ordinal = static_cast<WORD>(iterator);
		currExport.relativeAddress = readDword64Bit(pExportTable + static_cast<QWORD>(iterator) * sizeof(DWORD));
		currExport.absoluteAddress = modBA + currExport.relativeAddress;
		currExport.exportName = L"unknown";

		currExport.ordinal += Process::ordinalBaseOffset;

		exports.push_back(currExport);
	}

#endif

	std::sort(exports.begin(), exports.end(), [&](const Process::ModuleExportW& a, const Process::ModuleExportW& b) -> bool { return a.ordinal < b.ordinal; });

	return exports;
}


std::vector<Process::ModuleExportW> LocalProcessW::getModuleExports_x86(const std::wstring& modName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getModuleExports_x86(modBA) : std::vector<Process::ModuleExportW>{};
}

std::vector<Process::ModuleExportW> LocalProcessW::getModuleExports_x64(const std::wstring& modName) const noexcept
{
	const QWORD modBA{ getModBA_x64(modName) };

	return (modBA) ? getModuleExports_x64(modBA) : std::vector<Process::ModuleExportW>{};
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

	//return reinterpret_cast<QWORD(__cdecl*)(QWORD, QWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionGetNativeProcAddress)(modBA, reinterpret_cast<QWORD>(aFuncName.c_str()));

	QWORD procAddress{};

	IMAGE_DOS_HEADER dosHeader{};
	memcpy64Bit(reinterpret_cast<QWORD>(&dosHeader), modBA, sizeof(dosHeader));

	if (dosHeader.e_magic != 0x5A4D)
		return 0;

	IMAGE_NT_HEADERS64 ntHeader{};
	memcpy64Bit(reinterpret_cast<QWORD>(&ntHeader), modBA + dosHeader.e_lfanew, sizeof(ntHeader));

	if (ntHeader.Signature != 0x4550 || ntHeader.OptionalHeader.Magic != 0x20B || ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || !(ntHeader.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)))
	{
		return 0;
	}

	IMAGE_EXPORT_DIRECTORY exportDirectory{};
	memcpy64Bit(reinterpret_cast<QWORD>(&exportDirectory), modBA + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(exportDirectory));

	const QWORD namesAddr{ modBA + exportDirectory.AddressOfNames };
	const QWORD ordinalsAddr{ modBA + exportDirectory.AddressOfNameOrdinals };
	const QWORD exportTableAddr{ modBA + exportDirectory.AddressOfFunctions };

	std::vector<DWORD> exportTable{};
	exportTable.resize(exportDirectory.NumberOfFunctions);

	std::vector<WORD> ordinalTable{};
	ordinalTable.resize(exportDirectory.NumberOfNames);

	std::vector<DWORD> nameTable{};
	nameTable.resize(exportDirectory.NumberOfNames);

	memcpy64Bit(reinterpret_cast<QWORD>(exportTable.data()), exportTableAddr, static_cast<QWORD>(exportTable.size()) * sizeof(exportTable.at(0)));
	memcpy64Bit(reinterpret_cast<QWORD>(ordinalTable.data()), ordinalsAddr, static_cast<QWORD>(ordinalTable.size()) * sizeof(ordinalTable.at(0)));
	memcpy64Bit(reinterpret_cast<QWORD>(nameTable.data()), namesAddr, static_cast<QWORD>(nameTable.size()) * sizeof(nameTable.at(0)));

	char nameBuffer[128]{};

	for (DWORD iterator{ 0 }; iterator < exportDirectory.NumberOfNames; ++iterator)
	{
		memcpy64Bit(reinterpret_cast<QWORD>(nameBuffer), modBA + nameTable.at(iterator), sizeof(nameBuffer));

		std::string strTableEntry{ &nameBuffer[0] };

		if (!_stricmp(strTableEntry.c_str(), aFuncName.c_str()))
		{
			const WORD ordinal{ ordinalTable.at(iterator) };
			procAddress = modBA + static_cast<QWORD>(exportTable.at(ordinal));

			break;
		}
	}

	return procAddress;

#endif
}

QWORD LocalProcessW::getProcAddress_x86(const std::wstring& modName, const std::wstring& functionName) const noexcept
{
	const QWORD modBA{ getModBA_x86(modName) };

	return (modBA) ? getProcAddress_x86(modBA, functionName) : 0;
}

QWORD LocalProcessW::getProcAddress_x64(const std::wstring& modName, const std::wstring& functionName) const noexcept
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
		/*
		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
			return 0;
		}

		if (_NtWow64RVM(m_hProc, result + currOffset, &result, sizeof(result), nullptr) != STATUS_SUCCESS)
			return 0;
		*/

		result = readQword64Bit(result + currOffset);

#endif
	}

	result += signature.extra;

	if (signature.relativeAddress)
		result -= getModBA_x64(signature.moduleName);

	return result;
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

std::vector<Process::FoundGadgetW> LocalProcessW::findGadgets(const std::vector<short>& signature, const QWORD startAddress, const QWORD endAddress) const noexcept
{
	std::vector<Process::FoundGadgetW> result{};

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePattern(signature) };

#ifndef _WIN64
	if (startAddress <= 0xFFFFFFFF || endAddress <= 0xFFFFFFFF)
	{
#endif
		MEMORY_BASIC_INFORMATION mbi{};

		for (uintptr_t currAddress{ static_cast<uintptr_t>(startAddress) }; currAddress < static_cast<uintptr_t>(endAddress); currAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + static_cast<uintptr_t>(mbi.RegionSize))
		{
			if (!VirtualQuery(reinterpret_cast<LPCVOID>(currAddress), &mbi, sizeof(mbi)))
				break;

			if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
				continue;

			const DWORD scanSize{ (static_cast<QWORD>(currAddress) + mbi.RegionSize > endAddress) ? static_cast<DWORD>(endAddress - currAddress) : static_cast<DWORD>(mbi.RegionSize) };

			if (!(mbi.Protect & PAGE_EXECUTE))
			{
				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), scanSize, pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};
						Process::ModuleInformationW modInfo{};

						currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
						currGadget.readable = true;
						currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
						currGadget.pattern = pattern;
						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
						{
							currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
							currGadget.moduleName = modInfo.modName;
						}

						result.push_back(currGadget);
					}
				}
			}
			else
			{
				DWORD oldProtect{};

				if (VirtualProtect(reinterpret_cast<LPVOID>(currAddress), scanSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(currAddress), scanSize, pattern) };

					if (addrBuffer.size())
					{
						for (const char* const address : addrBuffer)
						{
							Process::FoundGadgetW currGadget{};
							Process::ModuleInformationW modInfo{};

							currGadget.absoluteAddress = reinterpret_cast<QWORD>(address);
							currGadget.readable = false;
							currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
							currGadget.pattern = pattern;
							currGadget.bytes.clear();
							currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

							if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
							{
								currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
								currGadget.moduleName = modInfo.modName;
							}

							result.push_back(currGadget);
						}
					}

					VirtualProtect(reinterpret_cast<LPVOID>(currAddress), scanSize, oldProtect, &oldProtect);
				}
			}
		}


#ifndef _WIN64
	}
	else
	{
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

		/*
		static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

		if (!_NtWow64RVM)
		{
			_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
			return result;
		}
		*/

		MEMORY_BASIC_INFORMATION64 mbi{};

		for (QWORD currAddress{ startAddress }; currAddress < endAddress; currAddress = mbi.BaseAddress + mbi.RegionSize)
		{
			QWORD returnLength{};

			if (!callNativeFunction(_NtWow64QVM, 6, reinterpret_cast<QWORD>(m_hProc), currAddress, static_cast<QWORD>(MemoryBasicInformation), reinterpret_cast<QWORD>(&mbi), static_cast<QWORD>(sizeof(MEMORY_BASIC_INFORMATION64)), reinterpret_cast<QWORD>(&returnLength)))
				break;

			if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD) || !(mbi.State & MEM_COMMIT) || !mbi.RegionSize)
				continue;

			const DWORD scanSize{ (currAddress + mbi.RegionSize > endAddress) ? static_cast<DWORD>(endAddress - currAddress) : static_cast<DWORD>(mbi.RegionSize) };

			const LPVOID pScanBuffer{ VirtualAlloc(nullptr, scanSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

			if (!pScanBuffer)
				continue;

			if (!(mbi.Protect & PAGE_EXECUTE))
			{
				//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, scanSize, nullptr) != STATUS_SUCCESS)
				//{
					//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					//continue;
				//}

				memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(scanSize));

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(scanSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};
						Process::ModuleInformationW modInfo{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.readable = true;
						currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
						currGadget.pattern = pattern;
						currGadget.bytes.clear();
						currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

						if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
						{
							currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
							currGadget.moduleName = modInfo.modName;
						}

						result.push_back(currGadget);
					}
				}
			}
			else
			{
				DWORD oldProtect{};
				QWORD protectAddress{ currAddress };
				QWORD protectionLength{ scanSize };

				if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
				{
					//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, scanSize, nullptr) != STATUS_SUCCESS)
					//{
						//callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
						//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
						//continue;
					//}

					memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(scanSize));

					callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

					const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(scanSize), pattern) };

					if (addrBuffer.size())
					{
						for (const char* const address : addrBuffer)
						{
							Process::FoundGadgetW currGadget{};
							Process::ModuleInformationW modInfo{};

							currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
							currGadget.readable = false;
							currGadget.writable = !((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READONLY));
							currGadget.pattern = pattern;
							currGadget.bytes.clear();
							currGadget.bytes.insert(currGadget.bytes.end(), address, address + pattern.size());

							if (isModuleAddress(reinterpret_cast<QWORD>(address), &modInfo))
							{
								currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
								currGadget.moduleName = modInfo.modName;
							}

							result.push_back(currGadget);
						}
					}
				}
			}

			VirtualFree(pScanBuffer, 0, MEM_RELEASE);
		}
	}
#endif

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

	for (DWORD currAddress{ modInfo.modBA.x86Addr.dw1 }; currAddress < modInfo.modBA.x86Addr.dw1 + modInfo.modSize; currAddress = reinterpret_cast<DWORD>(mbi.BaseAddress) + mbi.RegionSize)
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
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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

	/*
	static tNtWow64ReadVirtualMemory64 _NtWow64RVM{ reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64")) };

	if (!_NtWow64RVM)
	{
		_NtWow64RVM = reinterpret_cast<tNtWow64ReadVirtualMemory64>(getNativeProcAddress(L"NtWow64ReadVirtualMemory64"));
		return result;
	}
	*/

#endif

	const std::vector<Process::SigByte> pattern{ Process::getSigBytePatternW(signature) };

	const Process::ModuleInformationW modInfo{ getModuleInfo_x64(signature.moduleName) };

	if (!validModule(modInfo))
		return result;

	MEMORY_BASIC_INFORMATION64 mbi{};

	for (QWORD currAddress{ modInfo.modBA.x64Addr }; currAddress < modInfo.modBA.x64Addr + modInfo.modSize; currAddress = mbi.BaseAddress + mbi.RegionSize)
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
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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

		const LPVOID pScanBuffer{ VirtualAlloc(nullptr, static_cast<SIZE_T>(mbi.RegionSize), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

		if (!pScanBuffer)
			continue;

		if (signature.readable)
		{
			//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
			//{
				//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
				//continue;
			//}

			memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(mbi.RegionSize));

			const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

			if (addrBuffer.size())
			{
				for (const char* const address : addrBuffer)
				{
					Process::FoundGadgetW currGadget{};

					currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
					currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
			QWORD protectAddress{ currAddress };
			QWORD protectionLength{ mbi.RegionSize };

			if (callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(PAGE_EXECUTE_READWRITE), reinterpret_cast<QWORD>(&oldProtect)))
			{
				//if (_NtWow64RVM(m_hProc, currAddress, pScanBuffer, mbi.RegionSize, nullptr) != STATUS_SUCCESS)
				//{
					//callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));
					//VirtualFree(pScanBuffer, 0, MEM_RELEASE);
					//continue;
				//}

				memcpy64Bit(reinterpret_cast<QWORD>(pScanBuffer), currAddress, static_cast<QWORD>(mbi.RegionSize));

				callNativeFunction(_NtWow64PVM, 5, reinterpret_cast<QWORD>(m_hProc), reinterpret_cast<QWORD>(&protectAddress), reinterpret_cast<QWORD>(&protectionLength), static_cast<QWORD>(oldProtect), reinterpret_cast<QWORD>(&oldProtect));

				const std::vector<char*> addrBuffer{ findPatternsInBuffer(reinterpret_cast<const char* const>(pScanBuffer), static_cast<DWORD>(mbi.RegionSize), pattern) };

				if (addrBuffer.size())
				{
					for (const char* const address : addrBuffer)
					{
						Process::FoundGadgetW currGadget{};

						currGadget.absoluteAddress = currAddress + (reinterpret_cast<QWORD>(address) - reinterpret_cast<QWORD>(pScanBuffer));
						currGadget.relativeAdddress = static_cast<DWORD>(currGadget.absoluteAddress - modInfo.modBA.x64Addr);
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
		}

		VirtualFree(pScanBuffer, 0, MEM_RELEASE);

#endif
	}

	return result;
}


#ifndef _WIN64

BOOL LocalProcessW::callNativeFunction(const std::wstring& funcName, const DWORD argCount, ...) const noexcept
{
	const QWORD funcAddr{ getNativeProcAddressWow64(funcName) };

	if (!funcAddr)
		return FALSE;

	if (argCount)
	{
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

		//const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

		const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) == STATUS_SUCCESS) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0) == STATUS_SUCCESS);
	}
}

BOOL LocalProcessW::callNativeFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr)
		return FALSE;

	if (argCount)
	{
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

		//const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) == STATUS_SUCCESS) };

		const BOOL retVal{ static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) == STATUS_SUCCESS) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return static_cast<BOOL>(reinterpret_cast<LONG(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0) == STATUS_SUCCESS);
	}
}


QWORD LocalProcessW::call64BitFunction(const QWORD funcAddr, const DWORD argCount, ...) const noexcept
{
	if (!funcAddr)
		return 0;

	if (argCount)
	{
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

		//const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(m_shellcodeMemory + LocalProcess::shellcode::offsetFunctionCallNativeFunction)(funcAddr, reinterpret_cast<DWORD>(pArgList), argCount) };

		const QWORD retVal{ reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, reinterpret_cast<DWORD>(pArgList)) };

		delete[] pArgList;
		pArgList = nullptr;

		return retVal;
	}
	else
	{
		return reinterpret_cast<QWORD(__cdecl*)(QWORD, DWORD, DWORD)>(static_cast<const void*>(x86_32_Call64BitFunction))(funcAddr, argCount, 0);
	}
}


BYTE LocalProcessW::readByte64Bit(const QWORD address) const noexcept
{
	return static_cast<BYTE>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadByte), address));
}

WORD LocalProcessW::readWord64Bit(const QWORD address) const noexcept
{
	return static_cast<WORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadWord), address));
}

DWORD LocalProcessW::readDword64Bit(const QWORD address) const noexcept
{
	return static_cast<DWORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadDword), address));
}
QWORD LocalProcessW::readQword64Bit(const QWORD address) const noexcept
{
	return static_cast<QWORD>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_ReadQword), address));
}


bool LocalProcessW::writeByte64Bit(const QWORD address, const BYTE value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteByte), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessW::writeWord64Bit(const QWORD address, const WORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteWord), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessW::writeDword64Bit(const QWORD address, const DWORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteDword), 2, address, static_cast<QWORD>(value)));
}

bool LocalProcessW::writeQword64Bit(const QWORD address, const QWORD value) const noexcept
{
	return static_cast<bool>(call64BitFunction(reinterpret_cast<QWORD>(x86_64_WriteByte), 2, address, value));
}


QWORD LocalProcessW::memcpy64Bit(const QWORD pDst, const QWORD pSrc, const QWORD size) const noexcept
{
	return call64BitFunction(reinterpret_cast<QWORD>(x86_64_memcpy), 3, pDst, pSrc, size);
}

#endif