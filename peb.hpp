#include <Windows.h>
#include "ntdll.h"

using QWORD = DWORD64;

#pragma pack(push)
#pragma pack(1)
template <class T>
struct LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE BitField;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    T CrossProcessFlags;
    T UserSharedInfoPtr;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    T ApiSetMap;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T HotpatchInformation;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    T ActiveProcessAffinityMask;
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    DWORD FlsBitmapBits[4];
    T FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pContextData;
    T pImageHeaderHash;
    T TracingFlags;
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
#pragma pack(pop)
/*
struct LIST_ENTRY32
{
    DWORD Flink{};
    DWORD Blink{};
};

struct LIST_ENTRY64
{
    QWORD Flink{};
    QWORD Blink{};
};
*/
struct UNICODE_STRING32
{
    WORD Length{};
    WORD MaximumLength{};
    DWORD WideStringAddress{};
};

struct UNICODE_STRING64
{
    WORD Length{};
    WORD MaximumLength{};
    DWORD padding{};
    QWORD WideStringAddress{};
};

typedef struct _UNICODE_STRING_WOW64 {
    USHORT Length;
    USHORT MaximumLength;
    PVOID64 Buffer;
} UNICODE_STRING_WOW64;

struct PEB_LDR_DATA32
{
    ULONG Length{};
    BOOLEAN Initialized{};
    DWORD SsHandle{};
    LIST_ENTRY32 InLoadOrderModuleList{};
    LIST_ENTRY32 InMemoryOrderModuleList{};
    LIST_ENTRY32 InInitializationOrderModuleList{};
    DWORD EntryInProgress{};
    BOOLEAN ShutdownInProgress{};
    DWORD ShutdownThreadId{};
};

struct PEB_LDR_DATA64
{
    ULONG Length{};
    BOOLEAN Initialized{};
    QWORD SsHandle{};
    LIST_ENTRY64 InLoadOrderModuleList{};
    LIST_ENTRY64 InMemoryOrderModuleList{};
    LIST_ENTRY64 InInitializationOrderModuleList{};
    QWORD EntryInProgress{};
    BOOLEAN ShutdownInProgress{};
    QWORD ShutdownThreadId{};
};

struct RTL_BALANCED_NODE32
{
    union
    {
        DWORD pChildren[2]{};
        struct
        {
            DWORD Left;
            DWORD Right;
        };
    };
    union
    {
        DWORD Red : 1;
        DWORD Balance : 2;
        DWORD ParentValue;
    };
};

struct RTL_BALANCED_NODE64
{
    union
    {
        QWORD pChildren[2]{};
        struct
        {
            QWORD Left;
            QWORD Right;
        };
    };
    union
    {
        QWORD Red : 1;
        QWORD Balance : 2;
        QWORD ParentValue;
    };
};

//LDR_DATA_TABLE_ENTRY structs are not very accurate in the end (after tlsIndex), but idfc

struct LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks{};
    LIST_ENTRY32 InMemoryOrderLinks{};
    union 
    {
        LIST_ENTRY32 InInitializationOrderLinks{};
        LIST_ENTRY32 InProgressLinks;
    };

    DWORD DllBase;
    DWORD EntryPoint;
    ULONG SizeOfImage{};
    UNICODE_STRING32 FullDllName{};
    UNICODE_STRING32 BaseDllName{};

    union 
    {
        UCHAR FlagGroup[4]{};
        ULONG Flags;

        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };

    USHORT ObsoleteLoadCount{};
    USHORT TlsIndex{};
    LIST_ENTRY32 HashLinks{};
    ULONG TimeDateStamp{};
    LIST_ENTRY32 NodeModuleLink{};
    RTL_BALANCED_NODE32 BaseAddressIndexNode{};
    RTL_BALANCED_NODE32 MappingInfoIndexNode{};
    LARGE_INTEGER LoadTime{};
    ULONG BaseNameHashValue{};
    LDR_DLL_LOAD_REASON LoadReason{};
    ULONG ImplicitPathOptions{};
    ULONG ReferenceCount{};
};

struct LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks{};
    LIST_ENTRY64 InMemoryOrderLinks{};
    union
    {
        LIST_ENTRY64 InInitializationOrderLinks{};
        LIST_ENTRY64 InProgressLinks;
    };

    QWORD DllBase;
    QWORD EntryPoint;
    ULONG SizeOfImage{};
    UNICODE_STRING64 FullDllName{};
    UNICODE_STRING64 BaseDllName{};

    union
    {
        UCHAR FlagGroup[4]{};
        ULONG Flags;

        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };

    USHORT ObsoleteLoadCount{};
    USHORT TlsIndex{};
    LIST_ENTRY64 HashLinks{};
    ULONG TimeDateStamp{};
    LIST_ENTRY64 NodeModuleLink{};
    RTL_BALANCED_NODE64 BaseAddressIndexNode{};
    RTL_BALANCED_NODE64 MappingInfoIndexNode{};
    LARGE_INTEGER LoadTime{};
    ULONG BaseNameHashValue{};
    LDR_DLL_LOAD_REASON LoadReason{};
    ULONG ImplicitPathOptions{};
    ULONG ReferenceCount{};
};

struct PROCESS_BASIC_INFORMATION64
{
    NTSTATUS ExitStatus{};
    QWORD PEB_BaseAddress{};
    QWORD AffinityMask{};
    KPRIORITY BasePriority{};
    QWORD UniqueProcessID{};
    QWORD InheritedFromUniqueProcessID{};
};

struct PROCESS_BASIC_INFORMATION32
{
    NTSTATUS ExitStatus{};
    DWORD PEB_BaseAddress{};
    DWORD AffinityMask{};
    KPRIORITY BasePriority{};
    DWORD UniqueProcessID{};
    DWORD InheritedFromUniqueProcessID{};
};

typedef struct _PROCESS_BASIC_INFORMATION_WOW64
{
    NTSTATUS ExitStatus;
    QWORD  PEB_BaseAddress;
    QWORD  AffinityMask;
    KPRIORITY BasePriority;
    QWORD  UniqueProcessID;
    QWORD  InheritedFromUniqueProcessID;

} PROCESS_BASIC_INFORMATION_WOW64, * PPROCESS_BASIC_INFORMATION_WOW64;

