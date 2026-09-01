#pragma once
#pragma warning(push)
#pragma warning(disable: 4201)

#include <stdint.h>

#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)
#define in_range(x,a,b)    (x >= a && x <= b)
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_i(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)

typedef short WORD;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef struct _RTL_CRITICAL_SECTION
{
	VOID* DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	VOID* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG SpareUlong;
	VOID* FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID** ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	VOID* ActivationContextData;
	VOID* ProcessAssemblyStorageMap;
	VOID* SystemDefaultActivationContextData;
	VOID* SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	VOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, * PPEB;


typedef union _virt_addr_t
{
	void* value;
	struct
	{
		uintptr_t offset : 12;
		uintptr_t pt_index : 9;
		uintptr_t pd_index : 9;
		uintptr_t pdpt_index : 9;
		uintptr_t pml4_index : 9;
		uintptr_t reserved : 16;
	};
} virt_addr_t, * pvirt_addr_t;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef struct _MI_ACTIVE_PFN
{
	union
	{
		struct
		{
			struct
			{
				 unsigned __int64 Tradable : 1;
				 unsigned __int64 NonPagedBuddy : 43;
			};
		}  Leaf;
		struct
		{
			struct
			{
				 unsigned __int64 Tradable : 1;
				 unsigned __int64 WsleAge : 3;
				 unsigned __int64 OldestWsleLeafEntries : 10;
				 unsigned __int64 OldestWsleLeafAge : 3;
				 unsigned __int64 NonPagedBuddy : 43;
			};
		}  PageTable;
		 unsigned __int64 EntireActiveField;
	};
} MI_ACTIVE_PFN, * PMI_ACTIVE_PFN;

typedef struct _MMPTE_HARDWARE
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 Dirty1 : 1;
		 unsigned __int64 Owner : 1;
		 unsigned __int64 WriteThrough : 1;
		 unsigned __int64 CacheDisable : 1;
		 unsigned __int64 Accessed : 1;
		 unsigned __int64 Dirty : 1;
		 unsigned __int64 LargePage : 1;
		 unsigned __int64 Global : 1;
		 unsigned __int64 CopyOnWrite : 1;
		 unsigned __int64 Unused : 1;
		 unsigned __int64 Write : 1;
		 unsigned __int64 PageFrameNumber : 40;
		 unsigned __int64 ReservedForSoftware : 4;
		 unsigned __int64 WsleAge : 4;
		 unsigned __int64 WsleProtection : 3;
		 unsigned __int64 NoExecute : 1;
	};
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE_PROTOTYPE
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 DemandFillProto : 1;
		 unsigned __int64 HiberVerifyConverted : 1;
		 unsigned __int64 ReadOnly : 1;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 Combined : 1;
		 unsigned __int64 Unused1 : 4;
		 __int64 ProtoAddress : 48;
	};
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE;

typedef struct _MMPTE_SOFTWARE
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 PageFileReserved : 1;
		 unsigned __int64 PageFileAllocated : 1;
		 unsigned __int64 ColdPage : 1;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 Transition : 1;
		 unsigned __int64 PageFileLow : 4;
		 unsigned __int64 UsedPageTableEntries : 10;
		 unsigned __int64 ShadowStack : 1;
		 unsigned __int64 Unused : 5;
		 unsigned __int64 PageFileHigh : 32;
	};
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;

typedef struct _MMPTE_TIMESTAMP
{
	struct
	{
		 unsigned __int64 MustBeZero : 1;
		 unsigned __int64 Unused : 3;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 Transition : 1;
		 unsigned __int64 PageFileLow : 4;
		 unsigned __int64 Reserved : 16;
		 unsigned __int64 GlobalTimeStamp : 32;
	};
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP;

typedef struct _MMPTE_TRANSITION
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 Write : 1;
		 unsigned __int64 Spare : 1;
		 unsigned __int64 IoTracker : 1;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 Transition : 1;
		 unsigned __int64 PageFrameNumber : 40;
		 unsigned __int64 Unused : 12;
	};
} MMPTE_TRANSITION, * PMMPTE_TRANSITION;

typedef struct _MMPTE_SUBSECTION
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 Unused0 : 3;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 ColdPage : 1;
		 unsigned __int64 Unused1 : 3;
		 unsigned __int64 ExecutePrivilege : 1;
		 __int64 SubsectionAddress : 48;
	};
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION;

typedef struct _MMPTE_LIST
{
	struct
	{
		 unsigned __int64 Valid : 1;
		 unsigned __int64 OneEntry : 1;
		 unsigned __int64 filler0 : 2;
		 unsigned __int64 SwizzleBit : 1;
		 unsigned __int64 Protection : 5;
		 unsigned __int64 Prototype : 1;
		 unsigned __int64 Transition : 1;
		 unsigned __int64 filler1 : 16;
		 unsigned __int64 NextEntry : 36;
	};
} MMPTE_LIST, * PMMPTE_LIST;

typedef struct _MMPTE
{
	union
	{
		union
		{
			 unsigned __int64 Long;
			 volatile unsigned __int64 VolatileLong;
			 struct _MMPTE_HARDWARE Hard;
			 struct _MMPTE_PROTOTYPE Proto;
			 struct _MMPTE_SOFTWARE Soft;
			 struct _MMPTE_TIMESTAMP TimeStamp;
			 struct _MMPTE_TRANSITION Trans;
			 struct _MMPTE_SUBSECTION Subsect;
			 struct _MMPTE_LIST List;
		};
	}  u;
} MMPTE, * PMMPTE;

typedef struct _MIPFNBLINK
{
	union
	{
		struct
		{
			 unsigned __int64 Blink : 40;
			 unsigned __int64 NodeBlinkLow : 19;
			 unsigned __int64 TbFlushStamp : 3;
			 unsigned __int64 PageBlinkDeleteBit : 1;
			 unsigned __int64 PageBlinkLockBit : 1;
		};
		struct
		{
			 unsigned __int64 ShareCount : 62;
			 unsigned __int64 PageShareCountDeleteBit : 1;
			 unsigned __int64 PageShareCountLockBit : 1;
		};
		 unsigned __int64 EntireField;
		 volatile __int64 Lock;
		struct
		{
			 unsigned __int64 LockNotUsed : 62;
			 unsigned __int64 DeleteBit : 1;
			 unsigned __int64 LockBit : 1;
		};
	};
} MIPFNBLINK, * PMIPFNBLINK;

typedef struct _MMPFNENTRY1
{
	struct
	{
		 unsigned char PageLocation : 3;
		 unsigned char WriteInProgress : 1;
		 unsigned char Modified : 1;
		 unsigned char ReadInProgress : 1;
		 unsigned char CacheAttribute : 2;
	};
} MMPFNENTRY1, * PMMPFNENTRY1;

typedef struct _MMPFNENTRY3
{
	struct
	{
		 unsigned char Priority : 3;
		 unsigned char OnProtectedStandby : 1;
		 unsigned char InPageError : 1;
		 unsigned char SystemChargedPage : 1;
		 unsigned char RemovalRequested : 1;
		 unsigned char ParityError : 1;
	};
} MMPFNENTRY3, * PMMPFNENTRY3;

typedef struct _MI_PFN_ULONG5
{
	union
	{
		 unsigned long EntireField;
		struct
		{
			struct
			{
				 unsigned long NodeBlinkHigh : 21;
				 unsigned long NodeFlinkMiddle : 11;
			};
		}  StandbyList;
		struct
		{
			 unsigned char ModifiedListBucketIndex : 4;
		}  MappedPageList;
		struct
		{
			struct
			{
				 unsigned char AnchorLargePageSize : 2;
				 unsigned char Spare1 : 6;
			};
			 unsigned char ViewCount;
			 unsigned short Spare2;
		}  Active;
	};
} MI_PFN_ULONG5, * PMI_PFN_ULONG5;

typedef struct _MMPFN
{
	union
	{
		 struct _LIST_ENTRY ListEntry;
		 struct _RTL_BALANCED_NODE TreeNode;
		struct
		{
			union
			{
				union
				{
					 struct _SINGLE_LIST_ENTRY NextSlistPfn;
					 void* Next;
					struct
					{
						 unsigned __int64 Flink : 40;
						 unsigned __int64 NodeFlinkLow : 24;
					};
					 struct _MI_ACTIVE_PFN Active;
				};
			}  u1;
			union
			{
				 struct _MMPTE* PteAddress;
				 unsigned __int64 PteLong;
			};
			 struct _MMPTE OriginalPte;
		};
	};
	 struct _MIPFNBLINK u2;
	union
	{
		union
		{
			struct
			{
				 unsigned short ReferenceCount;
				 struct _MMPFNENTRY1 e1;
				 struct _MMPFNENTRY3 e3;
			};
			struct
			{
				 unsigned short ReferenceCount;
			}  e2;
			struct
			{
				 unsigned long EntireField;
			}  e4;
		};
	}  u3;
	 struct _MI_PFN_ULONG5 u5;
	union
	{
		union
		{
			struct
			{
				 unsigned __int64 PteFrame : 40;
				 unsigned __int64 ResidentPage : 1;
				 unsigned __int64 Unused1 : 1;
				 unsigned __int64 Unused2 : 1;
				 unsigned __int64 Partition : 10;
				 unsigned __int64 FileOnly : 1;
				 unsigned __int64 PfnExists : 1;
				 unsigned __int64 NodeFlinkHigh : 5;
				 unsigned __int64 PageIdentity : 3;
				 unsigned __int64 PrototypePte : 1;
			};
			 unsigned __int64 EntireField;
		};
	}  u4;
} MMPFN, * PMMPFN;

#pragma warning(pop)
