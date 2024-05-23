use core::ffi::{c_long, c_uchar, c_ulong, c_ushort, c_void};
use core::ffi::{c_char, c_int, c_uint};
use core::ptr::null_mut;

/*
    相关 struct PEB
 */

#[repr(C)]
pub struct PEB {
    Reserved1: [u8; 2],
    BeingDebugged: u8,
    Reserved2: u8,
    Reserved3: [usize; 2],
    pub(crate) ldr: *mut PEB_LDR_DATA,
    pub(crate) process_parameters: *mut RTL_USER_PROCESS_PARAMETERS,
    // 其他字段省略
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    Reserved1: [u8; 16],
    Reserved2: [*mut c_void; 10],
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    // 其他字段省略
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut c_void,
    InLoadOrderModuleList: LIST_ENTRY,
    pub(crate) in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub(crate) flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PWSTR(pub *mut u16);

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

impl ::core::marker::Copy for UNICODE_STRING {}

impl ::core::clone::Clone for UNICODE_STRING {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub(crate) InLoadOrderLinks: LIST_ENTRY,
    pub(crate) InMemoryOrderLinks: LIST_ENTRY,
    pub(crate) InInitializationOrderLinks: LIST_ENTRY,
    pub(crate) DllBase: *mut c_void,
    pub(crate) EntryPoint: *mut c_void,
    pub(crate) SizeOfImage: u32,
    pub(crate) FullDllName: UNICODE_STRING,
    pub(crate) BaseDllName: UNICODE_STRING,
}

/*
    PE 结构
 */


pub type __uint64 = u64;
pub type ULONGLONG = __uint64;

pub type DWORD = c_ulong;
pub type WORD = c_ushort;
pub type LONG = c_long;
pub type BYTE = c_uchar;
#[link_section = ".text$z"]
#[macro_export]
macro_rules! STRUCT {
    (#[debug] $($rest:tt)*) => (
        STRUCT!{#[cfg_attr(feature = "impl-debug", derive(Debug))] $($rest)*}
    );
    ($(#[$attrs:meta])* struct $name:ident {
        $($field:ident: $ftype:ty,)+
    }) => (
        #[repr(C)] #[derive(Copy)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> $name { *self }
        }
        #[cfg(feature = "impl-default")]
        impl Default for $name {
            #[inline]
            fn default() -> $name { unsafe { $crate::_core::mem::zeroed() } }
        }
    );
}

STRUCT! {struct IMAGE_DOS_HEADER {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [WORD; 4],
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [WORD; 10],
    e_lfanew: LONG,
}}
pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;
macro_rules! IFDEF {
    ($($thing:item)*) => ($($thing)*)
}
macro_rules! DECLARE_HANDLE {
    ($name:ident, $inner:ident) => {
        pub enum $inner {}
        pub type $name = *mut $inner;
    };
}

DECLARE_HANDLE! {HINSTANCE, HINSTANCE__}
pub type HMODULE = HINSTANCE;
pub type CHAR = c_char;
pub type LPCSTR = *const CHAR;

pub enum __some_function {}

/// Pointer to a function with unknown type signature.
pub type FARPROC = *mut __some_function;
pub type HANDLE = *mut c_void;
pub type ULONG_PTR = usize;
pub type SIZE_T = ULONG_PTR;
pub type NTSTATUS = LONG;
DECLARE_HANDLE! {HWND, HWND__}
pub type UINT = c_uint;
pub type INT = c_int;

pub const IMAGE_DIRECTORY_ENTRY_IMPORT: WORD = 1;
macro_rules! UNION {
    ($(#[$attrs:meta])* union $name:ident {
        [$stype:ty; $ssize:expr],
        $($variant:ident $variant_mut:ident: $ftype:ty,)+
    }) => (
        #[repr(C)] $(#[$attrs])*
        pub struct $name([$stype; $ssize]);
        impl Copy for $name {}
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> $name { *self }
        }
        #[cfg(feature = "impl-default")]
        impl Default for $name {
            #[inline]
            fn default() -> $name { unsafe { $crate::_core::mem::zeroed() } }
        }
        impl $name {$(
            #[inline]
            pub unsafe fn $variant(&self) -> &$ftype {
                &*(self as *const _ as *const $ftype)
            }
            #[inline]
            pub unsafe fn $variant_mut(&mut self) -> &mut $ftype {
                &mut *(self as *mut _ as *mut $ftype)
            }
        )+}
    );
    ($(#[$attrs:meta])* union $name:ident {
        [$stype32:ty; $ssize32:expr] [$stype64:ty; $ssize64:expr],
        $($variant:ident $variant_mut:ident: $ftype:ty,)+
    }) => (
        #[repr(C)] $(#[$attrs])* #[cfg(target_pointer_width = "32")]
        pub struct $name([$stype32; $ssize32]);
        #[repr(C)] $(#[$attrs])* #[cfg(target_pointer_width = "64")]
        pub struct $name([$stype64; $ssize64]);
        impl Copy for $name {}
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> $name { *self }
        }
        #[cfg(feature = "impl-default")]
        impl Default for $name {
            #[inline]
            fn default() -> $name { unsafe { $crate::_core::mem::zeroed() } }
        }
        impl $name {$(
            #[inline]
            pub unsafe fn $variant(&self) -> &$ftype {
                &*(self as *const _ as *const $ftype)
            }
            #[inline]
            pub unsafe fn $variant_mut(&mut self) -> &mut $ftype {
                &mut *(self as *mut _ as *mut $ftype)
            }
        )+}
    );
}

#[cfg(target_pointer_width = "64")]
IFDEF! {
pub type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
pub type PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64;
}

STRUCT! {struct IMAGE_NT_HEADERS64 {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}}
pub type PIMAGE_NT_HEADERS64 = *mut IMAGE_NT_HEADERS64;

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;


UNION! {union IMAGE_SECTION_HEADER_Misc {
    [u32; 1],
    PhysicalAddress PhysicalAddress_mut: DWORD,
    VirtualSize VirtualSize_mut: DWORD,
}}
STRUCT! {struct IMAGE_SECTION_HEADER {
    Name: [BYTE; IMAGE_SIZEOF_SHORT_NAME],
    Misc: IMAGE_SECTION_HEADER_Misc,
    VirtualAddress: DWORD,
    SizeOfRawData: DWORD,
    PointerToRawData: DWORD,
    PointerToRelocations: DWORD,
    PointerToLinenumbers: DWORD,
    NumberOfRelocations: WORD,
    NumberOfLinenumbers: WORD,
    Characteristics: DWORD,
}}

UNION! {union IMAGE_THUNK_DATA64_u1 {
    [u64; 1],
    ForwarderString ForwarderString_mut: ULONGLONG,
    Function Function_mut: ULONGLONG,
    Ordinal Ordinal_mut: ULONGLONG,
    AddressOfData AddressOfData_mut: ULONGLONG,
}}
STRUCT! {struct IMAGE_THUNK_DATA64 {
    u1: IMAGE_THUNK_DATA64_u1,
}}

UNION! {union IMAGE_IMPORT_DESCRIPTOR_u {
    [u32; 1],
    Characteristics Characteristics_mut: DWORD,
    OriginalFirstThunk OriginalFirstThunk_mut: DWORD,
}}
STRUCT! {struct IMAGE_IMPORT_DESCRIPTOR {
    u: IMAGE_IMPORT_DESCRIPTOR_u,
    TimeDateStamp: DWORD,
    ForwarderChain: DWORD,
    Name: DWORD,
    FirstThunk: DWORD,
}}

STRUCT! {struct IMAGE_IMPORT_BY_NAME {
    Hint: WORD,
    Name: [CHAR; 1],
}}

STRUCT! {struct IMAGE_BASE_RELOCATION {
    VirtualAddress: DWORD,
    SizeOfBlock: DWORD,
}}

pub const IMAGE_REL_BASED_DIR64: WORD = 10;
pub const IMAGE_REL_BASED_HIGHLOW: WORD = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: WORD = 5;
pub const IMAGE_ORDINAL_FLAG64: ULONGLONG = 0x8000000000000000;
pub const IMAGE_ORDINAL_FLAG32: DWORD = 0x80000000;
STRUCT! {struct IMAGE_FILE_HEADER {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
}}
STRUCT! {struct IMAGE_OPTIONAL_HEADER64 {
    Magic: WORD,
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: ULONGLONG,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: ULONGLONG,
    SizeOfStackCommit: ULONGLONG,
    SizeOfHeapReserve: ULONGLONG,
    SizeOfHeapCommit: ULONGLONG,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}}
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
STRUCT! {struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: DWORD,
    Size: DWORD,
}}

STRUCT! {struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: DWORD,
    TimeDateStamp: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    Name: DWORD,
    Base: DWORD,
    NumberOfFunctions: DWORD,
    NumberOfNames: DWORD,
    AddressOfFunctions: DWORD,
    AddressOfNames: DWORD,
    AddressOfNameOrdinals: DWORD,
}}
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: WORD = 0;

pub type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;


/*
    函数签名
*/

pub type LoadLibraryAFn = unsafe extern "system" fn(lpLibFileName: *const i8) -> *mut u8;
pub type GetProcAddressFn = unsafe extern "system" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;
pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut core::ffi::c_void,
    ZeroBits: usize,
    RegionSize: *mut SIZE_T,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS;
pub type MessageBoxAFn = unsafe extern "system" fn(
    hWnd: HWND,
    lpText: LPCSTR,
    lpCaption: LPCSTR,
    uType: UINT,
) -> INT;

// 定义 VirtualProtect 函数类型
pub type VirtualProtectFn = unsafe extern "system" fn(
    lpAddress: *mut c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> bool;

// 定义内存保护常量
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_READONLY: u32 = 0x02;

pub type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void;


// 定义所需的 WinHTTP 函数类型
pub type WinHttpOpenFn = unsafe extern "system" fn(
    pwszUserAgent: *const u16,
    dwAccessType: u32,
    pwszProxyName: *const u16,
    pwszProxyBypass: *const u16,
    dwFlags: u32,
) -> *mut c_void;

pub type WinHttpConnectFn = unsafe extern "system" fn(
    hSession: *mut c_void,
    pswzServerName: *const u16,
    nServerPort: u16,
    dwReserved: u32,
) -> *mut c_void;

pub type WinHttpOpenRequestFn = unsafe extern "system" fn(
    hConnect: *mut c_void,
    pwszVerb: *const u16,
    pwszObjectName: *const u16,
    pwszVersion: *const u16,
    pwszReferrer: *const u16,
    ppwszAcceptTypes: *const *const u16,
    dwFlags: u32,
) -> *mut c_void;

pub type WinHttpSendRequestFn = unsafe extern "system" fn(
    hRequest: *mut c_void,
    pwszHeaders: *const u16,
    dwHeadersLength: u32,
    lpOptional: *mut c_void,
    dwOptionalLength: u32,
    dwTotalLength: u32,
    dwContext: usize,
) -> i32;

pub type WinHttpReceiveResponseFn = unsafe extern "system" fn(
    hRequest: *mut c_void,
    lpReserved: *mut c_void,
) -> i32;

pub type WinHttpQueryDataAvailableFn = unsafe extern "system" fn(
    hRequest: *mut c_void,
    lpdwNumberOfBytesAvailable: *mut u32,
) -> i32;

pub type WinHttpReadDataFn = unsafe extern "system" fn(
    hRequest: *mut c_void,
    lpBuffer: *mut c_void,
    dwNumberOfBytesToRead: u32,
    lpdwNumberOfBytesRead: *mut u32,
) -> i32;

pub type WinHttpCloseHandleFn = unsafe extern "system" fn(hInternet: *mut c_void) -> i32;

pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
pub const WINHTTP_NO_PROXY_NAME: *const u16 = null_mut();
pub const WINHTTP_NO_PROXY_BYPASS: *const u16 = null_mut();
pub const WINHTTP_NO_ADDITIONAL_HEADERS: *const u16 = null_mut();
pub const WINHTTP_NO_REQUEST_DATA: *mut c_void = null_mut();
pub const WINHTTP_NO_REFERER: *const u16 = null_mut();
pub const WINHTTP_DEFAULT_ACCEPT_TYPES: *const *const u16 = null_mut();


type BOOL = i32;
pub type GetConsoleWindowFn = unsafe extern "system" fn() -> *mut c_void;
pub type ShowWindowFn = unsafe extern "system" fn(hWnd: *mut c_void, nCmdShow: c_int) -> BOOL;