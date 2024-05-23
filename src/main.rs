#![no_std]
#![no_main]
#![feature(lang_items, alloc_error_handler)]

extern crate alloc;

use core::panic::PanicInfo;

use crate::core_link::bootstrapper::config::init;
use crate::core_link::bootstrapper::Instance::ALLOCATOR;
use crate::core_link::module_loader::load_dll;

mod core_link;

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe {
        // 设置堆的大小
        const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        ALLOCATOR.lock().init(HEAP.as_ptr() as *mut u8, HEAP_SIZE);
    }
    init();
    load_dll();
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}