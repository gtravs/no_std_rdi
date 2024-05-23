// DLL HASH
pub static HASH_KERNEL32: u32 = 0x7040EE75;
pub static HASH_NTDLL: u32 = 0x22D3B5ED;
pub static HASH_MSVCRT: u32 = 0xFF6C2F6E;
pub static HASH_USER32: u32 = 0xD919AFD3;
pub static HASH_WINHTTP: u32 = 0xe6778b5d;

// FUNC HASH
pub static HASH_LOAD_LIBRARY_A: u32 = 0x5FBFF0FB;
pub static HASH_GET_PROC_ADDRESS: u32 = 0xCF31BB1F;
pub static HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x6793C34C;
pub static HASH_MESSAGE_BOX_A: u32 = 0x384F14B4;
pub static HASH_VIRTUAL_PROTECT: u32 = 0x844ff18d;
pub static HASH_VIRTUAL_ALLOC: u32 = 0x382c0f97;
pub static HASH_WIN_HTTP_OPEN: u32 = 0x5e4f39e5;
pub static HASH_WIN_HTTP_CONNECT: u32 = 0x7242c17d;
pub static HASH_WIN_HTTP_OPEN_REQUEST: u32 = 0xeab7b9ce;
pub static HASH_WIN_HTTP_SEND_REQUEST: u32 = 0xb183faa6;
pub static HASH_WIN_HTTP_RECEIVE_RESPONSE: u32 = 0x146c4925;
pub static HASH_WIN_HTTP_READ_DATA: u32 = 0x7195e4e9;
pub static HASH_WIN_HTTP_QUERY_DATA_AVAILABLE: u32 = 0x34cb8684;
pub static HASH_WIN_HTTP_CLOSE_HANDLE: u32 = 0x36220cd5;
pub static HASH_GET_CONSOLE_WINDOW: u32 = 0xe1db2410;
pub static HASH_SHOW_WINDOW: u32 = 0xe321461e;

pub static HASH_LOAD: u32 = 0x7c9a2d85;
pub static HASH_DLLMAIN: u32 = 0x79f31ec6;

pub fn hash_djb2(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for x in s.chars() {
        hash = ((hash << 5) + hash).wrapping_add(x as u32);
        hash = hash & 0xFFFFFFFF;
    }
    hash
}




