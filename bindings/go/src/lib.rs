use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn zlicenser_server_hello_world() -> *const c_char {
    b"hello from zlicenser-server\0".as_ptr() as *const c_char
}
