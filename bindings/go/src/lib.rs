use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn zlicenser_server_hello_world() -> *const c_char {
    c"hello from zlicenser-server".as_ptr()
}
