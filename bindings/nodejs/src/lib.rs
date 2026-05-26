use napi_derive::napi;

#[napi]
pub fn hello_world() -> String {
    zlicenser_server::hello_world().to_string()
}
