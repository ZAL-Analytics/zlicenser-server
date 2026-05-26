use pyo3::prelude::*;

#[pyfunction]
fn hello_world() -> &'static str {
    zlicenser_server::hello_world()
}

#[pymodule]
fn _lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    Ok(())
}
