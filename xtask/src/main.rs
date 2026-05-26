use std::env;

fn main() -> anyhow::Result<()> {
    match env::args().nth(1).as_deref() {
        Some("build-all") => build_all(),
        Some("test-all") => test_all(),
        Some("release") => release(),
        Some("regenerate-bindings") => regenerate_bindings(),
        Some("build-dashboard") => build_dashboard(),
        _ => {
            eprintln!("usage: cargo xtask <task>");
            eprintln!("tasks: build-all, test-all, release, regenerate-bindings, build-dashboard");
            Ok(())
        }
    }
}

fn build_all() -> anyhow::Result<()> {
    Ok(())
}

fn test_all() -> anyhow::Result<()> {
    Ok(())
}

fn release() -> anyhow::Result<()> {
    Ok(())
}

fn regenerate_bindings() -> anyhow::Result<()> {
    Ok(())
}

fn build_dashboard() -> anyhow::Result<()> {
    Ok(())
}
