fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    match target_os.as_str() {
        "macos" => {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/memflow.dylib");
            println!("cargo:rustc-cdylib-link-arg=-o");
            println!("cargo:rustc-cdylib-link-arg=tests/externals/memflow.dylib");
        }
        "windows" => {
            println!("cargo:rustc-cdylib-link-arg=/OUT:tests/externals/memflow.dll");
        }
        _ => {
            // For Linux and other Unix-like systems
            println!("cargo:rustc-cdylib-link-arg=-o");
            println!("cargo:rustc-cdylib-link-arg=tests/externals/memflow.so");
        }
    }
} 