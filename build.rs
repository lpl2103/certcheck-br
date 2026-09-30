use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/app.rc");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let windres_candidates = [
            r"C:\Users\Leandro\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin\x86_64-w64-mingw32-windres.exe",
            "x86_64-w64-mingw32-windres.exe",
            "windres.exe",
        ];

        let out_dir = std::env::var("OUT_DIR").unwrap();
        let res_path = format!("{}/app.res", out_dir);

        for windres in windres_candidates {
            let status = Command::new(windres)
                .current_dir("assets")
                .args(["-i", "app.rc", "-o", &res_path, "-O", "coff"])
                .status();

            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:rustc-link-arg={}", res_path);
                    break;
                }
            }
        }
    }
}
