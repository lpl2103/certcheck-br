//! Utilitários para exibição segura e confiável de diálogos nativos de arquivos no Windows.
//!
//! Garante a correta inicialização da thread COM em modo STA (`COINIT_APARTMENTTHREADED`)
//! antes de invocar a Windows Shell (`IFileDialog` / `rfd`), evitando travamentos,
//! falhas silenciosas ou fechamento repentino do seletor de arquivos.

use std::path::PathBuf;

/// Abre o seletor nativo do Windows para escolha de arquivo de certificado digital (.pfx, .p12, .cer, .crt, .pem).
pub fn pick_certificate_file() -> Option<PathBuf> {
    run_with_com(|| {
        rfd::FileDialog::new()
            .add_filter(
                "Certificados Digitais (*.pfx, *.p12, *.cer, *.crt, *.pem)",
                &[
                    "pfx", "p12", "cer", "crt", "pem",
                    "PFX", "P12", "CER", "CRT", "PEM",
                ],
            )
            .add_filter("Arquivos PKCS#12 (*.pfx, *.p12)", &["pfx", "p12", "PFX", "P12"])
            .add_filter(
                "Certificados X.509 (*.cer, *.crt, *.pem)",
                &["cer", "crt", "pem", "CER", "CRT", "PEM"],
            )
            .add_filter("Todos os Arquivos (*.*)", &["*"])
            .set_title("Selecionar Certificado Digital")
            .pick_file()
    })
}

/// Abre o seletor nativo do Windows para salvar o Laudo Técnico de Conformidade em HTML.
pub fn save_html_report(default_filename: &str) -> Option<PathBuf> {
    run_with_com(|| {
        rfd::FileDialog::new()
            .set_file_name(default_filename)
            .add_filter("Documento HTML (*.html)", &["html", "HTML"])
            .set_title("Salvar Laudo Técnico de Conformidade")
            .save_file()
    })
}

/// Abre o seletor nativo do Windows para escolher um arquivo qualquer para teste de assinatura digital.
pub fn pick_file_to_sign() -> Option<PathBuf> {
    run_with_com(|| {
        rfd::FileDialog::new()
            .set_title("Selecione um arquivo para teste de assinatura criptográfica")
            .pick_file()
    })
}

/// Executa um encerramento garantindo a inicialização prévia de COM STA na thread atual.
fn run_with_com<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(pv_reserved: *mut std::ffi::c_void, dw_co_init: u32) -> i32;
        fn CoUninitialize();
    }

    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const COINIT_DISABLE_OLE1DDE: u32 = 0x4;

    let hr = unsafe {
        CoInitializeEx(
            std::ptr::null_mut(),
            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
        )
    };

    let result = f();

    // S_OK (0) ou S_FALSE (1) indicam que COM foi inicializado nesta thread e deve ser finalizado.
    if hr >= 0 {
        unsafe {
            CoUninitialize();
        }
    }

    result
}
