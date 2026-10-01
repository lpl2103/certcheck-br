//! Limpeza do estado e cache SSL/TLS (Schannel) do Windows.
//!
//! Executa a mesma operação do botão "Limpar estado SSL" nas Opções da Internet (inetcpl.cpl).
//! Resolve falhas de autenticação mTLS em portais como e-CAC e PJe causadas por sessões
//! SSL presas no cache do subsistema Schannel.

use std::ffi::c_void;

type FnSslEmptyCacheW = unsafe extern "system" fn(*const u16, u32) -> i32;

extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hLibModule: *mut c_void) -> i32;
}

/// Limpa o cache de sessões SSL/TLS do subsistema Schannel do Windows.
pub fn clear_windows_ssl_cache() -> Result<String, String> {
    unsafe {
        let h_schannel = LoadLibraryA(b"schannel.dll\0".as_ptr());
        if h_schannel.is_null() {
            return Err("Não foi possível carregar schannel.dll do sistema.".to_string());
        }

        let proc = GetProcAddress(h_schannel, b"SslEmptyCacheW\0".as_ptr());
        if proc.is_null() {
            FreeLibrary(h_schannel);
            return Err("Função SslEmptyCacheW não encontrada em schannel.dll.".to_string());
        }

        let ssl_empty_cache: FnSslEmptyCacheW = std::mem::transmute(proc);
        // NULL e 0 limpam todo o cache de credenciais/sessões cliente SSL do sistema
        let res = ssl_empty_cache(std::ptr::null(), 0);
        FreeLibrary(h_schannel);

        if res != 0 {
            Ok("Estado e cache SSL/TLS do Windows limpos com sucesso!".to_string())
        } else {
            Err("O Windows retornou falha ao tentar limpar o cache SSL.".to_string())
        }
    }
}
