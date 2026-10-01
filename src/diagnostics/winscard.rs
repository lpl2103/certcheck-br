//! Diagnóstico em tempo real de leitoras e cartões A3 via PC/SC (WinSCard.dll).

use crate::diagnostics::model::{A3DiagnosticSummary, ProviderDiagnostic, ReaderInfo, TokenInfo};
use std::ffi::c_void;

const SCARD_SCOPE_USER: u32 = 0;
const SCARD_SHARE_SHARED: u32 = 2;
const SCARD_PROTOCOL_T0: u32 = 1;
const SCARD_PROTOCOL_T1: u32 = 2;
const SCARD_PROTOCOL_TX: u32 = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
const SCARD_LEAVE_CARD: u32 = 0;

type SCARDCONTEXT = usize;
type SCARDHANDLE = usize;

type FnSCardEstablishContext =
    unsafe extern "system" fn(u32, *const c_void, *const c_void, *mut SCARDCONTEXT) -> i32;
type FnSCardReleaseContext = unsafe extern "system" fn(SCARDCONTEXT) -> i32;
type FnSCardListReadersW =
    unsafe extern "system" fn(SCARDCONTEXT, *const u16, *mut u16, *mut u32) -> i32;
type FnSCardConnectW = unsafe extern "system" fn(
    SCARDCONTEXT,
    *const u16,
    u32,
    u32,
    *mut SCARDHANDLE,
    *mut u32,
) -> i32;
type FnSCardDisconnect = unsafe extern "system" fn(SCARDHANDLE, u32) -> i32;
type FnSCardStatusW = unsafe extern "system" fn(
    SCARDHANDLE,
    *mut u16,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u8,
    *mut u32,
) -> i32;

extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hLibModule: *mut c_void) -> i32;
}

/// Executa a varredura real do subsistema PC/SC do Windows para detectar leitores e tokens A3.
pub fn scan_a3_hardware() -> A3DiagnosticSummary {
    let mut summary = A3DiagnosticSummary::default();
    let mut possible_causes = Vec::new();

    unsafe {
        let h_winscard = LoadLibraryA(b"winscard.dll\0".as_ptr());
        if h_winscard.is_null() {
            possible_causes.push("A biblioteca winscard.dll não está disponível no sistema.".to_string());
            summary.possible_causes_for_failure = possible_causes;
            return summary;
        }

        let p_establish = GetProcAddress(h_winscard, b"SCardEstablishContext\0".as_ptr());
        let p_release = GetProcAddress(h_winscard, b"SCardReleaseContext\0".as_ptr());
        let p_list = GetProcAddress(h_winscard, b"SCardListReadersW\0".as_ptr());
        let p_connect = GetProcAddress(h_winscard, b"SCardConnectW\0".as_ptr());
        let p_disconnect = GetProcAddress(h_winscard, b"SCardDisconnect\0".as_ptr());
        let p_status = GetProcAddress(h_winscard, b"SCardStatusW\0".as_ptr());

        if p_establish.is_null() || p_list.is_null() {
            FreeLibrary(h_winscard);
            possible_causes.push("Funções essenciais do PC/SC não foram encontradas em winscard.dll.".to_string());
            summary.possible_causes_for_failure = possible_causes;
            return summary;
        }

        let scard_establish: FnSCardEstablishContext = std::mem::transmute(p_establish);
        let scard_release: FnSCardReleaseContext = std::mem::transmute(p_release);
        let scard_list: FnSCardListReadersW = std::mem::transmute(p_list);
        let scard_connect: Option<FnSCardConnectW> = if !p_connect.is_null() {
            Some(std::mem::transmute(p_connect))
        } else {
            None
        };
        let scard_disconnect: Option<FnSCardDisconnect> = if !p_disconnect.is_null() {
            Some(std::mem::transmute(p_disconnect))
        } else {
            None
        };
        let scard_status: Option<FnSCardStatusW> = if !p_status.is_null() {
            Some(std::mem::transmute(p_status))
        } else {
            None
        };

        let mut h_context: SCARDCONTEXT = 0;
        let res = scard_establish(SCARD_SCOPE_USER, std::ptr::null(), std::ptr::null(), &mut h_context);
        if res != 0 {
            FreeLibrary(h_winscard);
            possible_causes.push("O serviço 'Cartão Inteligente' (SCardSvr) do Windows não está em execução ou rejeitou a conexão.".to_string());
            summary.possible_causes_for_failure = possible_causes;
            return summary;
        }

        let mut readers_len: u32 = 0;
        let res_list = scard_list(h_context, std::ptr::null(), std::ptr::null_mut(), &mut readers_len);

        if res_list == 0 && readers_len > 1 {
            let mut readers_buf = vec![0u16; readers_len as usize];
            if scard_list(h_context, std::ptr::null(), readers_buf.as_mut_ptr(), &mut readers_len) == 0 {
                let reader_names = parse_multi_string_utf16(&readers_buf);
                summary.reader_detected = !reader_names.is_empty();

                for r_name in reader_names {
                    let mut is_card_present = false;
                    let mut atr_hex = None;
                    let mut reader_status = "Leitor Conectado (Sem Cartão)".to_string();

                    if let (Some(fn_connect), Some(fn_status), Some(fn_disc)) =
                        (scard_connect, scard_status, scard_disconnect)
                    {
                        let r_name_w: Vec<u16> = r_name.encode_utf16().chain(std::iter::once(0)).collect();
                        let mut h_card: SCARDHANDLE = 0;
                        let mut active_proto: u32 = 0;

                        let conn_res = fn_connect(
                            h_context,
                            r_name_w.as_ptr(),
                            SCARD_SHARE_SHARED,
                            SCARD_PROTOCOL_TX,
                            &mut h_card,
                            &mut active_proto,
                        );

                        if conn_res == 0 {
                            is_card_present = true;
                            summary.smart_card_detected = true;
                            summary.token_detected = true;

                            let mut r_name_back_len: u32 = 128;
                            let mut r_name_back = vec![0u16; 128];
                            let mut state: u32 = 0;
                            let mut proto: u32 = 0;
                            let mut atr_buf = [0u8; 36];
                            let mut atr_len: u32 = 36;

                            let stat_res = fn_status(
                                h_card,
                                r_name_back.as_mut_ptr(),
                                &mut r_name_back_len,
                                &mut state,
                                &mut proto,
                                atr_buf.as_mut_ptr(),
                                &mut atr_len,
                            );

                            if stat_res == 0 && atr_len > 0 {
                                let hex_str: String = atr_buf[..atr_len as usize]
                                    .iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");

                                atr_hex = Some(hex_str.clone());
                                let chip_vendor = infer_vendor_from_atr(&atr_buf[..atr_len as usize]);
                                reader_status = format!("Pronto / Cartão Inserido ({chip_vendor})");

                                summary.tokens.push(TokenInfo {
                                    label: format!("Mídia A3 em {}", r_name),
                                    manufacturer: Some(chip_vendor.to_string()),
                                    model: Some("Token/Smart Card ICP-Brasil".to_string()),
                                    serial_number: None,
                                    is_read_only: false,
                                    is_pin_initialized: true,
                                });
                            } else {
                                reader_status = "Cartão presente (não responsivo).".to_string();
                            }

                            fn_disc(h_card, SCARD_LEAVE_CARD);
                        }
                    }

                    summary.readers.push(ReaderInfo {
                        name: r_name,
                        is_card_present,
                        card_atr_hex: atr_hex,
                        status: reader_status,
                    });
                }
            }
        } else {
            possible_causes.push("Nenhum leitor de Smart Card ou Token USB foi detectado nas portas do computador.".to_string());
        }

        scard_release(h_context);
        FreeLibrary(h_winscard);
    }

    // 2. Diagnóstico dos Cryptographic Providers (KSP e CSP)
    summary.providers = check_standard_cryptographic_providers();
    summary.provider_detected = !summary.providers.is_empty();
    summary.ksp_csp_detected = summary.providers.iter().any(|p| p.is_available);

    summary.possible_causes_for_failure = possible_causes;
    summary
}

fn parse_multi_string_utf16(buf: &[u16]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for &ch in buf {
        if ch == 0 {
            if !current.is_empty() {
                if let Ok(s) = String::from_utf16(&current) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        result.push(trimmed.to_string());
                    }
                }
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }

    result
}

fn infer_vendor_from_atr(atr: &[u8]) -> &'static str {
    if atr.len() >= 3 {
        if atr[0] == 0x3B && atr[1] == 0x7F && atr[2] == 0x96 {
            return "G&D / Starsign / SafeSign";
        }
        if atr[0] == 0x3B && (atr[1] == 0xF8 || atr[1] == 0x75) {
            return "Gemalto / Thales SafeNet";
        }
        if atr[0] == 0x3B && atr[1] == 0x69 {
            return "Feitian ePass2003";
        }
        if atr[0] == 0x3B && atr[1] == 0x9F {
            return "Oberthur ID-One Cosmo";
        }
        if atr[0] == 0x3B && atr[1] == 0xBA {
            return "Watchdata ProxKey";
        }
    }
    "Smart Card Padrão ISO 7816"
}

fn check_standard_cryptographic_providers() -> Vec<ProviderDiagnostic> {
    vec![
        ProviderDiagnostic {
            name: "Microsoft Smart Card Key Storage Provider".to_string(),
            provider_type: "KSP (CNG)".to_string(),
            container_name: None,
            is_available: true,
            description: Some("KSP padrão do Windows para Smart Cards e Tokens CNG (Windows 7 ao 11).".to_string()),
        },
        ProviderDiagnostic {
            name: "Microsoft Base Smart Card Crypto Provider".to_string(),
            provider_type: "CSP (CryptoAPI)".to_string(),
            container_name: None,
            is_available: true,
            description: Some("CSP legado do Windows para aplicativos baseados em CAPI.".to_string()),
        },
        ProviderDiagnostic {
            name: "SafeSign Standard Cryptographic Service Provider".to_string(),
            provider_type: "CSP (AET)".to_string(),
            container_name: None,
            is_available: std::path::Path::new("C:\\Windows\\System32\\aetpkss1.dll").exists()
                || std::path::Path::new("C:\\Windows\\SysWOW64\\aetpkss1.dll").exists(),
            description: Some("Middleware SafeSign para cartões OAB e tokens GD Starsign.".to_string()),
        },
        ProviderDiagnostic {
            name: "eToken Base Cryptographic Provider".to_string(),
            provider_type: "CSP (SAC)".to_string(),
            container_name: None,
            is_available: std::path::Path::new("C:\\Windows\\System32\\eToken.dll").exists()
                || std::path::Path::new("C:\\Windows\\System32\\dkck201.dll").exists(),
            description: Some("Middleware SafeNet Authentication Client para tokens Thales/Gemalto.".to_string()),
        },
    ]
}
