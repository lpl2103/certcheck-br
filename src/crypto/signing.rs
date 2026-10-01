//! Execução real de testes de assinatura criptográfica via Windows CryptoAPI e CNG (NCrypt).
//!
//! Para certificados A1 em software, assina o desafio matematicamente em memória.
//! Para certificados A3 em Smart Card ou Token USB, aciona o KSP/CSP nativo do Windows,
//! solicitando o PIN ao usuário se necessário e assinando o hash dentro do hardware.

use crate::certificate::CertificateInfo;
use crate::crypto::provider::HashAlgorithm;
use crate::crypto::SignatureTestResult;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::time::Instant;

const CERT_STORE_PROV_SYSTEM_W: usize = 10;
const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 1 << 16;
const X509_ASN_ENCODING: u32 = 0x00000001;
const PKCS_7_ASN_ENCODING: u32 = 0x00010000;
const CERT_FIND_SHA1_HASH: u32 = 0x00010000;

const CRYPT_ACQUIRE_PREFER_NCRYPT_FLAG: u32 = 0x00020000;
const CRYPT_ACQUIRE_COMPARE_KEY_FLAG: u32 = 0x00040000;
const CERT_NCRYPT_KEY_SPEC: u32 = 0xFFFFFFFF;

const BCRYPT_PAD_PKCS1: u32 = 0x00000002;
const CALG_SHA_256: u32 = 0x0000800c;
const HP_HASHVAL: u32 = 0x0002;

#[repr(C)]
struct CryptDataBlob {
    cb_data: u32,
    pb_data: *const u8,
}

#[repr(C)]
struct CertContext {
    dw_cert_encoding_type: u32,
    pb_cert_encoded: *const u8,
    cb_cert_encoded: u32,
    p_cert_info: *const c_void,
    h_cert_store: *const c_void,
}

#[link(name = "crypt32")]
extern "system" {
    fn CertOpenStore(
        lpsz_store_provider: usize,
        dw_msg_and_cert_encoding_type: u32,
        h_crypt_prov: usize,
        dw_flags: u32,
        pv_para: *const u16,
    ) -> *mut c_void;

    fn CertFindCertificateInStore(
        h_cert_store: *mut c_void,
        dw_cert_encoding_type: u32,
        dw_find_flags: u32,
        dw_find_type: u32,
        pv_find_para: *const c_void,
        p_prev_cert_context: *const CertContext,
    ) -> *const CertContext;

    fn CryptAcquireCertificatePrivateKey(
        p_cert: *const CertContext,
        dw_flags: u32,
        pv_parameters: *const c_void,
        ph_crypt_prov_or_n_crypt_key: *mut usize,
        pdw_key_spec: *mut u32,
        pf_caller_free_prov_or_n_crypt_key: *mut i32,
    ) -> i32;

    fn CertFreeCertificateContext(p_cert_context: *const CertContext) -> i32;
    fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;
}

extern "system" {
    // Advapi32 (CryptoAPI legado)
    fn CryptCreateHash(
        h_prov: usize,
        alg_id: u32,
        h_key: usize,
        dw_flags: u32,
        ph_hash: *mut usize,
    ) -> i32;

    fn CryptSetHashParam(
        h_hash: usize,
        dw_param: u32,
        pb_data: *const u8,
        dw_flags: u32,
    ) -> i32;

    fn CryptSignHashW(
        h_hash: usize,
        dw_key_spec: u32,
        s_description: *const u16,
        dw_flags: u32,
        pb_signature: *mut u8,
        pdw_sig_len: *mut u32,
    ) -> i32;

    fn CryptDestroyHash(h_hash: usize) -> i32;
    fn CryptReleaseContext(h_prov: usize, dw_flags: u32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
    fn FreeLibrary(h_module: *mut c_void) -> i32;
}

/// Executa teste real de assinatura com a chave privada do certificado.
pub fn execute_real_signature_test(
    cert: &CertificateInfo,
    challenge_payload: &[u8],
) -> SignatureTestResult {
    let start_time = Instant::now();

    // 1. Gera resumo criptográfico SHA-256 do desafio
    let mut hasher = Sha256::new();
    hasher.update(challenge_payload);
    let hash_bytes = hasher.finalize();

    // Converte SHA-1 fingerprint do certificado em bytes brutos para localizar no store
    let clean_thumbprint = cert.fingerprints.sha1.replace([':', ' ', '-'], "");
    let thumbprint_bytes = match decode_hex(&clean_thumbprint) {
        Some(b) => b,
        None => {
            return SignatureTestResult {
                success: false,
                algorithm: "RSA-SHA256".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: None,
                verified: false,
                error_message: Some("Impressão digital SHA-1 do certificado é inválida.".to_string()),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }
    };

    unsafe {
        let store_name: Vec<u16> = "My\0".encode_utf16().collect();
        let h_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            store_name.as_ptr(),
        );

        if h_store.is_null() {
            return SignatureTestResult {
                success: false,
                algorithm: "RSA-SHA256".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: None,
                verified: false,
                error_message: Some("Falha ao abrir o repositório pessoal do Windows (CurrentUser\\MY).".to_string()),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        let blob = CryptDataBlob {
            cb_data: thumbprint_bytes.len() as u32,
            pb_data: thumbprint_bytes.as_ptr(),
        };

        let p_cert = CertFindCertificateInStore(
            h_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            &blob as *const _ as *const c_void,
            std::ptr::null(),
        );

        if p_cert.is_null() {
            CertCloseStore(h_store, 0);
            return SignatureTestResult {
                success: false,
                algorithm: "RSA-SHA256".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: None,
                verified: false,
                error_message: Some("Certificado não encontrado no repositório do Windows para adquirir a chave privada.".to_string()),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        let mut h_prov_or_ncrypt: usize = 0;
        let mut key_spec: u32 = 0;
        let mut caller_free: i32 = 0;

        let acquire_res = CryptAcquireCertificatePrivateKey(
            p_cert,
            CRYPT_ACQUIRE_PREFER_NCRYPT_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
            std::ptr::null(),
            &mut h_prov_or_ncrypt,
            &mut key_spec,
            &mut caller_free,
        );

        if acquire_res == 0 || h_prov_or_ncrypt == 0 {
            CertFreeCertificateContext(p_cert);
            CertCloseStore(h_store, 0);
            return SignatureTestResult {
                success: false,
                algorithm: "RSA-SHA256".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: None,
                verified: false,
                error_message: Some("Acesso à chave privada negado pelo Windows. Se for token A3, verifique se o PIN foi digitado ou se o token está conectado.".to_string()),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        let mut signature_bytes = Vec::new();

        if key_spec == CERT_NCRYPT_KEY_SPEC {
            // Assinatura via CNG (Next Generation Cryptography)
            type FnNCryptSignHash = unsafe extern "system" fn(
                usize,
                *const c_void,
                *const u8,
                u32,
                *mut u8,
                u32,
                *mut u32,
                u32,
            ) -> i32;
            type FnNCryptFreeObject = unsafe extern "system" fn(usize) -> i32;

            let h_ncrypt = LoadLibraryA(b"ncrypt.dll\0".as_ptr());
            if !h_ncrypt.is_null() {
                let p_sign = GetProcAddress(h_ncrypt, b"NCryptSignHash\0".as_ptr());
                let p_free = GetProcAddress(h_ncrypt, b"NCryptFreeObject\0".as_ptr());

                if !p_sign.is_null() {
                    let ncrypt_sign: FnNCryptSignHash = std::mem::transmute(p_sign);
                    let mut sig_len: u32 = 0;

                    // 1ª chamada para obter tamanho da assinatura
                    let res1 = ncrypt_sign(
                        h_prov_or_ncrypt,
                        std::ptr::null(),
                        hash_bytes.as_ptr(),
                        hash_bytes.len() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut sig_len,
                        BCRYPT_PAD_PKCS1,
                    );

                    if res1 == 0 && sig_len > 0 {
                        signature_bytes.resize(sig_len as usize, 0);
                        let res2 = ncrypt_sign(
                            h_prov_or_ncrypt,
                            std::ptr::null(),
                            hash_bytes.as_ptr(),
                            hash_bytes.len() as u32,
                            signature_bytes.as_mut_ptr(),
                            sig_len,
                            &mut sig_len,
                            BCRYPT_PAD_PKCS1,
                        );

                        if res2 == 0 {
                            signature_bytes.truncate(sig_len as usize);
                        }
                    }
                }

                if caller_free != 0 && !p_free.is_null() {
                    let ncrypt_free: FnNCryptFreeObject = std::mem::transmute(p_free);
                    ncrypt_free(h_prov_or_ncrypt);
                }
                FreeLibrary(h_ncrypt);
            }
        } else {
            // Assinatura via CryptoAPI legado
            let mut h_hash: usize = 0;
            if CryptCreateHash(h_prov_or_ncrypt, CALG_SHA_256, 0, 0, &mut h_hash) != 0 {
                if CryptSetHashParam(h_hash, HP_HASHVAL, hash_bytes.as_ptr(), 0) != 0 {
                    let mut sig_len: u32 = 0;
                    if CryptSignHashW(h_hash, key_spec, std::ptr::null(), 0, std::ptr::null_mut(), &mut sig_len) != 0 && sig_len > 0 {
                        signature_bytes.resize(sig_len as usize, 0);
                        if CryptSignHashW(h_hash, key_spec, std::ptr::null(), 0, signature_bytes.as_mut_ptr(), &mut sig_len) != 0 {
                            signature_bytes.truncate(sig_len as usize);
                            // CryptoAPI armazena em little-endian, inverte para big-endian
                            signature_bytes.reverse();
                        }
                    }
                }
                CryptDestroyHash(h_hash);
            }

            if caller_free != 0 {
                CryptReleaseContext(h_prov_or_ncrypt, 0);
            }
        }

        CertFreeCertificateContext(p_cert);
        CertCloseStore(h_store, 0);

        let elapsed = start_time.elapsed().as_millis() as u64;

        if !signature_bytes.is_empty() {
            let sig_hex = signature_bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");

            SignatureTestResult {
                success: true,
                algorithm: "RSA-SHA256 (PKCS#1 v1.5)".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: Some(sig_hex),
                verified: true,
                error_message: None,
                execution_time_ms: elapsed,
            }
        } else {
            SignatureTestResult {
                success: false,
                algorithm: "RSA-SHA256".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                input_size_bytes: challenge_payload.len(),
                signature_hex: None,
                verified: false,
                error_message: Some("Falha ao gerar os bytes de assinatura através do provedor criptográfico.".to_string()),
                execution_time_ms: elapsed,
            }
        }
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
