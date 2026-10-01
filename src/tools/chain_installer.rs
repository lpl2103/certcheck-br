//! Instalador e atualizador de cadeias de certificação oficiais da ICP-Brasil no Windows Store.
//!
//! Baixa as cadeias da AC Raiz (v2, v5, v10, v11) diretamente dos servidores do ITI e
//! instala no repositório de Autoridades Confiáveis do Windows (CurrentUser\Root / CA).

use std::ffi::c_void;

const CERT_STORE_PROV_SYSTEM_W: usize = 10;
const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 1 << 16;
const X509_ASN_ENCODING: u32 = 0x00000001;
const CERT_STORE_ADD_REPLACE_EXISTING: u32 = 3;

#[link(name = "crypt32")]
extern "system" {
    fn CertOpenStore(
        lpsz_store_provider: usize,
        dw_msg_and_cert_encoding_type: u32,
        h_crypt_prov: usize,
        dw_flags: u32,
        pv_para: *const u16,
    ) -> *mut c_void;

    fn CertAddEncodedCertificateToStore(
        h_cert_store: *mut c_void,
        dw_cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        dw_add_disposition: u32,
        pp_cert_context: *mut *const c_void,
    ) -> i32;

    fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;
}

/// Lista oficial de raízes da ICP-Brasil mantidas pelo Instituto Nacional de Tecnologia da Informação (ITI).
const OFFICIAL_ICP_BRASIL_ROOTS: &[(&str, &str)] = &[
    (
        "AC Raiz da ICP-Brasil v2",
        "https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv2.crt",
    ),
    (
        "AC Raiz da ICP-Brasil v5",
        "https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv5.crt",
    ),
    (
        "AC Raiz da ICP-Brasil v10",
        "https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt",
    ),
    (
        "AC Raiz da ICP-Brasil v11",
        "https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv11.crt",
    ),
];

/// Baixa e instala as Autoridades Certificadoras Raiz da ICP-Brasil no repositório de confiança do Windows.
pub fn install_official_icp_brasil_roots() -> Result<String, String> {
    let mut installed_count = 0;
    let mut errors = Vec::new();

    unsafe {
        let store_name: Vec<u16> = "Root\0".encode_utf16().collect();
        let h_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            store_name.as_ptr(),
        );

        if h_store.is_null() {
            return Err("Não foi possível abrir o repositório de certificados Confiáveis do Windows (CurrentUser\\Root).".to_string());
        }

        for (name, url) in OFFICIAL_ICP_BRASIL_ROOTS {
            match ureq::get(url).timeout(std::time::Duration::from_secs(8)).call() {
                Ok(resp) => {
                    let mut bytes = Vec::new();
                    if let Ok(_) = resp.into_reader().read_to_end(&mut bytes) {
                        let res = CertAddEncodedCertificateToStore(
                            h_store,
                            X509_ASN_ENCODING,
                            bytes.as_ptr(),
                            bytes.len() as u32,
                            CERT_STORE_ADD_REPLACE_EXISTING,
                            std::ptr::null_mut(),
                        );

                        if res != 0 {
                            installed_count += 1;
                        } else {
                            errors.push(format!("Falha ao registrar {} no repositório.", name));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Não foi possível baixar {}: {}", name, e));
                }
            }
        }

        CertCloseStore(h_store, 0);
    }

    if installed_count > 0 {
        let msg = format!(
            "{} certificado(s) de AC Raiz da ICP-Brasil instalado(s)/atualizado(s) no Windows com sucesso!",
            installed_count
        );
        Ok(msg)
    } else {
        Err(format!(
            "Nenhuma cadeia pôde ser instalada. Erros encontrados: {}",
            errors.join("; ")
        ))
    }
}

use std::io::Read;
