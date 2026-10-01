//! Detecção de softwares middlewares de tokens criptográficos e assinadores locais (PJeOffice, Shodō).

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareItem {
    pub name: String,
    pub vendor: String,
    pub installed: bool,
    pub path_found: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerItem {
    pub name: String,
    pub expected_port: u16,
    pub is_running: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusItem {
    pub service_name: String,
    pub display_name: String,
    pub status: String,
    pub is_healthy: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentDiagnostic {
    pub middlewares: Vec<MiddlewareItem>,
    pub signers: Vec<SignerItem>,
    pub smart_card_service: ServiceStatusItem,
}

#[repr(C)]
struct ServiceStatus {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;

const SERVICE_STOPPED: u32 = 0x00000001;
const SERVICE_START_PENDING: u32 = 0x00000002;
const SERVICE_STOP_PENDING: u32 = 0x00000003;
const SERVICE_RUNNING: u32 = 0x00000004;

extern "system" {
    fn OpenSCManagerW(
        lp_machine_name: *const u16,
        lp_database_name: *const u16,
        dw_desired_access: u32,
    ) -> *mut c_void;

    fn OpenServiceW(
        h_sc_manager: *mut c_void,
        lp_service_name: *const u16,
        dw_desired_access: u32,
    ) -> *mut c_void;

    fn QueryServiceStatus(
        h_service: *mut c_void,
        lp_service_status: *mut ServiceStatus,
    ) -> i32;

    fn CloseServiceHandle(h_sc_object: *mut c_void) -> i32;
}

/// Executa diagnóstico do ecossistema de drivers e assinadores instalados no Windows.
pub fn run_environment_diagnostic() -> EnvironmentDiagnostic {
    let middlewares = check_known_middlewares();
    let signers = check_signers();
    let smart_card_service = check_smart_card_service();

    EnvironmentDiagnostic {
        middlewares,
        signers,
        smart_card_service,
    }
}

/// Verifica o status do serviço nativo "Cartão Inteligente" (SCardSvr) do Windows.
pub fn check_smart_card_service() -> ServiceStatusItem {
    let mut status_item = ServiceStatusItem {
        service_name: "SCardSvr".to_string(),
        display_name: "Serviço de Cartão Inteligente do Windows (SCardSvr)".to_string(),
        status: "Desconhecido".to_string(),
        is_healthy: false,
        details: "Não foi possível consultar o Gerenciador de Serviços do Windows.".to_string(),
    };

    unsafe {
        let h_scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if h_scm.is_null() {
            return status_item;
        }

        let scard_name: Vec<u16> = "SCardSvr\0".encode_utf16().collect();
        let h_svc = OpenServiceW(h_scm, scard_name.as_ptr(), SERVICE_QUERY_STATUS);
        if h_svc.is_null() {
            CloseServiceHandle(h_scm);
            status_item.status = "Não Encontrado".to_string();
            status_item.details = "O serviço SCardSvr não está cadastrado no sistema.".to_string();
            return status_item;
        }

        let mut svc_status = ServiceStatus {
            dw_service_type: 0,
            dw_current_state: 0,
            dw_controls_accepted: 0,
            dw_win32_exit_code: 0,
            dw_service_specific_exit_code: 0,
            dw_check_point: 0,
            dw_wait_hint: 0,
        };

        let res = QueryServiceStatus(h_svc, &mut svc_status);
        CloseServiceHandle(h_svc);
        CloseServiceHandle(h_scm);

        if res != 0 {
            match svc_status.dw_current_state {
                SERVICE_RUNNING => {
                    status_item.status = "Em Execução (Ativo)".to_string();
                    status_item.is_healthy = true;
                    status_item.details = "O subsistema PC/SC está pronto para gerenciar leitoras e cartões A3.".to_string();
                }
                SERVICE_STOPPED => {
                    status_item.status = "Parado".to_string();
                    status_item.is_healthy = false;
                    status_item.details = "Aviso: O serviço está parado. Inicie o serviço 'Cartão Inteligente' no services.msc para detectar tokens A3.".to_string();
                }
                SERVICE_START_PENDING => {
                    status_item.status = "Iniciando".to_string();
                    status_item.is_healthy = false;
                    status_item.details = "O serviço está em transição de inicialização.".to_string();
                }
                SERVICE_STOP_PENDING => {
                    status_item.status = "Parando".to_string();
                    status_item.is_healthy = false;
                    status_item.details = "O serviço está sendo finalizado.".to_string();
                }
                _ => {
                    status_item.status = format!("Estado ({})", svc_status.dw_current_state);
                    status_item.is_healthy = false;
                    status_item.details = "Estado intermediário do serviço Windows.".to_string();
                }
            }
        }
    }

    status_item
}

/// Checa se os assinadores de tribunais (PJeOffice e Shodō) estão em execução nas portas padrão.
pub fn check_signers() -> Vec<SignerItem> {
    let mut signers = Vec::new();

    // 1. PJeOffice (porta 16210)
    let pje_running = is_tcp_port_open(16210);
    signers.push(SignerItem {
        name: "PJeOffice (CNJ / Tribunais)".to_string(),
        expected_port: 16210,
        is_running: pje_running,
        details: if pje_running {
            "Assinador ativo e respondendo na porta local 16210. Pronto para peticionamento.".to_string()
        } else {
            "Não detectado em execução na porta 16210. Abra o PJeOffice se for peticionar no PJe.".to_string()
        },
    });

    // 2. Shodō (porta 9000 - JT / CSJT)
    let shodo_running = is_tcp_port_open(9000);
    signers.push(SignerItem {
        name: "Shodō (Justiça do Trabalho / TRT)".to_string(),
        expected_port: 9000,
        is_running: shodo_running,
        details: if shodo_running {
            "Assinador ativo na porta local 9000. Pronto para peticionamento na Justiça do Trabalho.".to_string()
        } else {
            "Não detectado na porta 9000. Abra o Shodō se for utilizar o PJe da Justiça do Trabalho.".to_string()
        },
    });

    signers
}

/// Verifica a presença das bibliotecas nativas dos principais middlewares de tokens do Brasil.
pub fn check_known_middlewares() -> Vec<MiddlewareItem> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let sys32 = Path::new(&system_root).join("System32");
    let syswow64 = Path::new(&system_root).join("SysWOW64");
    let prog_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let prog_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".to_string());

    let candidates = [
        (
            "SafeSign Identity Client",
            "AET Europe / Certisign / Serasa",
            vec![
                sys32.join("aetpkss1.dll"),
                syswow64.join("aetpkss1.dll"),
                Path::new(&prog_files).join("A.E.T. Europe B.V\\SafeSign Ubiquitous\\tokenadmin.exe"),
                Path::new(&prog_files_x86).join("A.E.T. Europe B.V\\SafeSign Ubiquitous\\tokenadmin.exe"),
            ],
            "Driver padrão para tokens GD Burti, Starsign e cartões OAB/Certisign.",
        ),
        (
            "SafeNet Authentication Client (SAC)",
            "Thales / Gemalto",
            vec![
                sys32.join("eToken.dll"),
                syswow64.join("eToken.dll"),
                sys32.join("dkck201.dll"),
                syswow64.join("dkck201.dll"),
                Path::new(&prog_files).join("SafeNet\\Authentication\\SAC\\SACMonitor.exe"),
            ],
            "Driver oficial para tokens SafeNet / Gemalto / Thales (eToken 5100, 5110).",
        ),
        (
            "ePass2003 CSP / PKCS#11",
            "Feitian Technologies",
            vec![
                sys32.join("eps2003csp11.dll"),
                syswow64.join("eps2003csp11.dll"),
                sys32.join("ep2003_auth.dll"),
            ],
            "Driver para tokens USB Feitian ePass2003 (utilizado por Soluti e Valid).",
        ),
        (
            "Giesecke & Devrient (GD Starsign)",
            "G&D / Burti",
            vec![
                sys32.join("gclib.dll"),
                syswow64.join("gclib.dll"),
            ],
            "Driver para mídias Starsign Crypto USB e cartões inteligentes.",
        ),
        (
            "Watchdata ProxKey",
            "Watchdata Technologies",
            vec![
                sys32.join("Watchdata\\ProxKey\\wdpkcs.dll"),
                sys32.join("wdpkcs.dll"),
                syswow64.join("wdpkcs.dll"),
            ],
            "Driver para tokens Watchdata ProxKey e WD-PROX.",
        ),
    ];

    let mut result = Vec::new();

    for (name, vendor, paths, desc) in candidates {
        let mut found_path = None;
        for p in paths {
            if p.exists() {
                found_path = Some(p.to_string_lossy().to_string());
                break;
            }
        }

        let installed = found_path.is_some();
        let details = if installed {
            format!("{desc} (Localizado em: {})", found_path.as_deref().unwrap_or(""))
        } else {
            format!("{desc} (Não instalado).")
        };

        result.push(MiddlewareItem {
            name: name.to_string(),
            vendor: vendor.to_string(),
            installed,
            path_found: found_path,
            details,
        });
    }

    result
}

fn is_tcp_port_open(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}
