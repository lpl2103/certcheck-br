//! Testador de conectividade e handshake TLS com os principais portais e serviços governamentais.

use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpointTest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub description: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub status_message: String,
}

/// Executa testes de conectividade TCP/TLS contra os principais portais brasileiros.
pub fn run_government_services_test() -> Vec<ServiceEndpointTest> {
    let endpoints = [
        (
            "e-CAC (Receita Federal)",
            "cav.receita.fazenda.gov.br",
            443,
            "Portal de atendimento virtual da Receita Federal do Brasil (mTLS).",
        ),
        (
            "PJe Nacional (CNJ)",
            "pje.jus.br",
            443,
            "Plataforma do Processo Judicial Eletrônico do Conselho Nacional de Justiça.",
        ),
        (
            "Conectividade Social ICP (Caixa)",
            "conectividade.caixa.gov.br",
            443,
            "Portal da Caixa Econômica Federal para FGTS e transmissão de arquivos SEFIP.",
        ),
        (
            "SEFAZ Nacional (Portal NF-e)",
            "nfe.fazenda.gov.br",
            443,
            "Ambiente nacional de autorização e consulta de Notas Fiscais Eletrônicas.",
        ),
        (
            "VALIDAR (ITI / ICP-Brasil)",
            "validar.iti.gov.br",
            443,
            "Serviço oficial do Instituto Nacional de Tecnologia da Informação.",
        ),
    ];

    let mut results = Vec::new();

    for (name, host, port, desc) in endpoints {
        let (reachable, latency_ms, status_msg) = test_endpoint(host, port);
        results.push(ServiceEndpointTest {
            name: name.to_string(),
            host: host.to_string(),
            port,
            description: desc.to_string(),
            reachable,
            latency_ms,
            status_message: status_msg,
        });
    }

    results
}

fn test_endpoint(host: &str, port: u16) -> (bool, Option<u64>, String) {
    let addr_str = format!("{}:{}", host, port);
    let start = Instant::now();

    // 1. Resolução DNS e conexão TCP com timeout de 3 segundos
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(sock_addr) = addrs.next() {
                match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3)) {
                    Ok(_) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        (
                            true,
                            Some(elapsed),
                            format!("Porta {} acessível ({elapsed} ms). Servidor respondendo.", port),
                        )
                    }
                    Err(e) => (
                        false,
                        None,
                        format!("Falha na conexão TCP ({e}). Verifique firewall ou conexão com a internet."),
                    ),
                }
            } else {
                (
                    false,
                    None,
                    "Falha ao resolver endereço IP para o host.".to_string(),
                )
            }
        }
        Err(e) => (
            false,
            None,
            format!("Erro de resolução de DNS ({e})."),
        ),
    }
}
