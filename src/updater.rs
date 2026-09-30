//! # Módulo de Atualização Automática (`updater.rs`)
//!
//! Gerencia a verificação, download e substituição do executável da aplicação
//! diretamente do repositório público de distribuição no GitHub.
//!
//! ## Fluxo de Atualização:
//! 1. Ao iniciar, a aplicação consulta a API do GitHub Releases em background.
//! 2. Se existir uma versão mais nova, exibe um modal para o usuário.
//! 3. Ao aceitar, o download é feito em streaming com barra de progresso.
//! 4. O executável é substituído usando a técnica de "hot-swap" no Windows.
//!
//! ## Técnica de Substituição Quente no Windows:
//! No Windows, um executável em execução não pode ser sobrescrito diretamente.
//! 1. O download é gravado em arquivo temporário `certcheck-br.exe.new`.
//! 2. Renomeamos o executável atual para `certcheck-br.exe.old`.
//! 3. Movemos `certcheck-br.exe.new` para `certcheck-br.exe`.
//! 4. Disparamos a nova versão atualizada com a flag `--cleanup-old`.
//! 5. O novo processo aguarda a liberação e remove `certcheck-br.exe.old` do disco.

use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::process::Command;
use tracing::{info, warn};

/// Repositório público de distribuição no GitHub (contém apenas as releases com o .exe)
pub const GITHUB_OWNER: &str = "lpl2103";
pub const GITHUB_REPO: &str = "certcheck-br";
pub const GITHUB_API_LATEST: &str =
    "https://api.github.com/repos/lpl2103/certcheck-br/releases/latest";
pub const GITHUB_DIRECT_DOWNLOAD: &str =
    "https://github.com/lpl2103/certcheck-br/releases/latest/download/certcheck-br.exe";

/// Informações sobre uma versão remota disponível
#[derive(Debug, Clone)]
pub struct RemoteVersionInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
}

/// Status do processo de atualização
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    /// Ocioso / Pronto para checar
    Idle,
    /// Baixando o novo executável (Progresso de 0.0 a 1.0)
    Downloading(f32),
    /// Atualização concluída com sucesso (Aguardando reinicialização)
    Success(String),
    /// Falha no processo de atualização (Mensagem de erro)
    Error(String),
}

/// Compara duas versões em formato SemVer ("1.0.1" vs "1.0.0").
pub fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let clean = v.trim().trim_start_matches(['v', 'V']);
    let mut parts = clean.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(remote: &str, current: &str) -> bool {
    if let (Some(r), Some(c)) = (parse_version(remote), parse_version(current)) {
        r > c
    } else {
        remote.trim() != current.trim()
    }
}

/// Verifica se existe uma nova versão disponível no GitHub Releases.
pub fn check_for_updates() -> Option<RemoteVersionInfo> {
    let current_version = env!("CARGO_PKG_VERSION");
    info!(
        "Verificando atualizações (versão instalada: v{})...",
        current_version
    );

    // Consulta o repositório público de distribuição no GitHub
    info!(
        "Consultando releases no GitHub ({}/{})...",
        GITHUB_OWNER, GITHUB_REPO
    );
    let gh_resp = ureq::get(GITHUB_API_LATEST)
        .set(
            "User-Agent",
            &format!("CertCheckBR/{}", current_version),
        )
        .set("Accept", "application/vnd.github.v3+json")
        .timeout(std::time::Duration::from_secs(8))
        .call();

    match gh_resp {
        Ok(resp) if resp.status() == 200 => {
            if let Ok(json_str) = resp.into_string() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let tag_name = json
                        .get("tag_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let clean_tag = tag_name.trim().trim_start_matches(['v', 'V']);
                    let body = json
                        .get("body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Melhorias e correções de estabilidade.");

                    // Encontra a URL do binário certcheck-br.exe nos assets da release
                    let mut dl_url = GITHUB_DIRECT_DOWNLOAD.to_string();
                    if let Some(assets) = json.get("assets").and_then(|a| a.as_array()) {
                        for asset in assets {
                            if asset.get("name").and_then(|n| n.as_str())
                                == Some("certcheck-br.exe")
                            {
                                if let Some(url) = asset
                                    .get("browser_download_url")
                                    .and_then(|u| u.as_str())
                                {
                                    dl_url = url.to_string();
                                    break;
                                }
                            }
                        }
                    }

                    if is_newer_version(clean_tag, current_version) {
                        info!(
                            "Nova versão encontrada no GitHub: v{} (atual: v{})",
                            clean_tag, current_version
                        );
                        return Some(RemoteVersionInfo {
                            version: clean_tag.to_string(),
                            download_url: dl_url,
                            release_notes: body.to_string(),
                        });
                    } else {
                        info!(
                            "Aplicativo já está na versão mais recente (v{}).",
                            current_version
                        );
                    }
                }
            }
        }
        Ok(resp) => {
            warn!(
                "Resposta inesperada do GitHub Releases: status {}",
                resp.status()
            );
        }
        Err(e) => {
            warn!("Não foi possível consultar o GitHub Releases: {}", e);
        }
    }

    None
}

/// Executa o download da nova versão e realiza a substituição do executável no Windows.
pub fn perform_auto_update<F>(custom_url: Option<String>, progress_callback: F) -> Result<()>
where
    F: Fn(UpdateStatus) + Send + 'static,
{
    progress_callback(UpdateStatus::Downloading(0.0));

    // Determina a URL de download (prioriza custom_url se fornecido)
    let download_url = custom_url.unwrap_or_else(|| GITHUB_DIRECT_DOWNLOAD.to_string());

    info!(
        "Iniciando download da atualização a partir de '{}'...",
        download_url
    );
    let agent = ureq::builder()
        .redirects(5)
        .timeout(std::time::Duration::from_secs(120))
        .build();

    let response = agent
        .get(&download_url)
        .set("User-Agent", "CertCheckBR/Updater")
        .call()
        .with_context(|| {
            format!(
                "Falha ao conectar no endereço de atualização: {}",
                download_url
            )
        })?;

    let content_length = response
        .header("Content-Length")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(0);

    info!(
        "Tamanho reportado da atualização: {} bytes",
        content_length
    );

    // 2. Determina caminhos dos executáveis
    let current_exe =
        std::env::current_exe().context("Falha ao determinar caminho do executável atual")?;
    let old_exe = current_exe.with_extension("exe.old");
    let new_exe = current_exe.with_extension("exe.new");

    // 3. Gravação em streaming direto para arquivo temporário no disco (zero alocação excessiva em RAM)
    {
        let file = File::create(&new_exe)
            .with_context(|| format!("Falha ao criar arquivo temporário {:?}", new_exe))?;
        let mut writer = BufWriter::new(file);
        let mut reader = response.into_reader();
        let mut buffer = [0u8; 16384];
        let mut total_read = 0;
        let mut header_check = [0u8; 2];
        let mut checked_header = false;

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if !checked_header && n >= 2 {
                        header_check[0] = buffer[0];
                        header_check[1] = buffer[1];
                        checked_header = true;
                    }

                    writer
                        .write_all(&buffer[..n])
                        .context("Erro ao gravar dados do download no disco")?;
                    total_read += n;

                    if content_length > 0 {
                        let progress = (total_read as f32) / (content_length as f32);
                        progress_callback(UpdateStatus::Downloading(progress.min(1.0)));
                    }
                }
                Err(e) => bail!("Erro durante o download do fluxo de dados: {}", e),
            }
        }

        writer
            .flush()
            .context("Falha ao descarregar buffers do executável baixado")?;

        // Validação de sanidade do executável PE Windows (deve começar com "MZ" - 0x4D, 0x5A)
        if total_read < 1024 || header_check != [0x4D, 0x5A] {
            let _ = fs::remove_file(&new_exe);
            bail!("Arquivo baixado não é um executável Windows válido ou está corrompido");
        }

        info!("Download concluído com sucesso: {} bytes.", total_read);
    }

    // 4. Substituição do executável no Windows
    if old_exe.exists() {
        let _ = fs::remove_file(&old_exe);
    }

    // Renomeia atual -> old
    fs::rename(&current_exe, &old_exe).context("Falha ao mover executável atual para backup")?;

    // Renomeia new -> atual
    if let Err(e) = fs::rename(&new_exe, &current_exe) {
        // Tenta reverter o backup em caso de erro
        let _ = fs::rename(&old_exe, &current_exe);
        return Err(e).context("Falha ao posicionar novo executável");
    }

    info!("Executável substituído com sucesso por {:?}", current_exe);

    // 5. Reinicia o aplicativo atualizado em novo processo com instrução de limpeza
    Command::new(&current_exe)
        .arg("--cleanup-old")
        .spawn()
        .context("Falha ao iniciar processo atualizado")?;

    progress_callback(UpdateStatus::Success(
        "Atualização concluída com sucesso! Reiniciando...".to_string(),
    ));

    // Pequena pausa para garantir que o novo processo foi despachado
    std::thread::sleep(std::time::Duration::from_millis(300));
    std::process::exit(0);
}

/// Remove arquivos temporários deixados por uma atualização anterior (.exe.old e .exe.new).
pub fn clean_old_update_files() {
    if let Ok(exe_path) = std::env::current_exe() {
        let old_exe = exe_path.with_extension("exe.old");
        let new_exe = exe_path.with_extension("exe.new");

        if new_exe.exists() {
            let _ = fs::remove_file(&new_exe);
        }

        if old_exe.exists() {
            let is_cleanup_arg = std::env::args().any(|a| a == "--cleanup-old");
            std::thread::spawn(move || {
                if is_cleanup_arg {
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
                for _ in 0..15 {
                    if fs::remove_file(&old_exe).is_ok() {
                        tracing::info!(
                            "Executável de versão anterior (.exe.old) removido com sucesso."
                        );
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("V2.0"), Some((2, 0, 0)));
        assert_eq!(parse_version("10.5.2"), Some((10, 5, 2)));
        assert_eq!(parse_version("invalid"), None);
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.2.0", "0.1.0"));
        assert!(is_newer_version("v1.0.0", "0.9.9"));
        assert!(is_newer_version("0.1.1", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
        assert!(!is_newer_version("v0.1.0", "0.1.1"));
    }
}

