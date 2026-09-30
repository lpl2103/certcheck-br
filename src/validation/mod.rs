//! Módulo de validação de conformidade técnica e tomada de decisão.

pub mod checks;

pub use checks::{CheckCategory, CheckStatus, ValidationCheck};

use serde::{Deserialize, Serialize};

/// Veredito geral sobre o estado do certificado para uso em operações práticas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverallStatus {
    /// Todos os requisitos fundamentais foram atendidos com sucesso.
    AptoParaUso,
    /// O certificado é utilizável, porém com avisos (ex.: CRL offline, expira em breve).
    ComRestricoes,
    /// O certificado não pode ser utilizado (ex.: expirado, revogado, assinatura inválida).
    Inapto,
    /// As checagens completas ainda não foram executadas.
    NaoVerificado,
}

impl std::fmt::Display for OverallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverallStatus::AptoParaUso => write!(f, "CERTIFICADO APTO PARA USO"),
            OverallStatus::ComRestricoes => write!(f, "CERTIFICADO COM RESTRIÇÕES"),
            OverallStatus::Inapto => write!(f, "CERTIFICADO INAPTO / INVÁLIDO"),
            OverallStatus::NaoVerificado => write!(f, "NÃO VERIFICADO"),
        }
    }
}

/// Conjunto consolidado de resultados de validação.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationResult {
    pub overall_status: Option<OverallStatus>,
    pub checks: Vec<ValidationCheck>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_check(&mut self, check: ValidationCheck) {
        self.checks.push(check);
    }

    pub fn count_passed(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Pass).count()
    }

    pub fn count_warnings(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Warning).count()
    }

    pub fn count_errors(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Error).count()
    }

    pub fn count_info(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Info).count()
    }

    /// Calcula o status geral a partir das checagens registradas.
    pub fn compute_overall_status(&mut self) -> OverallStatus {
        if self.checks.is_empty() {
            self.overall_status = Some(OverallStatus::NaoVerificado);
            return OverallStatus::NaoVerificado;
        }

        let errors = self.count_errors();
        let warnings = self.count_warnings();

        let status = if errors > 0 {
            OverallStatus::Inapto
        } else if warnings > 0 {
            OverallStatus::ComRestricoes
        } else {
            OverallStatus::AptoParaUso
        };

        self.overall_status = Some(status);
        status
    }
}
