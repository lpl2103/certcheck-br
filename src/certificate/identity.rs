//! Extração e representação da identidade ICP-Brasil (Pessoa Física / Pessoa Jurídica).
//!
//! Identifica CPF, CNPJ, Titular e Razão Social com rastreabilidade da fonte exata do dado.

use serde::{Deserialize, Serialize};

/// Categoria da pessoa titular do certificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonType {
    PessoaFisica,
    PessoaJuridica,
    Equipamento,
    Desconhecido,
}

impl std::fmt::Display for PersonType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersonType::PessoaFisica => write!(f, "Pessoa Física (e-CPF)"),
            PersonType::PessoaJuridica => write!(f, "Pessoa Jurídica (e-CNPJ)"),
            PersonType::Equipamento => write!(f, "Equipamento / Aplicação"),
            PersonType::Desconhecido => write!(f, "Desconhecido"),
        }
    }
}

/// Identidade decodificada com rastreamento da fonte de dados.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcpBrasilIdentity {
    pub person_type: Option<PersonType>,
    pub holder_name: Option<String>,
    pub company_name: Option<String>,
    pub cpf: Option<String>,
    pub cnpj: Option<String>,
    pub email: Option<String>,
    pub nis_pis_pasep: Option<String>,
    pub rg: Option<String>,
    pub cei_inss: Option<String>,
    /// Descrição da fonte técnica onde cada dado foi encontrado (ex: "SAN otherName 2.16.76.1.3.1").
    pub data_source_description: String,
}

impl IcpBrasilIdentity {
    /// Formata o CPF no padrão XXX.XXX.XXX-XX se tiver 11 dígitos numéricos.
    pub fn formatted_cpf(&self) -> Option<String> {
        let cpf = self.cpf.as_deref()?;
        let digits: String = cpf.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 11 {
            Some(format!(
                "{}.{}.{}-{}",
                &digits[0..3],
                &digits[3..6],
                &digits[6..9],
                &digits[9..11]
            ))
        } else {
            Some(cpf.to_string())
        }
    }

    /// Formata o CNPJ no padrão XX.XXX.XXX/XXXX-XX se tiver 14 dígitos numéricos.
    pub fn formatted_cnpj(&self) -> Option<String> {
        let cnpj = self.cnpj.as_deref()?;
        let digits: String = cnpj.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 14 {
            Some(format!(
                "{}.{}.{}/{}-{}",
                &digits[0..2],
                &digits[2..5],
                &digits[5..8],
                &digits[8..12],
                &digits[12..14]
            ))
        } else {
            Some(cnpj.to_string())
        }
    }

    /// Retorna o nome do responsável legal caso seja pessoa jurídica (e-CNPJ)
    pub fn legal_representative(&self) -> Option<&str> {
        if self.cnpj.is_some() {
            self.holder_name.as_deref()
        } else {
            None
        }
    }

    /// Verifica se possui características estruturais da ICP-Brasil
    pub fn is_icp_brasil(&self) -> bool {
        self.cpf.is_some() || self.cnpj.is_some() || self.person_type.is_some()
    }
}
