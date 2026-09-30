//! Identificadores de Objeto (OIDs) normativos da ICP-Brasil (DOC-ICP-04).

/// Raiz da árvore de OIDs da ICP-Brasil (2.16.76.1)
pub const OID_ICP_BRASIL_ROOT: &str = "2.16.76.1";

// OIDs de Atributos do Titular (extensão Subject Alternative Name - otherName)
/// Dados da Pessoa Física (PF): Nascimento, CPF, NIS/PIS/PASEP, RG, Órgão Expedidor.
pub const OID_ICP_BR_PF_DADOS: &str = "2.16.76.1.3.1";

/// Nome do Responsável pela Pessoa Jurídica (PJ).
pub const OID_ICP_BR_PJ_NOME_RESPONSAVEL: &str = "2.16.76.1.3.2";

/// CNPJ da Pessoa Jurídica (14 dígitos).
pub const OID_ICP_BR_PJ_CNPJ: &str = "2.16.76.1.3.3";

/// Dados do Responsável pela Pessoa Jurídica (Nascimento, CPF, NIS, RG...).
pub const OID_ICP_BR_PJ_RESPONSAVEL: &str = "2.16.76.1.3.4";

/// Número de Inscrição no PIS/PASEP (específico).
pub const OID_ICP_BR_PIS_PASEP: &str = "2.16.76.1.3.5";

/// Número do CEI (Cadastro Específico do INSS) - Pessoa Física.
pub const OID_ICP_BR_CEI_PF: &str = "2.16.76.1.3.7";

/// Número do CEI (Cadastro Específico do INSS) - Pessoa Jurídica.
pub const OID_ICP_BR_CEI_PJ: &str = "2.16.76.1.3.8";

/// OID do Título de Eleitor da Pessoa Física.
pub const OID_ICP_BR_TITULO_ELEITOR: &str = "2.16.76.1.3.6";

// Tipos de certificados da ICP-Brasil
pub const OID_POLICY_A1: &str = "2.16.76.1.2.1";
pub const OID_POLICY_A2: &str = "2.16.76.1.2.2";
pub const OID_POLICY_A3: &str = "2.16.76.1.2.3";
pub const OID_POLICY_A4: &str = "2.16.76.1.2.4";
pub const OID_POLICY_S1: &str = "2.16.76.1.2.101";
pub const OID_POLICY_S2: &str = "2.16.76.1.2.102";
pub const OID_POLICY_S3: &str = "2.16.76.1.2.103";
pub const OID_POLICY_S4: &str = "2.16.76.1.2.104";
pub const OID_POLICY_T3: &str = "2.16.76.1.2.203";
pub const OID_POLICY_T4: &str = "2.16.76.1.2.204";

/// Retorna a descrição amigável de um OID conhecido da ICP-Brasil.
pub fn describe_icp_oid(oid: &str) -> Option<&'static str> {
    match oid {
        OID_ICP_BR_PF_DADOS => Some("ICP-Brasil: Dados do Titular (Pessoa Física)"),
        OID_ICP_BR_PJ_NOME_RESPONSAVEL => Some("ICP-Brasil: Nome do Responsável pela PJ"),
        OID_ICP_BR_PJ_CNPJ => Some("ICP-Brasil: CNPJ da Empresa"),
        OID_ICP_BR_PJ_RESPONSAVEL => Some("ICP-Brasil: Dados do Responsável pela PJ"),
        OID_ICP_BR_PIS_PASEP => Some("ICP-Brasil: NIS / PIS / PASEP"),
        OID_ICP_BR_TITULO_ELEITOR => Some("ICP-Brasil: Título de Eleitor"),
        OID_ICP_BR_CEI_PF => Some("ICP-Brasil: CEI Pessoa Física"),
        OID_ICP_BR_CEI_PJ => Some("ICP-Brasil: CEI Pessoa Jurídica"),
        OID_POLICY_A1 => Some("Política de Certificado ICP-Brasil A1"),
        OID_POLICY_A2 => Some("Política de Certificado ICP-Brasil A2"),
        OID_POLICY_A3 => Some("Política de Certificado ICP-Brasil A3"),
        OID_POLICY_A4 => Some("Política de Certificado ICP-Brasil A4"),
        OID_POLICY_S1 => Some("Política de Certificado de Sigilo S1"),
        OID_POLICY_S2 => Some("Política de Certificado de Sigilo S2"),
        OID_POLICY_S3 => Some("Política de Certificado de Sigilo S3"),
        OID_POLICY_S4 => Some("Política de Certificado de Sigilo S4"),
        OID_POLICY_T3 => Some("Política de Carimbo do Tempo T3"),
        OID_POLICY_T4 => Some("Política de Carimbo do Tempo T4"),
        _ => None,
    }
}
