//! Módulo específico para regras, cadeias e políticas da Infraestrutura de Chaves Públicas Brasileira (ICP-Brasil).

pub mod oids;

pub use oids::*;

/// Valida se um determinado OID pertence à hierarquia da ICP-Brasil.
pub fn is_icp_brasil_oid(oid: &str) -> bool {
    oid.starts_with(OID_ICP_BRASIL_ROOT)
}
