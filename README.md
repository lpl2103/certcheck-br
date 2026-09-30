# CertCheck BR — Diagnóstico Técnico de Certificados Digitais ICP-Brasil

O **CertCheck BR** é uma aplicação desktop nativa para Windows (10/11 x86_64), escrita em **Rust**, projetada para detecção, análise estrutural, validação de conformidade, consulta de revogação e testes criptográficos de certificados digitais brasileiros, com foco em certificados **ICP-Brasil A1 e A3**.

Diferente de ferramentas simplificadas que apenas verificam datas de expiração, o CertCheck BR é uma ferramenta técnica de diagnóstico aprofundado que opera de forma modular, segura e em camadas.

---

## 🏛 Arquitetura em Camadas (Fase 1)

O projeto é organizado segundo os princípios de arquitetura limpa e separação estrita de responsabilidades:

```text
certcheck-br/
├── Cargo.toml                  # Dependências maduras e estritamente auditadas
├── .cargo/config.toml          # Configuração do linker para o ecossistema Windows
├── src/
│   ├── main.rs                 # Ponto de entrada, inicialização de logs e janela eframe
│   ├── lib.rs                  # Re-export de toda a API de domínio e aplicação
│   │
│   ├── certificate/            # Modelos de domínio: X.509, DN, chaves, extensões e identidade
│   │   ├── types.rs            # CertificateType (A1/A3), KeyAlgorithm, KeyUsage, EKU, SAN
│   │   ├── identity.rs         # Identidade ICP-Brasil (CPF, CNPJ, Razão Social, Titular)
│   │   └── mod.rs              # CertificateInfo e métodos de validade
│   │
│   ├── validation/             # Motor de decisão e checagens de conformidade
│   │   ├── checks.rs           # ValidationCheck, CheckStatus (PASS/INFO/AVISO/FALHA), categorias
│   │   └── mod.rs              # ValidationResult e OverallStatus (Apto, Com Restrições, Inapto)
│   │
│   ├── crypto/                 # Abstrações criptográficas seguras
│   │   ├── provider.rs         # Trait CryptoProvider, ProviderInfo, Signature, SignaturePadding
│   │   └── mod.rs              # SignatureTestResult e tipos de suporte
│   │
│   ├── revocation/             # Modelos de consulta a CRL e OCSP
│   │   ├── model.rs            # CrlDetails, OcspDetails, RevocationStatus, RevocationSummary
│   │   └── mod.rs              # Lógica de consolidação de revogação
│   │
│   ├── icp_brasil/             # Regras normativas da ICP-Brasil (DOC-ICP-04)
│   │   ├── oids.rs             # OIDs oficiais do ITI (CPF, CNPJ, CEI, Políticas A1/A3)
│   │   └── mod.rs              # Reconhecimento e descrição de OIDs
│   │
│   ├── diagnostics/            # Diagnóstico de hardware A3, leitores, smart cards e rede
│   │   ├── model.rs            # ReaderInfo, TokenInfo, ProviderDiagnostic, A3DiagnosticSummary
│   │   └── mod.rs              # Diagnóstico consolidado
│   │
│   ├── report/                 # Relatórios técnicos estruturados
│   │   ├── model.rs            # DiagnosticReport e exportação JSON formatada
│   │   └── mod.rs              # Relatórios consolidados
│   │
│   ├── app/                    # Estado da aplicação e concorrência
│   │   ├── state.rs            # AppState, DetailTab, ThemeMode, AppConfig
│   │   ├── commands.rs         # AppCommand e AppEvent para canais entre UI e workers
│   │   └── mod.rs              # Re-exports de aplicação
│   │
│   ├── gui/                    # Interface gráfica nativa de alto desempenho (egui/eframe)
│   │   ├── theme.rs            # Cores temáticas (Modo Claro / Escuro) e Badges de Status
│   │   ├── dashboard.rs        # Dashboard com veredito final e checklist de conformidade
│   │   ├── certificates.rs     # Tabela de certificados detectados e barra de ações
│   │   ├── details.rs          # Visualizador com 10 abas técnicas completas
│   │   ├── validation.rs       # Painel detalhado de checagens X.509
│   │   ├── revocation.rs       # Painel de consulta CRL e OCSP
│   │   ├── signature.rs        # Testador criptográfico de assinatura e verificação
│   │   ├── a3.rs               # Diagnóstico de leitores, Smart Cards e tokens USB
│   │   ├── diagnostics.rs      # Conectividade e integridade local
│   │   ├── settings.rs         # Modal de configurações gerais e timeouts
│   │   └── mod.rs              # Loop principal egui::App e tratamento de eventos
│   │
│   ├── logging/                # Logging estruturado com buffer em memória para a UI
│   │   ├── buffer.rs           # MemoryLogBuffer thread-safe com sanitização de segredos
│   │   └── mod.rs              # Layer para tracing-subscriber
│   │
│   └── error/                  # Tipagem de erros com thiserror
│       ├── error_types.rs      # CertCheckError e categorização por camada
│       └── mod.rs              # Result type alias
│
└── tests/
    └── domain_tests.rs         # Suíte de testes unitários automatizados
```

---

## 🔒 Princípios Fundamentais de Segurança

1. **Chaves Privadas Invioláveis**: O CertCheck BR **NUNCA** exporta, armazena, transmite ou tenta extrair chaves privadas. Para certificados A3, toda operação é delegada ao provider/token de hardware.
2. **Sem Persistência de Senhas ou PINs**: Senhas de arquivos PKCS#12 e PINs de tokens nunca são armazenados em disco, variáveis de ambiente ou logs. A autenticação de PIN é delegada ao middleware nativo do dispositivo.
3. **Logs Sanitizados**: O coletor de logs (`MemoryLogBuffer`) sanitiza automaticamente qualquer ocorrência acidental de padrões como `senha=`, `pin=`, `private_key`.
4. **Local-First (Offline)**: Todas as análises de estrutura X.509, cálculo de fingerprints, identificação de CPF/CNPJ e validação local operam 100% offline. Apenas checagens de revogação externa acionam a rede (com timeout estrito).

---

## 💻 Instruções de Compilação no Windows

### Pré-requisitos
- **Rust Stable** (versão 1.80 ou superior).
- Compilador C/C++ compatível no Windows (`MSVC Build Tools` ou `MinGW-w64 GCC`).

### Comandos de Compilação e Teste

1. **Verificação de sintaxe e tipos:**
   ```powershell
   cargo check
   ```

2. **Executar a suíte de testes unitários:**
   ```powershell
   cargo test
   ```

3. **Executar a aplicação com interface gráfica (modo Debug):**
   ```powershell
   cargo run
   ```

4. **Gerar o binário otimizado para produção (modo Release):**
   ```powershell
   cargo build --release
   ```
   O executável final estará disponível em: `target\release\certcheck-br.exe`.

---

## 📊 Status da Entrega

| Fase | Descrição | Status |
|---|---|---|
| **Fase 1** | Estrutura modular, Cargo.toml, GUI eframe, temas, logs em memória, erros, domínio, testes unitários | **Concluída** |
| **Fase 2** | Parser completo X.509, leitura de .CER, .CRT, .PEM, ASN.1 e fingerprints | *Próxima fase* |
| **Fase 3** | Parser PKCS#12 (.pfx / .p12), diálogo seguro de senha e teste de chave privada | *Futuro* |
| **Fase 4** | Integração com Windows Certificate Store (Crypt32) e detecção de tokens A3 (WinSCard/NCrypt) | *Futuro* |
| **Fase 5** | Construção de cadeia de confiança e políticas ICP-Brasil | *Futuro* |
| **Fase 6** | Motor de consulta de revogação online (CRL HTTP e OCSP) com cache | *Futuro* |
| **Fase 7** | Operações de assinatura digital RSA/ECDSA e diagnóstico aprofundado de middleware | *Futuro* |
| **Fase 8** | Exportação de relatórios técnicos em JSON e HTML | *Futuro* |
| **Fase 9** | Testes de integração, hardening e empacotamento Windows (MSI) | *Futuro* |
