// AI Decision Audit Ledger Module
// Provides immutable, tamper-proof logging of all AI decisions for legal/tribunal proceedings

pub mod ledger;
pub mod tribunal;

#[allow(unused_imports)]
pub use ledger::AuditLedger;
pub use ledger::TribunalFormat;
