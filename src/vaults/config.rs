// =============================================================================
// MOONCOIN - Vault Configuration
// =============================================================================
//
// Configuración de vaults con diferentes niveles de protección.
//
// =============================================================================

use serde::{Serialize, Deserialize};
use super::{MIN_DELAY_BLOCKS, MAX_DELAY_BLOCKS, DEFAULT_DELAY_BLOCKS, validate_delay};

// =============================================================================
// Vault Tiers (Niveles de Protección)
// =============================================================================

/// Niveles predefinidos de protección
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultTier {
    /// ~30 minutos - Para gastos pequeños del día a día
    Quick,
    
    /// ~12 horas - Balance entre seguridad y conveniencia (RECOMENDADO)
    Standard,
    
    /// ~24 horas - Para ahorros importantes
    Secure,
    
    /// ~7 días - Para cold storage / grandes cantidades
    Maximum,
    
    /// Delay personalizado en bloques
    Custom(u32),
}

impl VaultTier {
    /// Obtener delay en bloques
    pub fn delay_blocks(&self) -> u32 {
        match self {
            VaultTier::Quick => 6,
            VaultTier::Standard => DEFAULT_DELAY_BLOCKS,
            VaultTier::Secure => 288,
            VaultTier::Maximum => 2016,
            VaultTier::Custom(blocks) => *blocks,
        }
    }
    
    /// Descripción legible para humanos
    pub fn description(&self) -> String {
        match self {
            VaultTier::Quick => "Quick (~30 min) - Para gastos pequeños".to_string(),
            VaultTier::Standard => "Standard (~12h) - Balance recomendado".to_string(),
            VaultTier::Secure => "Secure (~24h) - Para ahorros".to_string(),
            VaultTier::Maximum => "Maximum (~7 días) - Cold storage".to_string(),
            VaultTier::Custom(b) => format!("Custom ({} bloques)", b),
        }
    }
    
    /// Tiempo estimado de espera
    pub fn time_estimate(&self) -> String {
        super::blocks_to_time_estimate(self.delay_blocks())
    }
    
    /// Crear tier desde número de bloques
    pub fn from_blocks(blocks: u32) -> Self {
        match blocks {
            6 => VaultTier::Quick,
            144 => VaultTier::Standard,
            288 => VaultTier::Secure,
            2016 => VaultTier::Maximum,
            _ => VaultTier::Custom(blocks),
        }
    }
    
    /// Nivel de seguridad (1-4)
    pub fn security_level(&self) -> u8 {
        match self {
            VaultTier::Quick => 1,
            VaultTier::Standard => 2,
            VaultTier::Secure => 3,
            VaultTier::Maximum => 4,
            VaultTier::Custom(b) => {
                if *b <= 6 { 1 }
                else if *b <= 144 { 2 }
                else if *b <= 288 { 3 }
                else { 4 }
            }
        }
    }
}

impl Default for VaultTier {
    fn default() -> Self {
        VaultTier::Standard
    }
}

impl std::fmt::Display for VaultTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// =============================================================================
// Vault Configuration
// =============================================================================

/// Configuración completa de un vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Nivel de protección
    pub tier: VaultTier,
    
    /// Nombre descriptivo (opcional, para UI)
    pub name: Option<String>,
    
    /// Notificaciones habilitadas
    pub notifications_enabled: bool,
    
    /// Email para alertas (opcional)
    pub alert_email: Option<String>,
    
    /// Webhook URL para alertas (opcional)
    pub alert_webhook: Option<String>,
    
    /// Auto-cancel si no se confirma manualmente
    pub auto_cancel_on_suspicious: bool,
    
    /// Monto máximo sin delay adicional (en satoshis)
    pub high_value_threshold: Option<u64>,
    
    /// Delay adicional para montos altos (en bloques)
    pub high_value_extra_delay: Option<u32>,
    
    /// Requiere 2FA para iniciar retiro
    pub require_2fa: bool,
    
    /// Direcciones en whitelist (retiro instantáneo)
    pub whitelist_addresses: Vec<String>,
    
    /// Metadatos personalizados
    pub metadata: Option<String>,
}

impl VaultConfig {
    /// Crear configuración básica
    pub fn new(tier: VaultTier) -> Self {
        VaultConfig {
            tier,
            name: None,
            notifications_enabled: true,
            alert_email: None,
            alert_webhook: None,
            auto_cancel_on_suspicious: false,
            high_value_threshold: None,
            high_value_extra_delay: None,
            require_2fa: false,
            whitelist_addresses: Vec::new(),
            metadata: None,
        }
    }
    
    /// Configuración con nombre
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }
    
    /// Configuración con email de alerta
    pub fn with_alert_email(mut self, email: &str) -> Self {
        self.alert_email = Some(email.to_string());
        self.notifications_enabled = true;
        self
    }
    
    /// Configuración con umbral de alto valor
    pub fn with_high_value_protection(mut self, threshold_sats: u64, extra_delay_blocks: u32) -> Self {
        self.high_value_threshold = Some(threshold_sats);
        self.high_value_extra_delay = Some(extra_delay_blocks);
        self
    }
    
    /// Agregar dirección a whitelist
    pub fn add_whitelist_address(mut self, address: &str) -> Self {
        self.whitelist_addresses.push(address.to_string());
        self
    }
    
    /// Obtener delay efectivo para un monto
    pub fn effective_delay(&self, amount: u64) -> u32 {
        let base_delay = self.tier.delay_blocks();
        
        if let (Some(threshold), Some(extra)) = (self.high_value_threshold, self.high_value_extra_delay) {
            if amount > threshold {
                return base_delay.saturating_add(extra);
            }
        }
        
        base_delay
    }
    
    /// Verificar si una dirección está en whitelist
    pub fn is_whitelisted(&self, address: &str) -> bool {
        self.whitelist_addresses.iter().any(|a| a == address)
    }
    
    /// Validar configuración
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_delay(self.tier.delay_blocks())?;
        
        if let Some(extra) = self.high_value_extra_delay {
            let total = self.tier.delay_blocks().saturating_add(extra);
            if total > MAX_DELAY_BLOCKS {
                return Err("Total delay (base + high value) exceeds maximum");
            }
        }
        
        Ok(())
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig::new(VaultTier::Standard)
    }
}

// =============================================================================
// Preset Configurations
// =============================================================================

impl VaultConfig {
    /// Preset: Vault para gastos diarios
    pub fn daily_spending() -> Self {
        VaultConfig::new(VaultTier::Quick)
            .with_name("Daily Spending")
    }
    
    /// Preset: Vault para ahorros
    pub fn savings() -> Self {
        VaultConfig::new(VaultTier::Secure)
            .with_name("Savings")
            .with_high_value_protection(10_000_000_000, 144)
    }
    
    /// Preset: Cold storage
    pub fn cold_storage() -> Self {
        VaultConfig::new(VaultTier::Maximum)
            .with_name("Cold Storage")
            .with_high_value_protection(100_000_000_000, 2016)
    }
    
    /// Preset: Vault empresarial
    pub fn business() -> Self {
        VaultConfig {
            tier: VaultTier::Secure,
            name: Some("Business Vault".to_string()),
            notifications_enabled: true,
            alert_email: None,
            alert_webhook: None,
            auto_cancel_on_suspicious: true,
            high_value_threshold: Some(50_000_000_000),
            high_value_extra_delay: Some(288),
            require_2fa: true,
            whitelist_addresses: Vec::new(),
            metadata: None,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vault_tiers() {
        assert_eq!(VaultTier::Quick.delay_blocks(), 6);
        assert_eq!(VaultTier::Standard.delay_blocks(), 144);
        assert_eq!(VaultTier::Secure.delay_blocks(), 288);
        assert_eq!(VaultTier::Maximum.delay_blocks(), 2016);
        assert_eq!(VaultTier::Custom(500).delay_blocks(), 500);
    }
    
    #[test]
    fn test_tier_from_blocks() {
        assert_eq!(VaultTier::from_blocks(6), VaultTier::Quick);
        assert_eq!(VaultTier::from_blocks(144), VaultTier::Standard);
        assert_eq!(VaultTier::from_blocks(100), VaultTier::Custom(100));
    }
    
    #[test]
    fn test_security_levels() {
        assert_eq!(VaultTier::Quick.security_level(), 1);
        assert_eq!(VaultTier::Standard.security_level(), 2);
        assert_eq!(VaultTier::Secure.security_level(), 3);
        assert_eq!(VaultTier::Maximum.security_level(), 4);
    }
    
    #[test]
    fn test_vault_config_default() {
        let config = VaultConfig::default();
        assert_eq!(config.tier, VaultTier::Standard);
        assert!(config.notifications_enabled);
        assert!(config.whitelist_addresses.is_empty());
    }
    
    #[test]
    fn test_effective_delay() {
        let config = VaultConfig::new(VaultTier::Standard)
            .with_high_value_protection(1_000_000, 72);
        
        assert_eq!(config.effective_delay(500_000), 144);
        assert_eq!(config.effective_delay(2_000_000), 144 + 72);
    }
    
    #[test]
    fn test_whitelist() {
        let config = VaultConfig::new(VaultTier::Standard)
            .add_whitelist_address("MC1trusted123")
            .add_whitelist_address("MC1family456");
        
        assert!(config.is_whitelisted("MC1trusted123"));
        assert!(config.is_whitelisted("MC1family456"));
        assert!(!config.is_whitelisted("MC1random789"));
    }
    
    #[test]
    fn test_presets() {
        let daily = VaultConfig::daily_spending();
        assert_eq!(daily.tier, VaultTier::Quick);
        
        let savings = VaultConfig::savings();
        assert_eq!(savings.tier, VaultTier::Secure);
        
        let cold = VaultConfig::cold_storage();
        assert_eq!(cold.tier, VaultTier::Maximum);
        
        let biz = VaultConfig::business();
        assert!(biz.require_2fa);
    }
    
    #[test]
    fn test_config_validation() {
        let valid = VaultConfig::new(VaultTier::Standard);
        assert!(valid.validate().is_ok());
        
        let invalid = VaultConfig::new(VaultTier::Custom(1));
        assert!(invalid.validate().is_err());
    }
}
