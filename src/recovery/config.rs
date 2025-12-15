// =============================================================================
// MOONCOIN - Recovery Social: Configuration
// =============================================================================

use serde::{Serialize, Deserialize};
use super::{DEFAULT_RECOVERY_DELAY_BLOCKS, validate_delay};

// =============================================================================
// Recovery Tier
// =============================================================================

/// Niveles predefinidos de recovery
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryTier {
    /// 15 días de delay - Balance entre seguridad y conveniencia
    Standard,
    
    /// 30 días de delay - Recomendado para la mayoría
    Secure,
    
    /// 90 días de delay - Para cantidades muy grandes
    Maximum,
    
    /// Delay personalizado (en bloques)
    Custom(u32),
}

impl RecoveryTier {
    /// Obtener delay en bloques
    pub fn delay_blocks(&self) -> u32 {
        match self {
            RecoveryTier::Standard => 4320,   // ~15 días
            RecoveryTier::Secure => 8640,     // ~30 días
            RecoveryTier::Maximum => 25920,   // ~90 días
            RecoveryTier::Custom(blocks) => *blocks,
        }
    }
    
    /// Descripción legible
    pub fn description(&self) -> String {
        match self {
            RecoveryTier::Standard => "Standard (~15 días)".to_string(),
            RecoveryTier::Secure => "Secure (~30 días) - Recomendado".to_string(),
            RecoveryTier::Maximum => "Maximum (~90 días)".to_string(),
            RecoveryTier::Custom(b) => format!("Custom ({} bloques / ~{} días)", b, b / 288),
        }
    }
    
    /// Crear desde días
    pub fn from_days(days: u32) -> Self {
        match days {
            15 => RecoveryTier::Standard,
            30 => RecoveryTier::Secure,
            90 => RecoveryTier::Maximum,
            d => RecoveryTier::Custom(d * 288),
        }
    }
}

impl Default for RecoveryTier {
    fn default() -> Self {
        RecoveryTier::Secure
    }
}

// =============================================================================
// Recovery Config
// =============================================================================

/// Configuración completa de recovery social
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Tier de delay
    pub tier: RecoveryTier,
    
    /// Dirección de destino para recovery
    pub recovery_destination: String,
    
    /// Notificar al usuario cuando se inicia recovery
    pub notify_on_initiation: bool,
    
    /// Email para notificaciones
    pub notification_email: Option<String>,
    
    /// Webhook para notificaciones
    pub notification_webhook: Option<String>,
    
    /// Permitir extensión del delay por el usuario
    pub allow_delay_extension: bool,
    
    /// Bloques extra si se extiende el delay
    pub extension_blocks: Option<u32>,
    
    /// Requerir que los guardianes provean mensaje/razón
    pub require_reason: bool,
    
    /// Permitir recovery parcial (múltiples salidas)
    pub allow_partial_recovery: bool,
    
    /// Metadatos
    pub metadata: Option<String>,
}

impl RecoveryConfig {
    /// Crear configuración básica
    pub fn new(recovery_destination: String) -> Self {
        RecoveryConfig {
            tier: RecoveryTier::default(),
            recovery_destination,
            notify_on_initiation: true,
            notification_email: None,
            notification_webhook: None,
            allow_delay_extension: true,
            extension_blocks: Some(4320), // +15 días
            require_reason: false,
            allow_partial_recovery: false,
            metadata: None,
        }
    }
    
    /// Con tier específico
    pub fn with_tier(mut self, tier: RecoveryTier) -> Self {
        self.tier = tier;
        self
    }
    
    /// Con notificación por email
    pub fn with_email_notification(mut self, email: &str) -> Self {
        self.notification_email = Some(email.to_string());
        self.notify_on_initiation = true;
        self
    }
    
    /// Validar configuración
    pub fn validate(&self) -> Result<(), super::RecoveryError> {
        validate_delay(self.tier.delay_blocks())?;
        
        if self.recovery_destination.is_empty() {
            return Err(super::RecoveryError::Other(
                "Recovery destination cannot be empty".to_string()
            ));
        }
        
        if let Some(ext) = self.extension_blocks {
            let total = self.tier.delay_blocks().saturating_add(ext);
            if total > super::MAX_RECOVERY_DELAY_BLOCKS {
                return Err(super::RecoveryError::InvalidDelay { 
                    blocks: total, 
                    min: super::MIN_RECOVERY_DELAY_BLOCKS, 
                    max: super::MAX_RECOVERY_DELAY_BLOCKS 
                });
            }
        }
        
        Ok(())
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        RecoveryConfig::new("".to_string())
    }
}

// =============================================================================
// Presets
// =============================================================================

impl RecoveryConfig {
    /// Preset para individuos
    pub fn individual(recovery_destination: String) -> Self {
        RecoveryConfig::new(recovery_destination)
            .with_tier(RecoveryTier::Secure)
    }
    
    /// Preset para familias (más tiempo para coordinar)
    pub fn family(recovery_destination: String) -> Self {
        RecoveryConfig {
            tier: RecoveryTier::Secure,
            recovery_destination,
            notify_on_initiation: true,
            notification_email: None,
            notification_webhook: None,
            allow_delay_extension: true,
            extension_blocks: Some(8640), // +30 días
            require_reason: true,
            allow_partial_recovery: false,
            metadata: None,
        }
    }
    
    /// Preset para empresas (máxima seguridad)
    pub fn business(recovery_destination: String) -> Self {
        RecoveryConfig {
            tier: RecoveryTier::Maximum,
            recovery_destination,
            notify_on_initiation: true,
            notification_email: None,
            notification_webhook: None,
            allow_delay_extension: true,
            extension_blocks: Some(25920), // +90 días
            require_reason: true,
            allow_partial_recovery: true,
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
    fn test_recovery_tier() {
        assert_eq!(RecoveryTier::Standard.delay_blocks(), 4320);
        assert_eq!(RecoveryTier::Secure.delay_blocks(), 8640);
        assert_eq!(RecoveryTier::Maximum.delay_blocks(), 25920);
        assert_eq!(RecoveryTier::Custom(1000).delay_blocks(), 1000);
    }
    
    #[test]
    fn test_tier_from_days() {
        assert_eq!(RecoveryTier::from_days(15), RecoveryTier::Standard);
        assert_eq!(RecoveryTier::from_days(30), RecoveryTier::Secure);
        assert_eq!(RecoveryTier::from_days(90), RecoveryTier::Maximum);
        
        if let RecoveryTier::Custom(blocks) = RecoveryTier::from_days(45) {
            assert_eq!(blocks, 45 * 288);
        } else {
            panic!("Expected Custom tier");
        }
    }
    
    #[test]
    fn test_config_validation() {
        let valid = RecoveryConfig::new("MC1destination".to_string());
        assert!(valid.validate().is_ok());
        
        let invalid = RecoveryConfig::new("".to_string());
        assert!(invalid.validate().is_err());
    }
    
    #[test]
    fn test_presets() {
        let individual = RecoveryConfig::individual("MC1addr".to_string());
        assert_eq!(individual.tier, RecoveryTier::Secure);
        
        let family = RecoveryConfig::family("MC1addr".to_string());
        assert!(family.require_reason);
        
        let business = RecoveryConfig::business("MC1addr".to_string());
        assert_eq!(business.tier, RecoveryTier::Maximum);
        assert!(business.allow_partial_recovery);
    }
}
