// =============================================================================
// MOONCOIN - Herencia Digital: Configuración
// =============================================================================

use serde::{Serialize, Deserialize};
use super::{
    InheritanceError,
    DEFAULT_INACTIVITY_BLOCKS, DEFAULT_CHECKIN_INTERVAL,
    validate_inactivity_period, validate_checkin_interval,
    blocks_to_months, months_to_blocks,
};

// =============================================================================
// Inactivity Period
// =============================================================================

/// Períodos de inactividad predefinidos
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InactivityPeriod {
    /// 3 meses
    ThreeMonths,
    
    /// 6 meses
    SixMonths,
    
    /// 1 año (recomendado)
    OneYear,
    
    /// 2 años
    TwoYears,
    
    /// 5 años
    FiveYears,
    
    /// Personalizado (en bloques)
    Custom(u32),
}

impl InactivityPeriod {
    /// Obtener período en bloques
    pub fn blocks(&self) -> u32 {
        match self {
            InactivityPeriod::ThreeMonths => 25920,
            InactivityPeriod::SixMonths => 51840,
            InactivityPeriod::OneYear => 105120,
            InactivityPeriod::TwoYears => 210240,
            InactivityPeriod::FiveYears => 525600,
            InactivityPeriod::Custom(b) => *b,
        }
    }
    
    /// Descripción legible
    pub fn description(&self) -> String {
        match self {
            InactivityPeriod::ThreeMonths => "3 meses".to_string(),
            InactivityPeriod::SixMonths => "6 meses".to_string(),
            InactivityPeriod::OneYear => "1 año (recomendado)".to_string(),
            InactivityPeriod::TwoYears => "2 años".to_string(),
            InactivityPeriod::FiveYears => "5 años".to_string(),
            InactivityPeriod::Custom(b) => format!("{} meses", blocks_to_months(*b)),
        }
    }
    
    /// Crear desde meses
    pub fn from_months(months: u32) -> Self {
        match months {
            3 => InactivityPeriod::ThreeMonths,
            6 => InactivityPeriod::SixMonths,
            12 => InactivityPeriod::OneYear,
            24 => InactivityPeriod::TwoYears,
            60 => InactivityPeriod::FiveYears,
            m => InactivityPeriod::Custom(months_to_blocks(m)),
        }
    }
    
    /// Intervalo de check-in recomendado (mitad del período)
    pub fn recommended_checkin_interval(&self) -> u32 {
        self.blocks() / 2
    }
}

impl Default for InactivityPeriod {
    fn default() -> Self {
        InactivityPeriod::OneYear
    }
}

// =============================================================================
// Inheritance Config
// =============================================================================

/// Configuración completa de herencia
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceConfig {
    /// Período de inactividad
    pub inactivity_period: InactivityPeriod,
    
    /// Intervalo recomendado de check-in (en bloques)
    pub checkin_interval: u32,
    
    /// Notificar cuando se acerca deadline
    pub notify_before_deadline: bool,
    
    /// Bloques antes del deadline para notificar
    pub notification_threshold: u32,
    
    /// Email para notificaciones
    pub notification_email: Option<String>,
    
    /// Mensaje para los herederos
    pub message_to_heirs: Option<String>,
    
    /// Permitir que herederos extiendan el deadline
    pub heirs_can_extend: bool,
    
    /// Bloques de extensión si herederos extienden
    pub extension_blocks: Option<u32>,
    
    /// Metadatos
    pub metadata: Option<String>,
}

impl InheritanceConfig {
    /// Crear configuración básica
    pub fn new(inactivity_period: InactivityPeriod) -> Self {
        let checkin = inactivity_period.recommended_checkin_interval();
        
        InheritanceConfig {
            inactivity_period,
            checkin_interval: checkin,
            notify_before_deadline: true,
            notification_threshold: 8640, // ~1 mes antes
            notification_email: None,
            message_to_heirs: None,
            heirs_can_extend: false,
            extension_blocks: None,
            metadata: None,
        }
    }
    
    /// Con email de notificación
    pub fn with_notification_email(mut self, email: &str) -> Self {
        self.notification_email = Some(email.to_string());
        self.notify_before_deadline = true;
        self
    }
    
    /// Con mensaje para herederos
    pub fn with_message(mut self, message: &str) -> Self {
        self.message_to_heirs = Some(message.to_string());
        self
    }
    
    /// Con intervalo de check-in personalizado
    pub fn with_checkin_interval(mut self, blocks: u32) -> Self {
        self.checkin_interval = blocks;
        self
    }
    
    /// Validar configuración
    pub fn validate(&self) -> Result<(), InheritanceError> {
        validate_inactivity_period(self.inactivity_period.blocks())?;
        validate_checkin_interval(self.checkin_interval, self.inactivity_period.blocks())?;
        Ok(())
    }
}

impl Default for InheritanceConfig {
    fn default() -> Self {
        InheritanceConfig::new(InactivityPeriod::default())
    }
}

// =============================================================================
// Presets
// =============================================================================

impl InheritanceConfig {
    /// Preset conservador (1 año, check-in cada 6 meses)
    pub fn conservative() -> Self {
        InheritanceConfig::new(InactivityPeriod::OneYear)
    }
    
    /// Preset activo (6 meses, check-in cada 3 meses)
    pub fn active() -> Self {
        InheritanceConfig::new(InactivityPeriod::SixMonths)
            .with_checkin_interval(months_to_blocks(3))
    }
    
    /// Preset largo plazo (2 años, check-in cada año)
    pub fn long_term() -> Self {
        InheritanceConfig::new(InactivityPeriod::TwoYears)
            .with_checkin_interval(months_to_blocks(12))
    }
    
    /// Preset cold storage (5 años)
    pub fn cold_storage() -> Self {
        InheritanceConfig::new(InactivityPeriod::FiveYears)
            .with_checkin_interval(months_to_blocks(24))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_inactivity_period() {
        assert_eq!(InactivityPeriod::ThreeMonths.blocks(), 25920);
        assert_eq!(InactivityPeriod::SixMonths.blocks(), 51840);
        assert_eq!(InactivityPeriod::OneYear.blocks(), 105120);
        assert_eq!(InactivityPeriod::Custom(10000).blocks(), 10000);
    }
    
    #[test]
    fn test_from_months() {
        assert_eq!(InactivityPeriod::from_months(3), InactivityPeriod::ThreeMonths);
        assert_eq!(InactivityPeriod::from_months(12), InactivityPeriod::OneYear);
        
        if let InactivityPeriod::Custom(blocks) = InactivityPeriod::from_months(9) {
            assert_eq!(blocks, months_to_blocks(9));
        } else {
            panic!("Expected Custom");
        }
    }
    
    #[test]
    fn test_recommended_checkin() {
        let period = InactivityPeriod::OneYear;
        let checkin = period.recommended_checkin_interval();
        
        // Debe ser la mitad del período
        assert_eq!(checkin, period.blocks() / 2);
    }
    
    #[test]
    fn test_config_validation() {
        let valid = InheritanceConfig::new(InactivityPeriod::OneYear);
        assert!(valid.validate().is_ok());
        
        // Intervalo de check-in mayor que inactividad
        let mut invalid = InheritanceConfig::new(InactivityPeriod::ThreeMonths);
        invalid.checkin_interval = invalid.inactivity_period.blocks() + 1;
        assert!(invalid.validate().is_err());
    }
    
    #[test]
    fn test_presets() {
        let conservative = InheritanceConfig::conservative();
        assert_eq!(conservative.inactivity_period, InactivityPeriod::OneYear);
        
        let active = InheritanceConfig::active();
        assert_eq!(active.inactivity_period, InactivityPeriod::SixMonths);
        
        let long = InheritanceConfig::long_term();
        assert_eq!(long.inactivity_period, InactivityPeriod::TwoYears);
        
        let cold = InheritanceConfig::cold_storage();
        assert_eq!(cold.inactivity_period, InactivityPeriod::FiveYears);
    }
}
