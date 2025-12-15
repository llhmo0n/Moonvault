// =============================================================================
// MOONCOIN - Vault Manager
// =============================================================================
//
// Gestión de múltiples vaults de un usuario.
//
// RESPONSABILIDADES:
//   - Crear nuevos vaults
//   - Monitorear estados
//   - Ejecutar retiros/cancelaciones
//   - Alertas y notificaciones
//   - Persistencia
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    VaultId, VaultKeys, VaultConfig, VaultScript,
    VaultState, VaultStatus, WithdrawalRequest,
    validate_delay, blocks_to_time_estimate,
};

// =============================================================================
// Errors
// =============================================================================

/// Errores de operaciones de vault
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Vault no encontrado
    NotFound(String),
    
    /// Claves inválidas
    InvalidKeys(String),
    
    /// Configuración inválida
    InvalidConfig(String),
    
    /// Balance insuficiente
    InsufficientBalance { available: u64, requested: u64 },
    
    /// Estado inválido para la operación
    InvalidState { current: String, required: String },
    
    /// Ya existe un retiro pendiente
    WithdrawalAlreadyPending,
    
    /// No hay retiro pendiente
    NoActiveWithdrawal,
    
    /// Delay no cumplido
    DelayNotMet { blocks_remaining: u64 },
    
    /// Firma inválida
    InvalidSignature(String),
    
    /// Error de serialización
    SerializationError(String),
    
    /// Error genérico
    Other(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotFound(id) => write!(f, "Vault not found: {}", id),
            VaultError::InvalidKeys(msg) => write!(f, "Invalid keys: {}", msg),
            VaultError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            VaultError::InsufficientBalance { available, requested } => {
                write!(f, "Insufficient balance: {} available, {} requested", available, requested)
            }
            VaultError::InvalidState { current, required } => {
                write!(f, "Invalid state: {} (required: {})", current, required)
            }
            VaultError::WithdrawalAlreadyPending => write!(f, "Withdrawal already pending"),
            VaultError::NoActiveWithdrawal => write!(f, "No active withdrawal"),
            VaultError::DelayNotMet { blocks_remaining } => {
                write!(f, "Delay not met: {} blocks remaining", blocks_remaining)
            }
            VaultError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            VaultError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            VaultError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

// =============================================================================
// Vault Info (Vista simplificada)
// =============================================================================

/// Información resumida de un vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultInfo {
    /// ID del vault
    pub id: VaultId,
    
    /// Nombre (si tiene)
    pub name: Option<String>,
    
    /// Dirección P2SH del vault
    pub address: String,
    
    /// Balance actual (satoshis)
    pub balance: u64,
    
    /// Estado actual
    pub status: String,
    
    /// Delay en bloques
    pub delay_blocks: u32,
    
    /// Delay en tiempo legible
    pub delay_human: String,
    
    /// Tier de seguridad
    pub security_tier: String,
    
    /// Tiene retiro pendiente
    pub has_pending_withdrawal: bool,
    
    /// Bloques restantes para retiro (si aplica)
    pub blocks_until_withdrawal: Option<u64>,
    
    /// Tiempo restante legible (si aplica)
    pub time_until_withdrawal: Option<String>,
    
    /// Dirección de recuperación
    pub recovery_address: String,
    
    /// Fecha de creación
    pub created_at: String,
}

// =============================================================================
// Vault Manager
// =============================================================================

/// Gestor de vaults
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultManager {
    /// Vaults por ID
    vaults: HashMap<VaultId, ManagedVault>,
    
    /// Block height actual conocido
    current_block: u64,
    
    /// Índice de direcciones a vault IDs
    address_index: HashMap<String, VaultId>,
    
    /// Alertas activas
    active_alerts: Vec<VaultAlert>,
    
    /// Configuración del manager
    config: ManagerConfig,
}

/// Vault gestionado (estado + config + script)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedVault {
    pub state: VaultState,
    pub config: VaultConfig,
    pub script: VaultScript,
    pub keys: VaultKeys,
}

/// Configuración del manager
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerConfig {
    /// Alertar cuando un retiro está por expirar
    pub alert_on_pending_withdrawal: bool,
    
    /// Bloques antes de expiración para alertar
    pub alert_threshold_blocks: u32,
    
    /// Escanear automáticamente por depósitos
    pub auto_scan_deposits: bool,
    
    /// Intervalo de escaneo (bloques)
    pub scan_interval_blocks: u32,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        ManagerConfig {
            alert_on_pending_withdrawal: true,
            alert_threshold_blocks: 12, // ~1 hora antes
            auto_scan_deposits: true,
            scan_interval_blocks: 6,
        }
    }
}

/// Alerta de vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultAlert {
    pub vault_id: VaultId,
    pub alert_type: AlertType,
    pub message: String,
    pub created_at: u64,
    pub dismissed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    WithdrawalPending,
    WithdrawalExecutable,
    SuspiciousActivity,
    DepositReceived,
    CancellationExecuted,
}

impl VaultManager {
    /// Crear nuevo manager
    pub fn new() -> Self {
        VaultManager {
            vaults: HashMap::new(),
            current_block: 0,
            address_index: HashMap::new(),
            active_alerts: Vec::new(),
            config: ManagerConfig::default(),
        }
    }
    
    /// Actualizar block height conocido
    pub fn update_block_height(&mut self, height: u64) {
        self.current_block = height;
        self.check_alerts();
    }
    
    /// Crear nuevo vault
    pub fn create_vault(
        &mut self,
        keys: VaultKeys,
        config: VaultConfig,
    ) -> Result<VaultInfo, VaultError> {
        // Validar claves
        keys.validate()
            .map_err(|e| VaultError::InvalidKeys(e.to_string()))?;
        
        // Validar configuración
        config.validate()
            .map_err(|e| VaultError::InvalidConfig(e.to_string()))?;
        
        // Crear script
        let script = VaultScript::new(
            keys.hot_pubkey,
            keys.cold_pubkey,
            config.tier.delay_blocks(),
        );
        
        // Crear ID
        let vault_id = VaultId::from_script(&script.script);
        
        // Verificar que no existe
        if self.vaults.contains_key(&vault_id) {
            return Err(VaultError::Other("Vault already exists".to_string()));
        }
        
        // Crear estado
        let state = VaultState::new(vault_id.clone(), self.current_block);
        
        // Obtener dirección
        let address = script.p2sh_address();
        
        // Guardar vault
        let managed = ManagedVault {
            state,
            config: config.clone(),
            script,
            keys: keys.clone(),
        };
        
        self.address_index.insert(address.clone(), vault_id.clone());
        self.vaults.insert(vault_id.clone(), managed);
        
        // Retornar info
        Ok(VaultInfo {
            id: vault_id,
            name: config.name.clone(),
            address,
            balance: 0,
            status: "Active".to_string(),
            delay_blocks: config.tier.delay_blocks(),
            delay_human: blocks_to_time_estimate(config.tier.delay_blocks()),
            security_tier: config.tier.description(),
            has_pending_withdrawal: false,
            blocks_until_withdrawal: None,
            time_until_withdrawal: None,
            recovery_address: keys.recovery_address,
            created_at: chrono_now(),
        })
    }
    
    /// Obtener vault por ID
    pub fn get_vault(&self, id: &VaultId) -> Option<&ManagedVault> {
        self.vaults.get(id)
    }
    
    /// Obtener vault por dirección
    pub fn get_vault_by_address(&self, address: &str) -> Option<&ManagedVault> {
        self.address_index.get(address)
            .and_then(|id| self.vaults.get(id))
    }
    
    /// Listar todos los vaults
    pub fn list_vaults(&self) -> Vec<VaultInfo> {
        self.vaults.values()
            .map(|v| self.vault_to_info(v))
            .collect()
    }
    
    /// Registrar depósito
    pub fn record_deposit(
        &mut self,
        vault_id: &VaultId,
        txid: String,
        amount: u64,
    ) -> Result<(), VaultError> {
        let vault = self.vaults.get_mut(vault_id)
            .ok_or_else(|| VaultError::NotFound(vault_id.to_string()))?;
        
        vault.state.record_deposit(txid, amount, self.current_block);
        
        // Crear alerta de depósito
        if self.config.alert_on_pending_withdrawal {
            self.active_alerts.push(VaultAlert {
                vault_id: vault_id.clone(),
                alert_type: AlertType::DepositReceived,
                message: format!("Received {} sats", amount),
                created_at: now_timestamp(),
                dismissed: false,
            });
        }
        
        Ok(())
    }
    
    /// Iniciar retiro
    pub fn initiate_withdrawal(
        &mut self,
        vault_id: &VaultId,
        amount: u64,
        destination: String,
    ) -> Result<WithdrawalRequest, VaultError> {
        let vault = self.vaults.get_mut(vault_id)
            .ok_or_else(|| VaultError::NotFound(vault_id.to_string()))?;
        
        // Verificar balance
        if amount > vault.state.balance {
            return Err(VaultError::InsufficientBalance {
                available: vault.state.balance,
                requested: amount,
            });
        }
        
        // Calcular delay efectivo
        let delay = vault.config.effective_delay(amount);
        
        // Estimar fee (simplificado)
        let estimated_fee = 1000; // TODO: usar fee_estimator real
        
        // Iniciar retiro
        let request = vault.state.initiate_withdrawal(
            amount,
            destination,
            self.current_block,
            delay,
            estimated_fee,
        ).map_err(|e| VaultError::Other(e.to_string()))?;
        
        // Crear alerta
        self.active_alerts.push(VaultAlert {
            vault_id: vault_id.clone(),
            alert_type: AlertType::WithdrawalPending,
            message: format!(
                "Withdrawal of {} sats initiated. Executable in {} blocks (~{})",
                amount, delay, blocks_to_time_estimate(delay)
            ),
            created_at: now_timestamp(),
            dismissed: false,
        });
        
        Ok(request)
    }
    
    /// Cancelar retiro
    pub fn cancel_withdrawal(
        &mut self,
        vault_id: &VaultId,
        cold_key_signature: &[u8],
        reason: Option<String>,
    ) -> Result<String, VaultError> {
        let vault = self.vaults.get_mut(vault_id)
            .ok_or_else(|| VaultError::NotFound(vault_id.to_string()))?;
        
        if !vault.state.can_cancel() {
            return Err(VaultError::NoActiveWithdrawal);
        }
        
        // TODO: Verificar firma con cold key
        // Por ahora asumimos que la firma es válida si no está vacía
        if cold_key_signature.is_empty() {
            return Err(VaultError::InvalidSignature("Empty signature".to_string()));
        }
        
        // Generar TXID de recovery (en producción, esto sería la TX real)
        let recovery_txid = format!("recovery_{}", hex::encode(&vault_id.0[..8]));
        let recovery_address = vault.keys.recovery_address.clone();
        
        // Ejecutar cancelación
        vault.state.cancel_withdrawal(
            self.current_block,
            recovery_txid.clone(),
            recovery_address,
            reason.clone(),
        ).map_err(|e| VaultError::Other(e.to_string()))?;
        
        // Crear alerta
        self.active_alerts.push(VaultAlert {
            vault_id: vault_id.clone(),
            alert_type: AlertType::CancellationExecuted,
            message: format!(
                "Withdrawal cancelled. Funds sent to recovery. Reason: {}",
                reason.unwrap_or_else(|| "None specified".to_string())
            ),
            created_at: now_timestamp(),
            dismissed: false,
        });
        
        Ok(recovery_txid)
    }
    
    /// Completar retiro
    pub fn complete_withdrawal(
        &mut self,
        vault_id: &VaultId,
        hot_key_signature: &[u8],
    ) -> Result<String, VaultError> {
        let vault = self.vaults.get_mut(vault_id)
            .ok_or_else(|| VaultError::NotFound(vault_id.to_string()))?;
        
        // Verificar que se puede completar
        if !vault.state.can_complete_withdrawal(self.current_block) {
            if let Some(remaining) = vault.state.blocks_until_withdrawal(self.current_block) {
                return Err(VaultError::DelayNotMet { blocks_remaining: remaining });
            }
            return Err(VaultError::NoActiveWithdrawal);
        }
        
        // TODO: Verificar firma
        if hot_key_signature.is_empty() {
            return Err(VaultError::InvalidSignature("Empty signature".to_string()));
        }
        
        // Generar TXID (en producción, esto sería la TX real)
        let txid = format!("withdrawal_{}", hex::encode(&vault_id.0[..8]));
        
        // Completar
        vault.state.complete_withdrawal(self.current_block, txid.clone())
            .map_err(|e| VaultError::Other(e.to_string()))?;
        
        Ok(txid)
    }
    
    /// Obtener alertas activas
    pub fn get_active_alerts(&self) -> Vec<&VaultAlert> {
        self.active_alerts.iter()
            .filter(|a| !a.dismissed)
            .collect()
    }
    
    /// Descartar alerta
    pub fn dismiss_alert(&mut self, index: usize) {
        if let Some(alert) = self.active_alerts.get_mut(index) {
            alert.dismissed = true;
        }
    }
    
    /// Verificar alertas (llamar periódicamente)
    fn check_alerts(&mut self) {
        for (id, vault) in &self.vaults {
            // Verificar retiros que están por ser ejecutables
            if let Some(ref withdrawal) = vault.state.active_withdrawal {
                let remaining = withdrawal.blocks_remaining(self.current_block);
                
                if remaining == 0 {
                    // Retiro ejecutable
                    let already_alerted = self.active_alerts.iter()
                        .any(|a| a.vault_id == *id && 
                             a.alert_type == AlertType::WithdrawalExecutable &&
                             !a.dismissed);
                    
                    if !already_alerted {
                        self.active_alerts.push(VaultAlert {
                            vault_id: id.clone(),
                            alert_type: AlertType::WithdrawalExecutable,
                            message: "Withdrawal is now executable!".to_string(),
                            created_at: now_timestamp(),
                            dismissed: false,
                        });
                    }
                }
            }
        }
    }
    
    /// Convertir vault a info
    fn vault_to_info(&self, vault: &ManagedVault) -> VaultInfo {
        let remaining = vault.state.blocks_until_withdrawal(self.current_block);
        
        VaultInfo {
            id: vault.state.vault_id.clone(),
            name: vault.config.name.clone(),
            address: vault.script.p2sh_address(),
            balance: vault.state.balance,
            status: vault.state.status.description(),
            delay_blocks: vault.config.tier.delay_blocks(),
            delay_human: blocks_to_time_estimate(vault.config.tier.delay_blocks()),
            security_tier: vault.config.tier.description(),
            has_pending_withdrawal: vault.state.active_withdrawal.is_some(),
            blocks_until_withdrawal: remaining,
            time_until_withdrawal: remaining.map(|b| blocks_to_time_estimate(b as u32)),
            recovery_address: vault.keys.recovery_address.clone(),
            created_at: format_timestamp(vault.state.created_at_time),
        }
    }
    
    /// Serializar manager
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self)
            .map_err(|e| VaultError::SerializationError(e.to_string()))
    }
    
    /// Deserializar manager
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(bytes)
            .map_err(|e| VaultError::SerializationError(e.to_string()))
    }
    
    /// Número de vaults
    pub fn vault_count(&self) -> usize {
        self.vaults.len()
    }
    
    /// Balance total en todos los vaults
    pub fn total_balance(&self) -> u64 {
        self.vaults.values()
            .map(|v| v.state.balance)
            .sum()
    }
}

impl Default for VaultManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_timestamp(ts: u64) -> String {
    // Formato simple ISO-ish
    let secs_per_day = 86400;
    let days_since_epoch = ts / secs_per_day;
    let years = 1970 + days_since_epoch / 365;
    format!("{}-XX-XX", years) // Simplificado
}

fn chrono_now() -> String {
    format_timestamp(now_timestamp())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::config::VaultTier;
    
    fn sample_keys() -> VaultKeys {
        let mut hot = [0u8; 33];
        hot[0] = 0x02;
        hot[1] = 0x01;
        
        let mut cold = [0u8; 33];
        cold[0] = 0x02;
        cold[1] = 0x02;
        
        VaultKeys::new(hot, cold, "MC1recovery123".to_string())
    }
    
    #[test]
    fn test_create_vault() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Standard);
        
        let result = manager.create_vault(keys, config);
        assert!(result.is_ok());
        
        let info = result.unwrap();
        assert!(info.address.starts_with("MV"));
        assert_eq!(info.balance, 0);
        assert_eq!(manager.vault_count(), 1);
    }
    
    #[test]
    fn test_deposit_and_withdraw() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        // Crear vault
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Quick); // 6 bloques
        let info = manager.create_vault(keys, config).unwrap();
        
        // Depositar
        manager.record_deposit(&info.id, "tx1".to_string(), 1_000_000).unwrap();
        
        let updated = manager.get_vault(&info.id).unwrap();
        assert_eq!(updated.state.balance, 1_000_000);
        
        // Iniciar retiro
        let request = manager.initiate_withdrawal(
            &info.id,
            500_000,
            "MC1dest".to_string(),
        ).unwrap();
        
        assert_eq!(request.amount, 500_000);
        
        // Intentar completar antes de tiempo
        let early = manager.complete_withdrawal(&info.id, &[0x30, 0x44]);
        assert!(early.is_err());
        
        // Avanzar bloques
        manager.update_block_height(1000 + 6);
        
        // Completar retiro
        let result = manager.complete_withdrawal(&info.id, &[0x30, 0x44]);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_cancel_withdrawal() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Standard);
        let info = manager.create_vault(keys, config).unwrap();
        
        manager.record_deposit(&info.id, "tx1".to_string(), 1_000_000).unwrap();
        manager.initiate_withdrawal(&info.id, 500_000, "MC1dest".to_string()).unwrap();
        
        // Cancelar con cold key
        let result = manager.cancel_withdrawal(
            &info.id,
            &[0x30, 0x44], // Firma dummy
            Some("Suspicious activity detected".to_string()),
        );
        
        assert!(result.is_ok());
        
        let vault = manager.get_vault(&info.id).unwrap();
        assert!(vault.state.status.is_cancelled());
    }
    
    #[test]
    fn test_insufficient_balance() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Standard);
        let info = manager.create_vault(keys, config).unwrap();
        
        manager.record_deposit(&info.id, "tx1".to_string(), 1_000_000).unwrap();
        
        // Intentar retirar más de lo disponible
        let result = manager.initiate_withdrawal(
            &info.id,
            2_000_000,
            "MC1dest".to_string(),
        );
        
        assert!(matches!(result, Err(VaultError::InsufficientBalance { .. })));
    }
    
    #[test]
    fn test_alerts() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Quick);
        let info = manager.create_vault(keys, config).unwrap();
        
        manager.record_deposit(&info.id, "tx1".to_string(), 1_000_000).unwrap();
        
        // Debe haber alerta de depósito
        let alerts = manager.get_active_alerts();
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.alert_type == AlertType::DepositReceived));
    }
    
    #[test]
    fn test_serialization() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        let keys = sample_keys();
        let config = VaultConfig::new(VaultTier::Standard);
        manager.create_vault(keys, config).unwrap();
        
        // Serializar
        let bytes = manager.to_bytes().unwrap();
        
        // Deserializar
        let restored = VaultManager::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.vault_count(), 1);
        assert_eq!(restored.current_block, 1000);
    }
    
    #[test]
    fn test_list_vaults() {
        let mut manager = VaultManager::new();
        manager.update_block_height(1000);
        
        // Crear múltiples vaults
        for i in 0..3 {
            let mut keys = sample_keys();
            keys.hot_pubkey[2] = i;
            keys.cold_pubkey[2] = i + 10;
            
            let config = VaultConfig::new(VaultTier::Standard)
                .with_name(&format!("Vault {}", i));
            
            manager.create_vault(keys, config).unwrap();
        }
        
        let list = manager.list_vaults();
        assert_eq!(list.len(), 3);
    }
}
