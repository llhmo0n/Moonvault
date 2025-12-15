// =============================================================================
// MOONCOIN - Recovery Social: Guardians
// =============================================================================
//
// Gestión de los guardianes (contactos de confianza) para recovery.
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// =============================================================================
// Serde helpers
// =============================================================================

mod serde_pubkey33 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where D: Deserializer<'de> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom("Expected 33 bytes"));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// =============================================================================
// Guardian
// =============================================================================

/// Un guardián es un contacto de confianza que puede participar en recovery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Guardian {
    /// Nombre o alias del guardián
    pub name: String,
    
    /// Clave pública del guardián (comprimida, 33 bytes)
    #[serde(with = "serde_pubkey33")]
    pub pubkey: [u8; 33],
    
    /// Email para notificaciones (opcional)
    pub email: Option<String>,
    
    /// Teléfono para notificaciones (opcional)
    pub phone: Option<String>,
    
    /// Notas adicionales
    pub notes: Option<String>,
    
    /// Fecha de agregación (timestamp)
    pub added_at: u64,
    
    /// Estado del guardián
    pub status: GuardianStatus,
    
    /// Último contacto exitoso (timestamp)
    pub last_contact: Option<u64>,
}

/// Estado de un guardián
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianStatus {
    /// Activo y disponible
    Active,
    
    /// Pendiente de confirmación
    Pending,
    
    /// Temporalmente no disponible
    Unavailable,
    
    /// Removido del círculo
    Removed,
}

impl Guardian {
    /// Crear nuevo guardián
    pub fn new(name: String, pubkey: [u8; 33]) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Guardian {
            name,
            pubkey,
            email: None,
            phone: None,
            notes: None,
            added_at: now,
            status: GuardianStatus::Active,
            last_contact: None,
        }
    }
    
    /// Crear guardián con información de contacto
    pub fn with_contact(name: String, pubkey: [u8; 33], email: Option<String>, phone: Option<String>) -> Self {
        let mut g = Self::new(name, pubkey);
        g.email = email;
        g.phone = phone;
        g
    }
    
    /// Verificar si el guardián está activo
    pub fn is_active(&self) -> bool {
        self.status == GuardianStatus::Active
    }
    
    /// Obtener identificador corto
    pub fn short_id(&self) -> String {
        hex::encode(&self.pubkey[1..5])
    }
    
    /// Hash de la clave pública (para scripts)
    pub fn pubkey_hash(&self) -> [u8; 20] {
        use sha2::{Sha256, Digest as Sha2Digest};
        use ripemd::{Ripemd160, Digest as RipemdDigest};
        
        let sha = Sha256::digest(&self.pubkey);
        let ripemd = Ripemd160::digest(&sha);
        
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&ripemd);
        hash
    }
    
    /// Marcar como contactado
    pub fn mark_contacted(&mut self) {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        self.last_contact = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
    }
}

// =============================================================================
// Guardian Set
// =============================================================================

/// Conjunto de guardianes con threshold
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSet {
    /// Lista de guardianes
    pub guardians: Vec<Guardian>,
    
    /// Número mínimo de firmas requeridas
    pub threshold: usize,
    
    /// Fecha de creación
    pub created_at: u64,
    
    /// Última modificación
    pub modified_at: u64,
}

impl GuardianSet {
    /// Crear nuevo set de guardianes
    pub fn new(guardians: Vec<Guardian>, threshold: usize) -> Result<Self, super::RecoveryError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Validar
        super::validate_threshold(threshold, guardians.len())?;
        
        // Verificar duplicados
        let mut seen = std::collections::HashSet::new();
        for g in &guardians {
            let key = hex::encode(&g.pubkey);
            if !seen.insert(key.clone()) {
                return Err(super::RecoveryError::DuplicateGuardian(g.name.clone()));
            }
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(GuardianSet {
            guardians,
            threshold,
            created_at: now,
            modified_at: now,
        })
    }
    
    /// Número de guardianes activos
    pub fn active_count(&self) -> usize {
        self.guardians.iter().filter(|g| g.is_active()).count()
    }
    
    /// Verificar si hay suficientes guardianes activos
    pub fn has_quorum(&self) -> bool {
        self.active_count() >= self.threshold
    }
    
    /// Obtener guardianes activos
    pub fn active_guardians(&self) -> Vec<&Guardian> {
        self.guardians.iter().filter(|g| g.is_active()).collect()
    }
    
    /// Obtener guardián por pubkey
    pub fn get_by_pubkey(&self, pubkey: &[u8; 33]) -> Option<&Guardian> {
        self.guardians.iter().find(|g| &g.pubkey == pubkey)
    }
    
    /// Obtener guardián por nombre
    pub fn get_by_name(&self, name: &str) -> Option<&Guardian> {
        self.guardians.iter().find(|g| g.name == name)
    }
    
    /// Agregar guardián
    pub fn add_guardian(&mut self, guardian: Guardian) -> Result<(), super::RecoveryError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Verificar límite
        if self.guardians.len() >= super::MAX_GUARDIANS {
            return Err(super::RecoveryError::TooManyGuardians { 
                have: self.guardians.len() + 1, 
                max: super::MAX_GUARDIANS 
            });
        }
        
        // Verificar duplicado
        let key = hex::encode(&guardian.pubkey);
        for g in &self.guardians {
            if hex::encode(&g.pubkey) == key {
                return Err(super::RecoveryError::DuplicateGuardian(guardian.name.clone()));
            }
        }
        
        self.guardians.push(guardian);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// Remover guardián
    pub fn remove_guardian(&mut self, pubkey: &[u8; 33]) -> Result<(), super::RecoveryError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let initial_len = self.guardians.len();
        self.guardians.retain(|g| &g.pubkey != pubkey);
        
        if self.guardians.len() == initial_len {
            return Err(super::RecoveryError::Other("Guardian not found".to_string()));
        }
        
        // Verificar que aún hay quorum posible
        if self.guardians.len() < self.threshold {
            return Err(super::RecoveryError::NotEnoughGuardians { 
                have: self.guardians.len(), 
                need: self.threshold 
            });
        }
        
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// Obtener claves públicas ordenadas (para script multisig)
    pub fn sorted_pubkeys(&self) -> Vec<[u8; 33]> {
        let mut pubkeys: Vec<[u8; 33]> = self.guardians
            .iter()
            .filter(|g| g.is_active())
            .map(|g| g.pubkey)
            .collect();
        
        pubkeys.sort();
        pubkeys
    }
    
    /// Descripción del set (ej: "3-of-5")
    pub fn description(&self) -> String {
        format!("{}-of-{}", self.threshold, self.guardians.len())
    }
}

// =============================================================================
// Guardian Signature (para recovery)
// =============================================================================

/// Firma de un guardián durante el proceso de recovery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSignature {
    /// Clave pública del guardián que firma
    #[serde(with = "serde_pubkey33")]
    pub guardian_pubkey: [u8; 33],
    
    /// Firma DER
    pub signature: Vec<u8>,
    
    /// Timestamp de la firma
    pub signed_at: u64,
    
    /// Mensaje firmado (hash)
    pub message_hash: Vec<u8>,
}

impl GuardianSignature {
    pub fn new(guardian_pubkey: [u8; 33], signature: Vec<u8>, message_hash: Vec<u8>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        GuardianSignature {
            guardian_pubkey,
            signature,
            signed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            message_hash,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn sample_guardian(seed: u8) -> Guardian {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[1] = seed;
        Guardian::new(format!("Guardian {}", seed), pubkey)
    }
    
    #[test]
    fn test_guardian_creation() {
        let g = sample_guardian(1);
        
        assert_eq!(g.name, "Guardian 1");
        assert!(g.is_active());
        assert!(!g.short_id().is_empty());
    }
    
    #[test]
    fn test_guardian_pubkey_hash() {
        let g = sample_guardian(1);
        let hash = g.pubkey_hash();
        
        assert_eq!(hash.len(), 20);
    }
    
    #[test]
    fn test_guardian_set_creation() {
        let guardians = vec![
            sample_guardian(1),
            sample_guardian(2),
            sample_guardian(3),
            sample_guardian(4),
            sample_guardian(5),
        ];
        
        let set = GuardianSet::new(guardians, 3).unwrap();
        
        assert_eq!(set.guardians.len(), 5);
        assert_eq!(set.threshold, 3);
        assert!(set.has_quorum());
        assert_eq!(set.description(), "3-of-5");
    }
    
    #[test]
    fn test_guardian_set_invalid_threshold() {
        let guardians = vec![
            sample_guardian(1),
            sample_guardian(2),
            sample_guardian(3),
        ];
        
        // 1-of-3 es inválido (menos de la mitad)
        let result = GuardianSet::new(guardians, 1);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_guardian_set_duplicate() {
        let g = sample_guardian(1);
        let guardians = vec![g.clone(), g.clone()];
        
        let result = GuardianSet::new(guardians, 2);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_add_remove_guardian() {
        let guardians = vec![
            sample_guardian(1),
            sample_guardian(2),
            sample_guardian(3),
        ];
        
        let mut set = GuardianSet::new(guardians, 2).unwrap();
        
        // Agregar
        set.add_guardian(sample_guardian(4)).unwrap();
        assert_eq!(set.guardians.len(), 4);
        
        // Remover
        let pubkey = sample_guardian(4).pubkey;
        set.remove_guardian(&pubkey).unwrap();
        assert_eq!(set.guardians.len(), 3);
    }
    
    #[test]
    fn test_sorted_pubkeys() {
        let guardians = vec![
            sample_guardian(5),
            sample_guardian(1),
            sample_guardian(3),
        ];
        
        let set = GuardianSet::new(guardians, 2).unwrap();
        let sorted = set.sorted_pubkeys();
        
        // Deben estar ordenados
        assert!(sorted[0] < sorted[1]);
        assert!(sorted[1] < sorted[2]);
    }
    
    #[test]
    fn test_get_guardian() {
        let g1 = sample_guardian(1);
        let pubkey = g1.pubkey;
        
        let guardians = vec![g1, sample_guardian(2), sample_guardian(3)];
        let set = GuardianSet::new(guardians, 2).unwrap();
        
        assert!(set.get_by_pubkey(&pubkey).is_some());
        assert!(set.get_by_name("Guardian 1").is_some());
        assert!(set.get_by_name("Unknown").is_none());
    }
}
