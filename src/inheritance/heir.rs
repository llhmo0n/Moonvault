// =============================================================================
// MOONCOIN - Herencia Digital: Herederos
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashSet;

use super::{InheritanceError, MAX_HEIRS};

// =============================================================================
// Heir Share (Porcentaje)
// =============================================================================

/// Porcentaje de herencia (0-100)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeirShare(pub u32);

impl HeirShare {
    /// Crear nuevo porcentaje
    pub fn new(percent: u32) -> Result<Self, InheritanceError> {
        if percent == 0 || percent > 100 {
            return Err(InheritanceError::InvalidShares { total: percent });
        }
        Ok(HeirShare(percent))
    }
    
    /// Obtener porcentaje
    pub fn percent(&self) -> u32 {
        self.0
    }
    
    /// Calcular monto dado un balance total
    pub fn calculate_amount(&self, total_balance: u64) -> u64 {
        (total_balance * self.0 as u64) / 100
    }
}

impl std::fmt::Display for HeirShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%", self.0)
    }
}

// =============================================================================
// Heir (Heredero)
// =============================================================================

/// Un heredero es una dirección que recibirá fondos
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Heir {
    /// Nombre o alias del heredero
    pub name: Option<String>,
    
    /// Dirección de destino
    pub address: String,
    
    /// Porcentaje de la herencia
    pub share: HeirShare,
    
    /// Notas (ej: "Mi hijo Juan")
    pub notes: Option<String>,
    
    /// Fecha de agregación
    pub added_at: u64,
}

impl Heir {
    /// Crear nuevo heredero
    pub fn new(address: String, share: HeirShare) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Heir {
            name: None,
            address,
            share,
            notes: None,
            added_at: now,
        }
    }
    
    /// Crear heredero con nombre
    pub fn with_name(address: String, share: HeirShare, name: &str) -> Self {
        let mut heir = Self::new(address, share);
        heir.name = Some(name.to_string());
        heir
    }
    
    /// Calcular monto a recibir
    pub fn calculate_inheritance(&self, total_balance: u64) -> u64 {
        self.share.calculate_amount(total_balance)
    }
    
    /// Descripción legible
    pub fn description(&self) -> String {
        match &self.name {
            Some(n) => format!("{} ({}) - {}", n, &self.address[..12.min(self.address.len())], self.share),
            None => format!("{} - {}", &self.address[..12.min(self.address.len())], self.share),
        }
    }
}

// =============================================================================
// Heir Set (Conjunto de Herederos)
// =============================================================================

/// Conjunto de herederos con validación
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeirSet {
    /// Lista de herederos
    pub heirs: Vec<Heir>,
    
    /// Fecha de creación
    pub created_at: u64,
    
    /// Última modificación
    pub modified_at: u64,
}

impl HeirSet {
    /// Crear nuevo set de herederos
    pub fn new(heirs: Vec<Heir>) -> Result<Self, InheritanceError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Validar cantidad
        if heirs.is_empty() {
            return Err(InheritanceError::NoHeirs);
        }
        
        if heirs.len() > MAX_HEIRS {
            return Err(InheritanceError::TooManyHeirs { 
                have: heirs.len(), 
                max: MAX_HEIRS 
            });
        }
        
        // Validar que porcentajes sumen 100%
        let total: u32 = heirs.iter().map(|h| h.share.0).sum();
        if total != 100 {
            return Err(InheritanceError::InvalidShares { total });
        }
        
        // Verificar duplicados
        let mut seen = HashSet::new();
        for h in &heirs {
            if !seen.insert(h.address.clone()) {
                return Err(InheritanceError::DuplicateHeir(h.address.clone()));
            }
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(HeirSet {
            heirs,
            created_at: now,
            modified_at: now,
        })
    }
    
    /// Crear set con un solo heredero (100%)
    pub fn single(address: String) -> Result<Self, InheritanceError> {
        let heir = Heir::new(address, HeirShare::new(100)?);
        Self::new(vec![heir])
    }
    
    /// Crear set con dos herederos (50/50)
    pub fn equal_split(addr1: String, addr2: String) -> Result<Self, InheritanceError> {
        let heirs = vec![
            Heir::new(addr1, HeirShare::new(50)?),
            Heir::new(addr2, HeirShare::new(50)?),
        ];
        Self::new(heirs)
    }
    
    /// Número de herederos
    pub fn count(&self) -> usize {
        self.heirs.len()
    }
    
    /// Calcular distribución dado un balance
    pub fn calculate_distribution(&self, total_balance: u64) -> Vec<(String, u64)> {
        self.heirs.iter()
            .map(|h| (h.address.clone(), h.calculate_inheritance(total_balance)))
            .collect()
    }
    
    /// Obtener heredero por dirección
    pub fn get_by_address(&self, address: &str) -> Option<&Heir> {
        self.heirs.iter().find(|h| h.address == address)
    }
    
    /// Verificar si una dirección es heredero
    pub fn is_heir(&self, address: &str) -> bool {
        self.heirs.iter().any(|h| h.address == address)
    }
    
    /// Descripción del set
    pub fn description(&self) -> String {
        if self.heirs.len() == 1 {
            format!("1 heredero: {}", self.heirs[0].description())
        } else {
            format!("{} herederos", self.heirs.len())
        }
    }
    
    /// Lista de direcciones
    pub fn addresses(&self) -> Vec<&str> {
        self.heirs.iter().map(|h| h.address.as_str()).collect()
    }
}

// =============================================================================
// Presets Comunes
// =============================================================================

impl HeirSet {
    /// Preset: Esposo/a único heredero
    pub fn spouse(address: String) -> Result<Self, InheritanceError> {
        let heir = Heir::with_name(address, HeirShare::new(100)?, "Spouse");
        Self::new(vec![heir])
    }
    
    /// Preset: Hijos partes iguales
    pub fn children_equal(addresses: Vec<String>) -> Result<Self, InheritanceError> {
        if addresses.is_empty() {
            return Err(InheritanceError::NoHeirs);
        }
        
        let share_each = 100 / addresses.len() as u32;
        let mut remainder = 100 % addresses.len() as u32;
        
        let mut heirs = Vec::new();
        for (i, addr) in addresses.into_iter().enumerate() {
            // El primer heredero recibe el resto
            let extra = if i == 0 { remainder } else { 0 };
            remainder = 0;
            
            let share = HeirShare::new(share_each + extra)?;
            let heir = Heir::with_name(addr, share, &format!("Child {}", i + 1));
            heirs.push(heir);
        }
        
        Self::new(heirs)
    }
    
    /// Preset: Esposo/a 50%, hijos dividen el resto
    pub fn spouse_and_children(spouse_addr: String, children_addrs: Vec<String>) -> Result<Self, InheritanceError> {
        if children_addrs.is_empty() {
            return Self::spouse(spouse_addr);
        }
        
        let mut heirs = vec![
            Heir::with_name(spouse_addr, HeirShare::new(50)?, "Spouse")
        ];
        
        let children_share = 50 / children_addrs.len() as u32;
        let mut remainder = 50 % children_addrs.len() as u32;
        
        for (i, addr) in children_addrs.into_iter().enumerate() {
            let extra = if i == 0 { remainder } else { 0 };
            remainder = 0;
            
            let share = HeirShare::new(children_share + extra)?;
            let heir = Heir::with_name(addr, share, &format!("Child {}", i + 1));
            heirs.push(heir);
        }
        
        Self::new(heirs)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_heir_share() {
        let share = HeirShare::new(50).unwrap();
        assert_eq!(share.percent(), 50);
        assert_eq!(share.calculate_amount(1000), 500);
        
        // 0% inválido
        assert!(HeirShare::new(0).is_err());
        
        // >100% inválido
        assert!(HeirShare::new(101).is_err());
    }
    
    #[test]
    fn test_heir_creation() {
        let heir = Heir::new("MC1addr123".to_string(), HeirShare::new(100).unwrap());
        assert!(heir.name.is_none());
        assert_eq!(heir.calculate_inheritance(1000), 1000);
        
        let heir2 = Heir::with_name("MC1addr456".to_string(), HeirShare::new(50).unwrap(), "John");
        assert_eq!(heir2.name, Some("John".to_string()));
    }
    
    #[test]
    fn test_heir_set_single() {
        let set = HeirSet::single("MC1addr".to_string()).unwrap();
        assert_eq!(set.count(), 1);
        assert!(set.is_heir("MC1addr"));
    }
    
    #[test]
    fn test_heir_set_equal_split() {
        let set = HeirSet::equal_split(
            "MC1addr1".to_string(),
            "MC1addr2".to_string(),
        ).unwrap();
        
        assert_eq!(set.count(), 2);
        
        let dist = set.calculate_distribution(1000);
        assert_eq!(dist[0].1, 500);
        assert_eq!(dist[1].1, 500);
    }
    
    #[test]
    fn test_heir_set_validation() {
        // Porcentajes no suman 100%
        let heirs = vec![
            Heir::new("MC1a".to_string(), HeirShare::new(30).unwrap()),
            Heir::new("MC1b".to_string(), HeirShare::new(30).unwrap()),
        ];
        assert!(HeirSet::new(heirs).is_err());
        
        // Duplicados
        let heirs = vec![
            Heir::new("MC1same".to_string(), HeirShare::new(50).unwrap()),
            Heir::new("MC1same".to_string(), HeirShare::new(50).unwrap()),
        ];
        assert!(HeirSet::new(heirs).is_err());
    }
    
    #[test]
    fn test_children_equal() {
        let set = HeirSet::children_equal(vec![
            "MC1child1".to_string(),
            "MC1child2".to_string(),
            "MC1child3".to_string(),
        ]).unwrap();
        
        assert_eq!(set.count(), 3);
        
        // 100/3 = 33 con resto 1, primer hijo recibe 34%
        let dist = set.calculate_distribution(100);
        assert_eq!(dist[0].1, 34);
        assert_eq!(dist[1].1, 33);
        assert_eq!(dist[2].1, 33);
    }
    
    #[test]
    fn test_spouse_and_children() {
        let set = HeirSet::spouse_and_children(
            "MC1spouse".to_string(),
            vec!["MC1child1".to_string(), "MC1child2".to_string()],
        ).unwrap();
        
        assert_eq!(set.count(), 3);
        
        let dist = set.calculate_distribution(100);
        assert_eq!(dist[0].1, 50); // Spouse
        assert_eq!(dist[1].1, 25); // Child 1
        assert_eq!(dist[2].1, 25); // Child 2
    }
    
    #[test]
    fn test_distribution() {
        let set = HeirSet::new(vec![
            Heir::new("MC1a".to_string(), HeirShare::new(60).unwrap()),
            Heir::new("MC1b".to_string(), HeirShare::new(30).unwrap()),
            Heir::new("MC1c".to_string(), HeirShare::new(10).unwrap()),
        ]).unwrap();
        
        let dist = set.calculate_distribution(1_000_000);
        
        assert_eq!(dist[0], ("MC1a".to_string(), 600_000));
        assert_eq!(dist[1], ("MC1b".to_string(), 300_000));
        assert_eq!(dist[2], ("MC1c".to_string(), 100_000));
    }
}
