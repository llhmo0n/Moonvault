// =============================================================================
// MOONCOIN v2.0 - Address Labels
// =============================================================================
//
// Sistema de etiquetas para organizar direcciones:
// - Etiquetar direcciones propias (ej: "Ahorros", "Trading")
// - Etiquetar direcciones de contactos (ej: "Juan", "Tienda")
// - Categorías y notas
// - Búsqueda por etiqueta
// - Exportar/importar labels
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// =============================================================================
// Constants
// =============================================================================

const LABELS_FILE: &str = "address_labels.json";

// =============================================================================
// Label Entry
// =============================================================================

/// Entrada de etiqueta para una dirección
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressLabel {
    /// Dirección
    pub address: String,
    /// Etiqueta/nombre
    pub label: String,
    /// Categoría (opcional)
    pub category: Option<String>,
    /// Notas adicionales (opcional)
    pub notes: Option<String>,
    /// Es dirección propia (de nuestro wallet)
    pub is_mine: bool,
    /// Fecha de creación
    pub created_at: u64,
    /// Última modificación
    pub updated_at: u64,
    /// Color para UI (opcional)
    pub color: Option<String>,
}

impl AddressLabel {
    /// Crea una nueva etiqueta
    pub fn new(address: &str, label: &str, is_mine: bool) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        AddressLabel {
            address: address.to_string(),
            label: label.to_string(),
            category: None,
            notes: None,
            is_mine,
            created_at: now,
            updated_at: now,
            color: None,
        }
    }
    
    /// Con categoría
    pub fn with_category(mut self, category: &str) -> Self {
        self.category = Some(category.to_string());
        self
    }
    
    /// Con notas
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }
    
    /// Con color
    pub fn with_color(mut self, color: &str) -> Self {
        self.color = Some(color.to_string());
        self
    }
}

// =============================================================================
// Categorías predefinidas
// =============================================================================

/// Categorías comunes
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Category {
    /// Direcciones propias para ahorros
    Savings,
    /// Direcciones para trading
    Trading,
    /// Direcciones para gastos diarios
    Spending,
    /// Direcciones de exchanges
    Exchange,
    /// Direcciones de amigos/familia
    Friends,
    /// Direcciones de negocios
    Business,
    /// Direcciones de donaciones
    Donations,
    /// Sin categoría
    None,
    /// Categoría personalizada
    Custom(String),
}

impl Category {
    pub fn to_string(&self) -> String {
        match self {
            Category::Savings => "savings".to_string(),
            Category::Trading => "trading".to_string(),
            Category::Spending => "spending".to_string(),
            Category::Exchange => "exchange".to_string(),
            Category::Friends => "friends".to_string(),
            Category::Business => "business".to_string(),
            Category::Donations => "donations".to_string(),
            Category::None => "none".to_string(),
            Category::Custom(s) => s.clone(),
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "savings" => Category::Savings,
            "trading" => Category::Trading,
            "spending" => Category::Spending,
            "exchange" => Category::Exchange,
            "friends" => Category::Friends,
            "business" => Category::Business,
            "donations" => Category::Donations,
            "none" | "" => Category::None,
            other => Category::Custom(other.to_string()),
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            Category::Savings => "💰",
            Category::Trading => "📈",
            Category::Spending => "🛒",
            Category::Exchange => "🏦",
            Category::Friends => "👥",
            Category::Business => "💼",
            Category::Donations => "🎁",
            Category::None => "📋",
            Category::Custom(_) => "🏷️",
        }
    }
}

// =============================================================================
// Label Manager
// =============================================================================

/// Gestor de etiquetas
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LabelManager {
    /// Etiquetas por dirección
    pub labels: HashMap<String, AddressLabel>,
}

impl LabelManager {
    /// Crea un nuevo gestor
    pub fn new() -> Self {
        LabelManager {
            labels: HashMap::new(),
        }
    }
    
    /// Añade o actualiza una etiqueta
    pub fn set_label(&mut self, address: &str, label: &str, is_mine: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(existing) = self.labels.get_mut(address) {
            existing.label = label.to_string();
            existing.updated_at = now;
        } else {
            self.labels.insert(
                address.to_string(),
                AddressLabel::new(address, label, is_mine)
            );
        }
    }
    
    /// Establece la categoría
    pub fn set_category(&mut self, address: &str, category: &str) -> Result<(), String> {
        if let Some(entry) = self.labels.get_mut(address) {
            entry.category = if category.is_empty() { None } else { Some(category.to_string()) };
            entry.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Ok(())
        } else {
            Err("Address not found".to_string())
        }
    }
    
    /// Establece notas
    pub fn set_notes(&mut self, address: &str, notes: &str) -> Result<(), String> {
        if let Some(entry) = self.labels.get_mut(address) {
            entry.notes = if notes.is_empty() { None } else { Some(notes.to_string()) };
            entry.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Ok(())
        } else {
            Err("Address not found".to_string())
        }
    }
    
    /// Obtiene la etiqueta de una dirección
    pub fn get_label(&self, address: &str) -> Option<&AddressLabel> {
        self.labels.get(address)
    }
    
    /// Obtiene solo el nombre de la etiqueta
    pub fn get_label_name(&self, address: &str) -> Option<&str> {
        self.labels.get(address).map(|l| l.label.as_str())
    }
    
    /// Elimina una etiqueta
    pub fn remove_label(&mut self, address: &str) -> Option<AddressLabel> {
        self.labels.remove(address)
    }
    
    /// Busca direcciones por etiqueta
    pub fn search_by_label(&self, query: &str) -> Vec<&AddressLabel> {
        let query_lower = query.to_lowercase();
        self.labels.values()
            .filter(|l| l.label.to_lowercase().contains(&query_lower))
            .collect()
    }
    
    /// Busca direcciones por categoría
    pub fn search_by_category(&self, category: &str) -> Vec<&AddressLabel> {
        let cat_lower = category.to_lowercase();
        self.labels.values()
            .filter(|l| {
                l.category.as_ref()
                    .map(|c| c.to_lowercase() == cat_lower)
                    .unwrap_or(false)
            })
            .collect()
    }
    
    /// Obtiene todas las direcciones propias
    pub fn get_my_addresses(&self) -> Vec<&AddressLabel> {
        self.labels.values()
            .filter(|l| l.is_mine)
            .collect()
    }
    
    /// Obtiene direcciones de contactos
    pub fn get_contacts(&self) -> Vec<&AddressLabel> {
        self.labels.values()
            .filter(|l| !l.is_mine)
            .collect()
    }
    
    /// Lista todas las categorías usadas
    pub fn list_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self.labels.values()
            .filter_map(|l| l.category.clone())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
    
    /// Número total de etiquetas
    pub fn count(&self) -> usize {
        self.labels.len()
    }
    
    /// Guarda las etiquetas
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(LABELS_FILE, json)
            .map_err(|e| format!("Write error: {}", e))
    }
    
    /// Carga las etiquetas
    pub fn load() -> Result<Self, String> {
        if !Path::new(LABELS_FILE).exists() {
            return Ok(LabelManager::new());
        }
        
        let json = fs::read_to_string(LABELS_FILE)
            .map_err(|e| format!("Read error: {}", e))?;
        
        serde_json::from_str(&json)
            .map_err(|e| format!("Parse error: {}", e))
    }
    
    /// Exporta a CSV
    pub fn export_csv(&self) -> String {
        let mut csv = String::from("address,label,category,is_mine,notes\n");
        
        for label in self.labels.values() {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                label.address,
                label.label.replace(',', ";"),
                label.category.as_deref().unwrap_or(""),
                if label.is_mine { "yes" } else { "no" },
                label.notes.as_deref().unwrap_or("").replace(',', ";")
            ));
        }
        
        csv
    }
    
    /// Importa desde CSV
    pub fn import_csv(&mut self, csv: &str) -> Result<usize, String> {
        let mut count = 0;
        
        for (i, line) in csv.lines().enumerate() {
            // Saltar header
            if i == 0 && line.to_lowercase().contains("address") {
                continue;
            }
            
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let address = parts[0].trim();
                let label = parts[1].trim();
                let category = parts.get(2).map(|s| s.trim()).unwrap_or("");
                let is_mine = parts.get(3).map(|s| s.trim().to_lowercase() == "yes").unwrap_or(false);
                let notes = parts.get(4).map(|s| s.trim()).unwrap_or("");
                
                let mut entry = AddressLabel::new(address, label, is_mine);
                if !category.is_empty() {
                    entry = entry.with_category(category);
                }
                if !notes.is_empty() {
                    entry = entry.with_notes(notes);
                }
                
                self.labels.insert(address.to_string(), entry);
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    /// Formatea una dirección con su etiqueta
    pub fn format_address(&self, address: &str) -> String {
        if let Some(label) = self.get_label(address) {
            let cat_emoji = label.category.as_ref()
                .map(|c| Category::from_str(c).emoji())
                .unwrap_or("");
            format!("{} {} ({}...)", cat_emoji, label.label, &address[..8.min(address.len())])
        } else {
            format!("{}...", &address[..16.min(address.len())])
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
    fn test_label_manager() {
        let mut manager = LabelManager::new();
        
        manager.set_label("MCtest123", "My Savings", true);
        manager.set_label("MCother456", "Juan", false);
        
        assert_eq!(manager.count(), 2);
        assert_eq!(manager.get_label_name("MCtest123"), Some("My Savings"));
        
        let mine = manager.get_my_addresses();
        assert_eq!(mine.len(), 1);
        
        let contacts = manager.get_contacts();
        assert_eq!(contacts.len(), 1);
    }
    
    #[test]
    fn test_search() {
        let mut manager = LabelManager::new();
        
        manager.set_label("MC1", "Savings Account", true);
        manager.set_label("MC2", "Trading Fund", true);
        manager.set_label("MC3", "Emergency Savings", true);
        
        let results = manager.search_by_label("savings");
        assert_eq!(results.len(), 2);
    }
    
    #[test]
    fn test_category() {
        let mut manager = LabelManager::new();
        
        manager.set_label("MC1", "Test", true);
        manager.set_category("MC1", "savings").unwrap();
        
        let results = manager.search_by_category("savings");
        assert_eq!(results.len(), 1);
    }
    
    #[test]
    fn test_csv_export_import() {
        let mut manager = LabelManager::new();
        manager.set_label("MC1", "Test Label", true);
        
        let csv = manager.export_csv();
        assert!(csv.contains("MC1"));
        assert!(csv.contains("Test Label"));
        
        let mut new_manager = LabelManager::new();
        let count = new_manager.import_csv(&csv).unwrap();
        assert_eq!(count, 1);
    }
}
