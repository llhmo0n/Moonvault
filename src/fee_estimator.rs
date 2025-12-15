// =============================================================================
// MOONCOIN v2.0 - Fee Estimator
// =============================================================================
//
// Estimación inteligente de fees basada en:
// - Historial de bloques recientes
// - Tamaño de transacciones
// - Congestión del mempool
// - Prioridad deseada (rápido/normal/económico)
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::VecDeque;

use crate::block::Block;
use crate::transaction::Tx;
use crate::mempool::Mempool;

// =============================================================================
// Constants
// =============================================================================

/// Número de bloques a analizar para estimación
const BLOCKS_TO_ANALYZE: usize = 6;

/// Fee mínimo absoluto (satoshis por byte)
const MIN_FEE_RATE: u64 = 1;

/// Fee máximo razonable (satoshis por byte)
const MAX_FEE_RATE: u64 = 1000;

/// Tamaño típico de una transacción P2PKH (bytes)
pub const TYPICAL_TX_SIZE: usize = 225;

/// Tamaño típico de una transacción SegWit P2WPKH (vbytes)
pub const TYPICAL_SEGWIT_TX_SIZE: usize = 141;

// =============================================================================
// Fee Priority
// =============================================================================

/// Prioridad de confirmación
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeePriority {
    /// Confirmación en 1-2 bloques (~10 min)
    High,
    /// Confirmación en 3-6 bloques (~30 min)
    Medium,
    /// Confirmación en 6+ bloques (~1 hora)
    Low,
    /// El mínimo posible (puede tardar mucho)
    Minimum,
}

impl FeePriority {
    /// Multiplicador de fee según prioridad
    pub fn multiplier(&self) -> f64 {
        match self {
            FeePriority::High => 2.0,
            FeePriority::Medium => 1.0,
            FeePriority::Low => 0.5,
            FeePriority::Minimum => 0.25,
        }
    }
    
    /// Bloques objetivo para confirmación
    pub fn target_blocks(&self) -> usize {
        match self {
            FeePriority::High => 1,
            FeePriority::Medium => 3,
            FeePriority::Low => 6,
            FeePriority::Minimum => 20,
        }
    }
    
    /// Descripción de la prioridad
    pub fn description(&self) -> &'static str {
        match self {
            FeePriority::High => "Fast (~10 min)",
            FeePriority::Medium => "Normal (~30 min)",
            FeePriority::Low => "Economy (~1 hour)",
            FeePriority::Minimum => "Minimum (slow)",
        }
    }
}

// =============================================================================
// Block Fee Stats
// =============================================================================

/// Estadísticas de fees de un bloque
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockFeeStats {
    /// Altura del bloque
    pub height: u64,
    /// Número de transacciones
    pub tx_count: usize,
    /// Fee total del bloque (satoshis)
    pub total_fees: u64,
    /// Fee rate mínimo (sat/byte)
    pub min_fee_rate: u64,
    /// Fee rate máximo (sat/byte)
    pub max_fee_rate: u64,
    /// Fee rate promedio (sat/byte)
    pub avg_fee_rate: u64,
    /// Fee rate mediano (sat/byte)
    pub median_fee_rate: u64,
    /// Tamaño total del bloque (bytes)
    pub block_size: usize,
    /// Porcentaje de uso del bloque
    pub fill_percentage: f64,
}

impl BlockFeeStats {
    /// Calcula estadísticas de un bloque
    pub fn from_block(block: &Block, utxo_values: &dyn Fn(&str, u32) -> Option<u64>) -> Self {
        let mut fee_rates: Vec<u64> = Vec::new();
        let mut total_fees = 0u64;
        let mut block_size = 0usize;
        
        for tx in &block.txs {
            // Calcular tamaño de TX
            let tx_size = estimate_tx_size(tx);
            block_size += tx_size;
            
            // Calcular fee (inputs - outputs)
            let input_value: u64 = tx.inputs.iter()
                .filter_map(|inp| utxo_values(&inp.prev_tx_hash, inp.prev_index))
                .sum();
            
            let output_value: u64 = tx.outputs.iter()
                .map(|o| o.amount)
                .sum();
            
            // Solo si podemos calcular el fee (no coinbase)
            if input_value > 0 && input_value >= output_value {
                let fee = input_value - output_value;
                total_fees += fee;
                
                if tx_size > 0 {
                    let fee_rate = fee / tx_size as u64;
                    fee_rates.push(fee_rate);
                }
            }
        }
        
        // Calcular estadísticas
        fee_rates.sort_unstable();
        
        let min_fee_rate = *fee_rates.first().unwrap_or(&MIN_FEE_RATE);
        let max_fee_rate = *fee_rates.last().unwrap_or(&MIN_FEE_RATE);
        let avg_fee_rate = if fee_rates.is_empty() {
            MIN_FEE_RATE
        } else {
            fee_rates.iter().sum::<u64>() / fee_rates.len() as u64
        };
        let median_fee_rate = if fee_rates.is_empty() {
            MIN_FEE_RATE
        } else {
            fee_rates[fee_rates.len() / 2]
        };
        
        // Porcentaje de llenado (asumiendo max 1MB)
        let max_block_size = 1_000_000;
        let fill_percentage = (block_size as f64 / max_block_size as f64) * 100.0;
        
        BlockFeeStats {
            height: block.height,
            tx_count: block.txs.len(),
            total_fees,
            min_fee_rate,
            max_fee_rate,
            avg_fee_rate,
            median_fee_rate,
            block_size,
            fill_percentage,
        }
    }
}

// =============================================================================
// Fee Estimator
// =============================================================================

/// Estimador de fees
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FeeEstimator {
    /// Historial de estadísticas de bloques
    pub block_stats: VecDeque<BlockFeeStats>,
    /// Última estimación
    pub last_estimate: Option<FeeEstimate>,
    /// Configuración
    pub config: FeeConfig,
}

/// Configuración del estimador
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Bloques a analizar
    pub blocks_to_analyze: usize,
    /// Fee mínimo
    pub min_fee_rate: u64,
    /// Fee máximo
    pub max_fee_rate: u64,
    /// Usar mempool para ajustar
    pub use_mempool: bool,
}

impl Default for FeeConfig {
    fn default() -> Self {
        FeeConfig {
            blocks_to_analyze: BLOCKS_TO_ANALYZE,
            min_fee_rate: MIN_FEE_RATE,
            max_fee_rate: MAX_FEE_RATE,
            use_mempool: true,
        }
    }
}

/// Estimación de fee
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Fee rate en satoshis por byte
    pub fee_rate: u64,
    /// Fee rate en satoshis por vbyte (SegWit)
    pub fee_rate_vbyte: u64,
    /// Prioridad
    pub priority: FeePriority,
    /// Bloques estimados para confirmación
    pub estimated_blocks: usize,
    /// Fee total para TX típica legacy
    pub typical_fee: u64,
    /// Fee total para TX típica SegWit
    pub typical_fee_segwit: u64,
    /// Confianza de la estimación (0-100)
    pub confidence: u8,
}

impl FeeEstimator {
    /// Crea un nuevo estimador
    pub fn new() -> Self {
        FeeEstimator {
            block_stats: VecDeque::with_capacity(BLOCKS_TO_ANALYZE * 2),
            last_estimate: None,
            config: FeeConfig::default(),
        }
    }
    
    /// Procesa un nuevo bloque
    pub fn process_block(&mut self, stats: BlockFeeStats) {
        self.block_stats.push_back(stats);
        
        // Mantener solo los últimos N bloques
        while self.block_stats.len() > self.config.blocks_to_analyze * 2 {
            self.block_stats.pop_front();
        }
    }
    
    /// Estima el fee para una prioridad dada
    pub fn estimate(&mut self, priority: FeePriority) -> FeeEstimate {
        let base_rate = self.calculate_base_rate();
        let fee_rate = self.adjust_for_priority(base_rate, priority);
        
        // Aplicar límites
        let fee_rate = fee_rate.clamp(self.config.min_fee_rate, self.config.max_fee_rate);
        
        let estimate = FeeEstimate {
            fee_rate,
            fee_rate_vbyte: fee_rate, // Para SegWit es igual en vbytes
            priority,
            estimated_blocks: priority.target_blocks(),
            typical_fee: fee_rate * TYPICAL_TX_SIZE as u64,
            typical_fee_segwit: fee_rate * TYPICAL_SEGWIT_TX_SIZE as u64,
            confidence: self.calculate_confidence(),
        };
        
        self.last_estimate = Some(estimate.clone());
        estimate
    }
    
    /// Estima fees para todas las prioridades
    pub fn estimate_all(&mut self) -> Vec<FeeEstimate> {
        vec![
            self.estimate(FeePriority::High),
            self.estimate(FeePriority::Medium),
            self.estimate(FeePriority::Low),
            self.estimate(FeePriority::Minimum),
        ]
    }
    
    /// Calcula el fee rate base
    fn calculate_base_rate(&self) -> u64 {
        if self.block_stats.is_empty() {
            return MIN_FEE_RATE;
        }
        
        // Usar los últimos N bloques
        let recent: Vec<_> = self.block_stats.iter()
            .rev()
            .take(self.config.blocks_to_analyze)
            .collect();
        
        if recent.is_empty() {
            return MIN_FEE_RATE;
        }
        
        // Promedio ponderado de fee rates medianos
        // Bloques más recientes tienen más peso
        let mut weighted_sum = 0u64;
        let mut weight_total = 0u64;
        
        for (i, stats) in recent.iter().enumerate() {
            let weight = (recent.len() - i) as u64; // Más peso a los recientes
            weighted_sum += stats.median_fee_rate * weight;
            weight_total += weight;
        }
        
        if weight_total == 0 {
            return MIN_FEE_RATE;
        }
        
        weighted_sum / weight_total
    }
    
    /// Ajusta el fee según la prioridad
    fn adjust_for_priority(&self, base_rate: u64, priority: FeePriority) -> u64 {
        let multiplier = priority.multiplier();
        
        // Ajustar también por congestión
        let congestion_factor = self.calculate_congestion_factor();
        
        let adjusted = (base_rate as f64 * multiplier * congestion_factor) as u64;
        adjusted.max(MIN_FEE_RATE)
    }
    
    /// Calcula factor de congestión basado en llenado de bloques
    fn calculate_congestion_factor(&self) -> f64 {
        if self.block_stats.is_empty() {
            return 1.0;
        }
        
        let avg_fill: f64 = self.block_stats.iter()
            .rev()
            .take(3)
            .map(|s| s.fill_percentage)
            .sum::<f64>() / 3.0;
        
        // Si los bloques están muy llenos, aumentar fee
        if avg_fill > 90.0 {
            1.5
        } else if avg_fill > 75.0 {
            1.2
        } else if avg_fill > 50.0 {
            1.0
        } else {
            0.8 // Bloques vacíos = menos urgencia
        }
    }
    
    /// Calcula la confianza de la estimación
    fn calculate_confidence(&self) -> u8 {
        let block_count = self.block_stats.len();
        
        if block_count >= self.config.blocks_to_analyze {
            90
        } else if block_count >= 3 {
            70
        } else if block_count >= 1 {
            50
        } else {
            20 // Sin datos = baja confianza
        }
    }
    
    /// Ajusta la estimación basándose en el mempool
    pub fn adjust_for_mempool(&self, estimate: FeeEstimate, mempool: &Mempool) -> FeeEstimate {
        let pending_count = mempool.txs.len();
        
        if pending_count == 0 {
            return estimate;
        }
        
        // Si hay muchas TX pendientes, aumentar fee
        let mempool_factor = if pending_count > 1000 {
            1.5
        } else if pending_count > 500 {
            1.3
        } else if pending_count > 100 {
            1.1
        } else {
            1.0
        };
        
        let new_rate = (estimate.fee_rate as f64 * mempool_factor) as u64;
        let new_rate = new_rate.clamp(self.config.min_fee_rate, self.config.max_fee_rate);
        
        FeeEstimate {
            fee_rate: new_rate,
            fee_rate_vbyte: new_rate,
            typical_fee: new_rate * TYPICAL_TX_SIZE as u64,
            typical_fee_segwit: new_rate * TYPICAL_SEGWIT_TX_SIZE as u64,
            ..estimate
        }
    }
    
    /// Obtiene estadísticas resumidas
    pub fn get_stats(&self) -> FeeEstimatorStats {
        let estimates = vec![
            self.clone().estimate(FeePriority::High),
            self.clone().estimate(FeePriority::Medium),
            self.clone().estimate(FeePriority::Low),
        ];
        
        FeeEstimatorStats {
            blocks_analyzed: self.block_stats.len(),
            high_fee_rate: estimates[0].fee_rate,
            medium_fee_rate: estimates[1].fee_rate,
            low_fee_rate: estimates[2].fee_rate,
            avg_block_fill: self.block_stats.iter()
                .map(|s| s.fill_percentage)
                .sum::<f64>() / self.block_stats.len().max(1) as f64,
            confidence: self.calculate_confidence(),
        }
    }
}

/// Estadísticas del estimador
#[derive(Clone, Debug)]
pub struct FeeEstimatorStats {
    pub blocks_analyzed: usize,
    pub high_fee_rate: u64,
    pub medium_fee_rate: u64,
    pub low_fee_rate: u64,
    pub avg_block_fill: f64,
    pub confidence: u8,
}

// =============================================================================
// Transaction Size Estimation
// =============================================================================

/// Estima el tamaño de una transacción en bytes
pub fn estimate_tx_size(tx: &Tx) -> usize {
    // Overhead base
    let mut size = 10; // version (4) + locktime (4) + varint overhead (2)
    
    // Inputs: ~148 bytes cada uno (P2PKH)
    size += tx.inputs.len() * 148;
    
    // Outputs: ~34 bytes cada uno
    size += tx.outputs.len() * 34;
    
    size
}

/// Estima el tamaño de una transacción SegWit (vbytes)
pub fn estimate_segwit_tx_vsize(num_inputs: usize, num_outputs: usize) -> usize {
    // Base size (sin witness)
    let base = 10 + num_inputs * 41 + num_outputs * 31;
    
    // Witness size
    let witness = num_inputs * 107; // signature + pubkey
    
    // Weight = base * 4 + witness
    let weight = base * 4 + witness;
    
    // vsize = (weight + 3) / 4
    (weight + 3) / 4
}

/// Calcula el fee total para un tamaño dado
pub fn calculate_fee(size_bytes: usize, fee_rate: u64) -> u64 {
    size_bytes as u64 * fee_rate
}

/// Calcula el fee para una TX con N inputs y M outputs
pub fn calculate_tx_fee(num_inputs: usize, num_outputs: usize, fee_rate: u64, segwit: bool) -> u64 {
    let size = if segwit {
        estimate_segwit_tx_vsize(num_inputs, num_outputs)
    } else {
        10 + num_inputs * 148 + num_outputs * 34
    };
    
    calculate_fee(size, fee_rate)
}

// =============================================================================
// Fee Recommendations
// =============================================================================

/// Genera recomendaciones de fee basadas en el monto a enviar
pub fn recommend_fee(amount: u64, estimates: &[FeeEstimate]) -> FeeRecommendation {
    // Encontrar la estimación con mejor relación costo/beneficio
    let medium = estimates.iter()
        .find(|e| e.priority == FeePriority::Medium)
        .cloned()
        .unwrap_or_else(|| FeeEstimate {
            fee_rate: MIN_FEE_RATE,
            fee_rate_vbyte: MIN_FEE_RATE,
            priority: FeePriority::Medium,
            estimated_blocks: 3,
            typical_fee: MIN_FEE_RATE * TYPICAL_TX_SIZE as u64,
            typical_fee_segwit: MIN_FEE_RATE * TYPICAL_SEGWIT_TX_SIZE as u64,
            confidence: 50,
        });
    
    // Calcular porcentaje del monto
    let fee_percentage = if amount > 0 {
        (medium.typical_fee as f64 / amount as f64) * 100.0
    } else {
        0.0
    };
    
    // Determinar si usar SegWit (ahorro > 30%)
    let use_segwit = medium.typical_fee_segwit < (medium.typical_fee * 70 / 100);
    
    FeeRecommendation {
        recommended_fee_rate: medium.fee_rate,
        recommended_fee: if use_segwit { medium.typical_fee_segwit } else { medium.typical_fee },
        use_segwit,
        fee_percentage,
        estimated_blocks: medium.estimated_blocks,
        warning: if fee_percentage > 5.0 {
            Some("Fee is more than 5% of amount".to_string())
        } else {
            None
        },
    }
}

/// Recomendación de fee
#[derive(Clone, Debug)]
pub struct FeeRecommendation {
    pub recommended_fee_rate: u64,
    pub recommended_fee: u64,
    pub use_segwit: bool,
    pub fee_percentage: f64,
    pub estimated_blocks: usize,
    pub warning: Option<String>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fee_priority() {
        assert_eq!(FeePriority::High.target_blocks(), 1);
        assert_eq!(FeePriority::Medium.target_blocks(), 3);
        assert_eq!(FeePriority::Low.target_blocks(), 6);
        
        assert!(FeePriority::High.multiplier() > FeePriority::Medium.multiplier());
    }
    
    #[test]
    fn test_fee_estimator() {
        let mut estimator = FeeEstimator::new();
        
        // Sin datos, debería dar fee mínimo
        let estimate = estimator.estimate(FeePriority::Medium);
        assert_eq!(estimate.fee_rate, MIN_FEE_RATE);
        assert!(estimate.confidence < 50);
    }
    
    #[test]
    fn test_tx_size_estimation() {
        // TX típica: 1 input, 2 outputs
        let size = 10 + 1 * 148 + 2 * 34;
        assert_eq!(size, 226);
        
        // SegWit vsize debería ser menor
        let vsize = estimate_segwit_tx_vsize(1, 2);
        assert!(vsize < size);
    }
    
    #[test]
    fn test_calculate_fee() {
        let size = 225;
        let fee_rate = 10; // 10 sat/byte
        let fee = calculate_fee(size, fee_rate);
        assert_eq!(fee, 2250);
    }
    
    #[test]
    fn test_fee_recommendation() {
        let estimates = vec![
            FeeEstimate {
                fee_rate: 10,
                fee_rate_vbyte: 10,
                priority: FeePriority::Medium,
                estimated_blocks: 3,
                typical_fee: 2250,
                typical_fee_segwit: 1410,
                confidence: 80,
            },
        ];
        
        let amount = 100_000; // 0.001 MOON
        let rec = recommend_fee(amount, &estimates);
        
        assert_eq!(rec.recommended_fee_rate, 10);
        assert!(rec.use_segwit); // SegWit ahorra más del 30%
    }
}
