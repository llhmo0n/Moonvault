// =============================================================================
// MOONCOIN v2.0 - Ajuste de Dificultad (Bitcoin-style)
// =============================================================================

use crate::lib::*;
use crate::block::Block;

/// Calcula la dificultad para el siguiente bloque
pub fn calculate_next_difficulty(chain: &[Block]) -> u32 {
    let height = chain.len() as u64;
    
    // Si no hay bloques o es el primer intervalo, usar dificultad inicial
    if height == 0 {
        return INITIAL_DIFFICULTY_BITS;
    }
    
    // Solo ajustar cada DIFFICULTY_ADJUSTMENT_INTERVAL bloques
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
        return chain.last().unwrap().difficulty_bits;
    }
    
    // Obtener el primer bloque del intervalo anterior
    let interval_start_height = height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL);
    let first_block = &chain[interval_start_height as usize];
    let last_block = chain.last().unwrap();
    
    // Calcular tiempo real del intervalo
    let actual_timespan = last_block.timestamp.saturating_sub(first_block.timestamp);
    
    // Calcular nuevo target basado en el tiempo real vs esperado
    let new_difficulty = adjust_difficulty(
        last_block.difficulty_bits,
        actual_timespan,
        EXPECTED_TIMESPAN,
    );
    
    log::info!(
        "Ajuste de dificultad en altura {}: {} -> {} (timespan: {}s vs {}s esperado)",
        height,
        last_block.difficulty_bits,
        new_difficulty,
        actual_timespan,
        EXPECTED_TIMESPAN
    );
    
    new_difficulty
}

/// Ajusta la dificultad basado en el tiempo real vs esperado
fn adjust_difficulty(current_bits: u32, actual_timespan: u64, expected_timespan: u64) -> u32 {
    // Limitar el ajuste a un factor de 4 (como Bitcoin)
    let actual_clamped = actual_timespan
        .max(expected_timespan / 4)
        .min(expected_timespan * 4);
    
    // Calcular ratio: si actual > expected, la red es lenta, bajar dificultad
    // Si actual < expected, la red es rápida, subir dificultad
    
    let ratio = (actual_clamped as f64) / (expected_timespan as f64);
    
    // Calcular nuevo difficulty_bits
    // Menor ratio = más rápido = más bits = más difícil
    // Mayor ratio = más lento = menos bits = más fácil
    
    let adjustment = if ratio < 1.0 {
        // Red más rápida de lo esperado: aumentar dificultad
        let increase = ((1.0 / ratio).log2() * 2.0).ceil() as u32;
        current_bits.saturating_add(increase.min(4))  // Máximo +4 bits por ajuste
    } else if ratio > 1.0 {
        // Red más lenta de lo esperado: disminuir dificultad
        let decrease = (ratio.log2() * 2.0).ceil() as u32;
        current_bits.saturating_sub(decrease.min(4))  // Máximo -4 bits por ajuste
    } else {
        current_bits
    };
    
    // Mantener dentro de límites
    adjustment.clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS)
}

/// Estima el hashrate de la red basado en la dificultad y tiempo entre bloques
pub fn estimate_network_hashrate(chain: &[Block]) -> f64 {
    if chain.len() < 2 {
        return 0.0;
    }
    
    let last = chain.last().unwrap();
    let prev = &chain[chain.len() - 2];
    
    let time_diff = last.timestamp.saturating_sub(prev.timestamp);
    if time_diff == 0 {
        return 0.0;
    }
    
    // Hashrate aproximado = 2^difficulty_bits / tiempo
    let difficulty = 2_f64.powi(last.difficulty_bits as i32);
    difficulty / (time_diff as f64)
}

/// Estima el tiempo hasta el próximo bloque
pub fn estimate_time_to_block(current_difficulty: u32, hashrate: f64) -> f64 {
    if hashrate <= 0.0 {
        return f64::INFINITY;
    }
    
    let difficulty = 2_f64.powi(current_difficulty as i32);
    difficulty / hashrate
}

/// Calcula el progreso hacia el próximo ajuste de dificultad
pub fn difficulty_adjustment_progress(height: u64) -> (u64, u64) {
    let blocks_since_adjustment = height % DIFFICULTY_ADJUSTMENT_INTERVAL;
    let blocks_until_adjustment = DIFFICULTY_ADJUSTMENT_INTERVAL - blocks_since_adjustment;
    (blocks_since_adjustment, blocks_until_adjustment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_difficulty_faster() {
        // Red 2x más rápida: debería aumentar dificultad
        let new = adjust_difficulty(20, 302_400, 604_800);  // 3.5 días vs 7 días
        assert!(new > 20);
    }

    #[test]
    fn test_adjust_difficulty_slower() {
        // Red 2x más lenta: debería disminuir dificultad
        let new = adjust_difficulty(20, 1_209_600, 604_800);  // 14 días vs 7 días
        assert!(new < 20);
    }

    #[test]
    fn test_difficulty_limits() {
        // No debe bajar de MIN_DIFFICULTY_BITS
        let new = adjust_difficulty(MIN_DIFFICULTY_BITS, 9_999_999, 100);
        assert!(new >= MIN_DIFFICULTY_BITS);
        
        // No debe subir de MAX_DIFFICULTY_BITS
        let new = adjust_difficulty(MAX_DIFFICULTY_BITS, 1, 9_999_999);
        assert!(new <= MAX_DIFFICULTY_BITS);
    }
}
