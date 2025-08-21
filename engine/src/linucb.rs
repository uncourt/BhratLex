use nalgebra::{DMatrix, DVector};
use rand::prelude::*;
use std::collections::HashMap;

pub struct LinUCBBandit {
    num_arms: usize,
    context_dim: usize,
    alpha: f64,
    
    // Per-arm parameters
    a_matrices: Vec<DMatrix<f64>>,  // A_a for each arm
    b_vectors: Vec<DVector<f64>>,   // b_a for each arm
    theta_vectors: Vec<DVector<f64>>, // θ_a for each arm
    
    // Statistics
    arm_counts: Vec<u64>,
    total_reward: f64,
    total_count: u64,
}

impl LinUCBBandit {
    pub fn new(num_arms: usize, context_dim: usize, alpha: f64) -> Self {
        let mut a_matrices = Vec::with_capacity(num_arms);
        let mut b_vectors = Vec::with_capacity(num_arms);
        let mut theta_vectors = Vec::with_capacity(num_arms);
        
        for _ in 0..num_arms {
            // Initialize A_a as identity matrix
            a_matrices.push(DMatrix::identity(context_dim, context_dim));
            // Initialize b_a as zero vector
            b_vectors.push(DVector::zeros(context_dim));
            // Initialize θ_a as zero vector
            theta_vectors.push(DVector::zeros(context_dim));
        }
        
        Self {
            num_arms,
            context_dim,
            alpha,
            a_matrices,
            b_vectors,
            theta_vectors,
            arm_counts: vec![0; num_arms],
            total_reward: 0.0,
            total_count: 0,
        }
    }
    
    /// Select arm based on LinUCB algorithm
    /// Returns (arm_index, confidence_score)
    pub fn select_arm(&mut self, context: &[f64]) -> (usize, f32) {
        if context.len() != self.context_dim {
            panic!("Context dimension mismatch");
        }
        
        let context_vec = DVector::from_vec(context.to_vec());
        let mut best_arm = 0;
        let mut best_ucb = f64::NEG_INFINITY;
        
        for arm in 0..self.num_arms {
            let ucb_value = self.compute_ucb_value(arm, &context_vec);
            
            if ucb_value > best_ucb {
                best_ucb = ucb_value;
                best_arm = arm;
            }
        }
        
        // Return confidence as normalized UCB value
        let confidence = (best_ucb.max(0.0).min(2.0) / 2.0) as f32;
        
        (best_arm, confidence)
    }
    
    /// Update bandit with observed reward
    pub fn update(&mut self, arm: usize, context: &[f64], reward: f64) {
        if arm >= self.num_arms || context.len() != self.context_dim {
            return;
        }
        
        let context_vec = DVector::from_vec(context.to_vec());
        
        // Update A_a = A_a + x_t * x_t^T
        let outer_product = &context_vec * context_vec.transpose();
        self.a_matrices[arm] += outer_product;
        
        // Update b_a = b_a + r_t * x_t
        self.b_vectors[arm] += reward * &context_vec;
        
        // Update θ_a = A_a^(-1) * b_a
        if let Some(a_inv) = self.a_matrices[arm].try_inverse() {
            self.theta_vectors[arm] = a_inv * &self.b_vectors[arm];
        }
        
        // Update statistics
        self.arm_counts[arm] += 1;
        self.total_reward += reward;
        self.total_count += 1;
    }
    
    fn compute_ucb_value(&self, arm: usize, context: &DVector<f64>) -> f64 {
        // Compute θ_a^T * x_t
        let mean_reward = self.theta_vectors[arm].dot(context);
        
        // Compute confidence interval: α * sqrt(x_t^T * A_a^(-1) * x_t)
        let confidence_interval = if let Some(a_inv) = self.a_matrices[arm].try_inverse() {
            let quadratic_form = context.transpose() * a_inv * context;
            self.alpha * quadratic_form[(0, 0)].sqrt()
        } else {
            self.alpha // Fallback if matrix is not invertible
        };
        
        mean_reward + confidence_interval
    }
    
    pub fn get_statistics(&self) -> LinUCBStats {
        LinUCBStats {
            total_count: self.total_count,
            total_reward: self.total_reward,
            average_reward: if self.total_count > 0 { 
                self.total_reward / self.total_count as f64 
            } else { 
                0.0 
            },
            arm_counts: self.arm_counts.clone(),
            arm_rewards: self.compute_arm_rewards(),
        }
    }
    
    fn compute_arm_rewards(&self) -> Vec<f64> {
        self.theta_vectors
            .iter()
            .map(|theta| theta.norm())
            .collect()
    }
    
    /// Get current arm preferences for a given context
    pub fn get_arm_preferences(&self, context: &[f64]) -> Vec<f64> {
        if context.len() != self.context_dim {
            return vec![0.0; self.num_arms];
        }
        
        let context_vec = DVector::from_vec(context.to_vec());
        
        (0..self.num_arms)
            .map(|arm| {
                self.theta_vectors[arm].dot(&context_vec)
            })
            .collect()
    }
    
    /// Reset bandit to initial state
    pub fn reset(&mut self) {
        for arm in 0..self.num_arms {
            self.a_matrices[arm] = DMatrix::identity(self.context_dim, self.context_dim);
            self.b_vectors[arm] = DVector::zeros(self.context_dim);
            self.theta_vectors[arm] = DVector::zeros(self.context_dim);
            self.arm_counts[arm] = 0;
        }
        self.total_reward = 0.0;
        self.total_count = 0;
    }
    
    /// Export model parameters for persistence
    pub fn export_parameters(&self) -> LinUCBParameters {
        LinUCBParameters {
            num_arms: self.num_arms,
            context_dim: self.context_dim,
            alpha: self.alpha,
            theta_vectors: self.theta_vectors
                .iter()
                .map(|v| v.as_slice().to_vec())
                .collect(),
            arm_counts: self.arm_counts.clone(),
            total_reward: self.total_reward,
            total_count: self.total_count,
        }
    }
    
    /// Import model parameters for persistence
    pub fn import_parameters(&mut self, params: LinUCBParameters) -> Result<(), String> {
        if params.num_arms != self.num_arms || params.context_dim != self.context_dim {
            return Err("Parameter dimensions don't match".to_string());
        }
        
        for (i, theta_vec) in params.theta_vectors.iter().enumerate() {
            if theta_vec.len() != self.context_dim {
                return Err("Theta vector dimension mismatch".to_string());
            }
            self.theta_vectors[i] = DVector::from_vec(theta_vec.clone());
        }
        
        self.arm_counts = params.arm_counts;
        self.total_reward = params.total_reward;
        self.total_count = params.total_count;
        self.alpha = params.alpha;
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LinUCBStats {
    pub total_count: u64,
    pub total_reward: f64,
    pub average_reward: f64,
    pub arm_counts: Vec<u64>,
    pub arm_rewards: Vec<f64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinUCBParameters {
    pub num_arms: usize,
    pub context_dim: usize,
    pub alpha: f64,
    pub theta_vectors: Vec<Vec<f64>>,
    pub arm_counts: Vec<u64>,
    pub total_reward: f64,
    pub total_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_linucb_basic() {
        let mut bandit = LinUCBBandit::new(3, 4, 1.0);
        
        let context = vec![1.0, 0.5, -0.2, 0.8];
        let (arm, confidence) = bandit.select_arm(&context);
        
        assert!(arm < 3);
        assert!(confidence >= 0.0 && confidence <= 1.0);
        
        bandit.update(arm, &context, 1.0);
        
        let stats = bandit.get_statistics();
        assert_eq!(stats.total_count, 1);
        assert_eq!(stats.total_reward, 1.0);
    }
    
    #[test]
    fn test_linucb_preferences() {
        let bandit = LinUCBBandit::new(3, 2, 1.0);
        let context = vec![1.0, 0.0];
        
        let prefs = bandit.get_arm_preferences(&context);
        assert_eq!(prefs.len(), 3);
    }
    
    #[test]
    fn test_parameter_export_import() {
        let mut bandit1 = LinUCBBandit::new(2, 3, 1.5);
        let context = vec![1.0, 0.5, -1.0];
        
        bandit1.update(0, &context, 0.8);
        bandit1.update(1, &context, 0.2);
        
        let params = bandit1.export_parameters();
        let mut bandit2 = LinUCBBandit::new(2, 3, 1.0);
        
        assert!(bandit2.import_parameters(params).is_ok());
        
        let stats1 = bandit1.get_statistics();
        let stats2 = bandit2.get_statistics();
        
        assert_eq!(stats1.total_count, stats2.total_count);
        assert_eq!(stats1.total_reward, stats2.total_reward);
    }
}