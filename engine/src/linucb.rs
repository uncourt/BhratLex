use nalgebra::{DMatrix, DVector};
use std::collections::HashMap;
use tracing::debug;

pub struct LinUCB {
    alpha: f64,
    actions: Vec<String>,
    action_features: HashMap<String, DVector<f64>>,
    action_matrices: HashMap<String, DMatrix<f64>>,
    action_vectors: HashMap<String, DVector<f64>>,
    feature_dim: usize,
}

impl LinUCB {
    pub fn new(alpha: f64, feature_dim: usize) -> Self {
        Self {
            alpha,
            actions: vec!["ALLOW".to_string(), "WARN".to_string(), "BLOCK".to_string()],
            action_features: HashMap::new(),
            action_matrices: HashMap::new(),
            action_vectors: HashMap::new(),
            feature_dim,
        }
    }

    pub fn initialize_action(&mut self, action: &str) {
        if !self.action_matrices.contains_key(action) {
            let matrix = DMatrix::identity(self.feature_dim, self.feature_dim);
            let vector = DVector::zeros(self.feature_dim);
            
            self.action_matrices.insert(action.to_string(), matrix);
            self.action_vectors.insert(action.to_string(), vector);
            
            debug!("Initialized LinUCB for action: {}", action);
        }
    }

    pub fn select_action(&mut self, context: &[f64]) -> String {
        let mut best_action = "ALLOW".to_string();
        let mut best_ucb = f64::NEG_INFINITY;
        
        let context_vector = DVector::from_column_slice(context);
        
        for action in &self.actions {
            self.initialize_action(action);
            
            let matrix = self.action_matrices.get(action).unwrap();
            let vector = self.action_vectors.get(action).unwrap();
            
            // Calculate UCB
            let ucb = self.calculate_ucb(matrix, vector, &context_vector);
            
            if ucb > best_ucb {
                best_ucb = ucb;
                best_action = action.clone();
            }
        }
        
        debug!("LinUCB selected action: {} with UCB: {}", best_action, best_ucb);
        best_action
    }

    pub fn update(&mut self, action: &str, context: &[f64], reward: f64) {
        self.initialize_action(action);
        
        let context_vector = DVector::from_column_slice(context);
        let matrix = self.action_matrices.get_mut(action).unwrap();
        let vector = self.action_vectors.get_mut(action).unwrap();
        
        // Update matrix and vector
        let outer_product = &context_vector * context_vector.transpose();
        *matrix += outer_product;
        *vector += reward * &context_vector;
        
        debug!("Updated LinUCB for action: {} with reward: {}", action, reward);
    }

    fn calculate_ucb(&self, matrix: &DMatrix<f64>, vector: &DVector<f64>, context: &DVector<f64>) -> f64 {
        // Calculate inverse of matrix
        let matrix_inv = matrix.try_inverse().unwrap_or_else(|| {
            // If matrix is singular, add small regularization
            let reg_matrix = matrix + DMatrix::identity(self.feature_dim, self.feature_dim) * 1e-6;
            reg_matrix.try_inverse().unwrap_or_else(|| {
                DMatrix::identity(self.feature_dim, self.feature_dim)
            })
        });
        
        // Calculate theta (parameter vector)
        let theta = &matrix_inv * vector;
        
        // Calculate prediction
        let prediction = context.dot(&theta);
        
        // Calculate exploration bonus
        let exploration = self.alpha * (context.transpose() * &matrix_inv * context).sqrt();
        
        prediction + exploration
    }

    pub fn get_action_stats(&self) -> HashMap<String, HashMap<String, f64>> {
        let mut stats = HashMap::new();
        
        for action in &self.actions {
            if let (Some(matrix), Some(vector)) = (
                self.action_matrices.get(action),
                self.action_vectors.get(action)
            ) {
                let mut action_stats = HashMap::new();
                action_stats.insert("matrix_determinant".to_string(), matrix.determinant());
                action_stats.insert("vector_norm".to_string(), vector.norm());
                action_stats.insert("matrix_condition".to_string(), matrix.condition_number());
                
                stats.insert(action.clone(), action_stats);
            }
        }
        
        stats
    }

    pub fn reset(&mut self) {
        self.action_matrices.clear();
        self.action_vectors.clear();
        debug!("Reset all LinUCB matrices and vectors");
    }

    pub fn set_alpha(&mut self, alpha: f64) {
        self.alpha = alpha;
        debug!("Set LinUCB alpha to: {}", alpha);
    }

    pub fn get_alpha(&self) -> f64 {
        self.alpha
    }

    pub fn get_feature_dimension(&self) -> usize {
        self.feature_dim
    }

    pub fn get_num_actions(&self) -> usize {
        self.actions.len()
    }
}

impl Default for LinUCB {
    fn default() -> Self {
        Self::new(1.0, 19) // 19 features from DomainFeatures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linucb_initialization() {
        let mut linucb = LinUCB::new(1.0, 3);
        assert_eq!(linucb.get_feature_dimension(), 3);
        assert_eq!(linucb.get_num_actions(), 3);
    }

    #[test]
    fn test_action_selection() {
        let mut linucb = LinUCB::new(1.0, 3);
        let context = vec![1.0, 0.5, 0.3];
        let action = linucb.select_action(&context);
        assert!(["ALLOW", "WARN", "BLOCK"].contains(&action.as_str()));
    }

    #[test]
    fn test_update() {
        let mut linucb = LinUCB::new(1.0, 3);
        let context = vec![1.0, 0.5, 0.3];
        linucb.update("ALLOW", &context, 1.0);
        
        let stats = linucb.get_action_stats();
        assert!(stats.contains_key("ALLOW"));
    }
}