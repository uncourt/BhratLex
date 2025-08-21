#!/usr/bin/env python3
"""
Student Model Training Script
Distills teacher model knowledge to lightweight student model
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

class StudentModelTrainer:
    def __init__(self, input_file: str, output_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.logger = logging.getLogger(__name__)
        
        # Feature names matching the Rust DomainFeatures struct
        self.feature_names = [
            'length', 'entropy', 'consonant_ratio', 'vowel_ratio', 'digit_ratio',
            'special_char_ratio', 'consecutive_consonants', 'consecutive_vowels',
            'consecutive_digits', 'consecutive_special_chars', 'idn_homoglyph_score',
            'typosquatting_score', 'dga_entropy', 'nrd_flag', 'dynamic_dns_flag',
            'parked_domain_flag', 'cname_cloaking_flag', 'dns_rebinding_flag',
            'cryptojacking_flag'
        ]
        
    def load_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load and preprocess training data"""
        self.logger.info(f"Loading data from {self.input_file}")
        
        try:
            # Load CSV data
            df = pd.read_csv(self.input_file)
            self.logger.info(f"Loaded {len(df)} samples with {len(df.columns)} columns")
            
            # Check required columns
            required_columns = self.feature_names + ['label']
            missing_columns = set(required_columns) - set(df.columns)
            
            if missing_columns:
                self.logger.warning(f"Missing columns: {missing_columns}")
                self.logger.info("Available columns: " + ", ".join(df.columns))
                
                # Try to map common column names
                df = self._map_column_names(df)
            
            # Extract features and labels
            X = df[self.feature_names].values
            y = df['label'].values
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0)
            
            # Convert labels to binary (0 for safe, 1 for malicious)
            y = (y == 'malicious').astype(int)
            
            self.logger.info(f"Features shape: {X.shape}, Labels shape: {y.shape}")
            self.logger.info(f"Class distribution: {np.bincount(y)}")
            
            return X, y
            
        except Exception as e:
            self.logger.error(f"Failed to load data: {e}")
            raise
    
    def _map_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map common column names to expected feature names"""
        column_mapping = {
            'domain_length': 'length',
            'domain_entropy': 'entropy',
            'consonant_ratio': 'consonant_ratio',
            'vowel_ratio': 'vowel_ratio',
            'digit_ratio': 'digit_ratio',
            'special_char_ratio': 'special_char_ratio',
            'max_consecutive_consonants': 'consecutive_consonants',
            'max_consecutive_vowels': 'consecutive_vowels',
            'max_consecutive_digits': 'consecutive_digits',
            'max_consecutive_special_chars': 'consecutive_special_chars',
            'homoglyph_score': 'idn_homoglyph_score',
            'typosquatting_score': 'typosquatting_score',
            'dga_score': 'dga_entropy',
            'nrd_score': 'nrd_flag',
            'dynamic_dns_score': 'dynamic_dns_flag',
            'parked_domain_score': 'parked_domain_flag',
            'cname_cloaking_score': 'cname_cloaking_flag',
            'dns_rebinding_score': 'dns_rebinding_flag',
            'cryptojacking_score': 'cryptojacking_flag',
            'is_malicious': 'label',
            'threat_label': 'label',
            'target': 'label'
        }
        
        # Rename columns
        df = df.rename(columns=column_mapping)
        
        # Add missing columns with default values
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0.0
                self.logger.warning(f"Added missing feature {feature} with default value 0.0")
        
        if 'label' not in df.columns:
            # Try to infer label from other columns
            label_candidates = ['is_malicious', 'threat_label', 'target', 'class']
            for candidate in label_candidates:
                if candidate in df.columns:
                    df['label'] = df[candidate]
                    self.logger.info(f"Mapped {candidate} to label")
                    break
            else:
                raise ValueError("Could not find or infer label column")
        
        return df
    
    def preprocess_features(self, X: np.ndarray) -> np.ndarray:
        """Preprocess features for training"""
        self.logger.info("Preprocessing features")
        
        # Standardize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Clip extreme values
        X_scaled = np.clip(X_scaled, -5, 5)
        
        self.logger.info(f"Feature preprocessing completed. Mean: {X_scaled.mean():.3f}, Std: {X_scaled.std():.3f}")
        
        return X_scaled
    
    def train_model(self, X: np.ndarray, y: np.ndarray) -> LogisticRegression:
        """Train logistic regression model"""
        self.logger.info("Training logistic regression model")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        model = LogisticRegression(
            random_state=42,
            max_iter=1000,
            solver='liblinear',
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # Print metrics
        self.logger.info("Model evaluation:")
        self.logger.info(f"Accuracy: {model.score(X_test, y_test):.3f}")
        self.logger.info(f"ROC AUC: {roc_auc_score(y_test, y_pred_proba):.3f}")
        
        # Classification report
        report = classification_report(y_test, y_pred, target_names=['Safe', 'Malicious'])
        self.logger.info(f"\nClassification Report:\n{report}")
        
        return model
    
    def create_student_model(self, model: LogisticRegression) -> Dict:
        """Create student model in the format expected by Rust"""
        self.logger.info("Creating student model")
        
        # Extract weights and bias
        weights = {}
        for i, feature_name in enumerate(self.feature_names):
            weights[feature_name] = float(model.coef_[0][i])
        
        bias = float(model.intercept_[0])
        
        # Create student model structure
        student_model = {
            "weights": weights,
            "bias": bias,
            "version": f"v1.0.{datetime.now().strftime('%Y%m%d')}",
            "training_samples": len(model.classes_),
            "feature_names": self.feature_names,
            "model_type": "logistic_regression",
            "training_date": datetime.now().isoformat(),
            "performance_metrics": {
                "accuracy": float(model.score(X_test, y_test)),
                "roc_auc": float(roc_auc_score(y_test, y_pred_proba))
            }
        }
        
        return student_model
    
    def save_model(self, student_model: Dict):
        """Save student model to JSON file"""
        self.logger.info(f"Saving student model to {self.output_file}")
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Save model
            with open(self.output_file, 'w') as f:
                json.dump(student_model, f, indent=2)
            
            self.logger.info("Student model saved successfully")
            
            # Print model summary
            self._print_model_summary(student_model)
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")
            raise
    
    def _print_model_summary(self, student_model: Dict):
        """Print summary of the trained model"""
        print("\n" + "="*50)
        print("STUDENT MODEL SUMMARY")
        print("="*50)
        print(f"Version: {student_model['version']}")
        print(f"Training samples: {student_model['training_samples']}")
        print(f"Model type: {student_model['model_type']}")
        print(f"Training date: {student_model['training_date']}")
        print(f"Bias: {student_model['bias']:.6f}")
        
        print("\nFeature Weights (Top 10 by importance):")
        weights = student_model['weights']
        sorted_weights = sorted(weights.items(), key=lambda x: abs(x[1]), reverse=True)
        
        for feature, weight in sorted_weights[:10]:
            importance = "HIGH" if abs(weight) > 0.5 else "MEDIUM" if abs(weight) > 0.2 else "LOW"
            print(f"  {feature:25s}: {weight:8.4f} ({importance})")
        
        print(f"\nPerformance Metrics:")
        metrics = student_model['performance_metrics']
        print(f"  Accuracy: {metrics['accuracy']:.3f}")
        print(f"  ROC AUC:  {metrics['roc_auc']:.3f}")
        print("="*50)
    
    def run_training(self):
        """Run complete training pipeline"""
        try:
            # Load data
            X, y = self.load_data()
            
            # Preprocess features
            X_processed = self.preprocess_features(X)
            
            # Train model
            model = self.train_model(X_processed, y)
            
            # Create student model
            student_model = self.create_student_model(model)
            
            # Save model
            self.save_model(student_model)
            
            self.logger.info("Training completed successfully!")
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Train Garuda student model")
    parser.add_argument("--input", "-i", required=True, help="Input CSV file with training data")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file for student model")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Validate input file
    if not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)
    
    # Create trainer and run training
    trainer = StudentModelTrainer(args.input, args.output)
    
    try:
        trainer.run_training()
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()