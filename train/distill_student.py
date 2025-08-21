#!/usr/bin/env python3

import argparse
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import lightgbm as lgb


class StudentModelTrainer:
    def __init__(self):
        self.feature_names = [
            "domain_length", "subdomain_count", "numeric_ratio", "special_char_ratio",
            "entropy", "vowel_consonant_ratio", "digit_letter_ratio", "consecutive_consonants",
            "dictionary_words", "tld_popularity", "alexa_rank_log", "domain_age_days",
            "is_idn", "homoglyph_score", "typosquatting_score", "dga_score",
            "dynamic_dns", "parked_domain", "suspicious_tld", "fast_flux",
            "dns_record_count", "mx_record_exists", "spf_record_exists", "dmarc_record_exists",
            "ssl_cert_valid", "whois_privacy", "registrar_reputation", "ip_reputation",
            "asn_reputation", "geolocation_risk", "url_length", "path_depth",
            "query_params_count", "fragment_exists", "suspicious_keywords", "phishing_keywords",
            "brand_impersonation", "url_shortener", "redirect_count", "response_time_ms",
            "content_type_suspicious", "javascript_obfuscated", "form_count", "input_field_count",
            "external_links_count", "suspicious_file_extensions", "crypto_mining_scripts",
            "social_engineering_indicators", "urgency_language", "trust_indicators_missing"
        ]
        
        self.scaler = StandardScaler()
        self.teacher_model = None
        self.student_model = None
    
    def load_data(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load training data from CSV"""
        print(f"Loading data from {csv_path}...")
        
        if not os.path.exists(csv_path):
            print(f"Creating sample data file at {csv_path}...")
            self.create_sample_data(csv_path)
        
        df = pd.read_csv(csv_path)
        print(f"Loaded {len(df)} samples")
        
        # Extract features
        X = df[self.feature_names].values
        
        # Extract labels (convert to binary: 0=benign, 1=threat)
        if 'is_threat' in df.columns:
            y = df['is_threat'].values.astype(int)
        else:
            # Fallback: use probability threshold
            y = (df['probability'] > 0.5).astype(int)
        
        print(f"Features shape: {X.shape}")
        print(f"Labels distribution: {np.bincount(y)}")
        
        return X, y
    
    def create_sample_data(self, csv_path: str):
        """Create sample training data for demonstration"""
        print("Creating sample training data...")
        
        np.random.seed(42)
        n_samples = 10000
        
        # Generate synthetic features
        data = {}
        
        # Basic domain features
        data['domain_length'] = np.random.normal(15, 5, n_samples).clip(3, 50)
        data['subdomain_count'] = np.random.poisson(0.5, n_samples).clip(0, 5)
        data['numeric_ratio'] = np.random.beta(0.5, 2, n_samples)
        data['special_char_ratio'] = np.random.beta(0.3, 3, n_samples)
        data['entropy'] = np.random.normal(4.2, 0.8, n_samples).clip(2, 6)
        data['vowel_consonant_ratio'] = np.random.normal(0.8, 0.2, n_samples).clip(0.2, 2)
        data['digit_letter_ratio'] = np.random.beta(0.3, 2, n_samples)
        data['consecutive_consonants'] = np.random.poisson(2, n_samples).clip(0, 8)
        data['dictionary_words'] = np.random.poisson(1, n_samples).clip(0, 5)
        data['tld_popularity'] = np.random.exponential(0.1, n_samples).clip(0, 1)
        data['alexa_rank_log'] = np.random.normal(10, 3, n_samples).clip(0, 20)
        data['domain_age_days'] = np.random.exponential(365, n_samples).clip(0, 7300)
        
        # Binary features
        data['is_idn'] = np.random.binomial(1, 0.05, n_samples)
        data['dynamic_dns'] = np.random.binomial(1, 0.1, n_samples)
        data['parked_domain'] = np.random.binomial(1, 0.05, n_samples)
        data['suspicious_tld'] = np.random.binomial(1, 0.1, n_samples)
        data['fast_flux'] = np.random.binomial(1, 0.02, n_samples)
        data['mx_record_exists'] = np.random.binomial(1, 0.7, n_samples)
        data['spf_record_exists'] = np.random.binomial(1, 0.4, n_samples)
        data['dmarc_record_exists'] = np.random.binomial(1, 0.3, n_samples)
        data['ssl_cert_valid'] = np.random.binomial(1, 0.8, n_samples)
        data['whois_privacy'] = np.random.binomial(1, 0.3, n_samples)
        data['url_shortener'] = np.random.binomial(1, 0.05, n_samples)
        data['content_type_suspicious'] = np.random.binomial(1, 0.1, n_samples)
        data['javascript_obfuscated'] = np.random.binomial(1, 0.05, n_samples)
        
        # Threat scores
        data['homoglyph_score'] = np.random.beta(0.5, 4, n_samples)
        data['typosquatting_score'] = np.random.beta(0.5, 4, n_samples)
        data['dga_score'] = np.random.beta(0.5, 4, n_samples)
        
        # Network features
        data['dns_record_count'] = np.random.poisson(3, n_samples).clip(0, 10)
        data['registrar_reputation'] = np.random.normal(0.7, 0.2, n_samples).clip(0, 1)
        data['ip_reputation'] = np.random.normal(0.8, 0.15, n_samples).clip(0, 1)
        data['asn_reputation'] = np.random.normal(0.8, 0.15, n_samples).clip(0, 1)
        data['geolocation_risk'] = np.random.beta(1, 3, n_samples)
        
        # URL features
        data['url_length'] = np.random.normal(50, 20, n_samples).clip(10, 200)
        data['path_depth'] = np.random.poisson(2, n_samples).clip(0, 10)
        data['query_params_count'] = np.random.poisson(1, n_samples).clip(0, 10)
        data['fragment_exists'] = np.random.binomial(1, 0.2, n_samples)
        data['suspicious_keywords'] = np.random.poisson(0.5, n_samples).clip(0, 5)
        data['phishing_keywords'] = np.random.poisson(0.3, n_samples).clip(0, 5)
        data['brand_impersonation'] = np.random.binomial(1, 0.05, n_samples)
        data['redirect_count'] = np.random.poisson(0.5, n_samples).clip(0, 5)
        data['response_time_ms'] = np.random.exponential(500, n_samples).clip(50, 10000)
        
        # Content features
        data['form_count'] = np.random.poisson(1, n_samples).clip(0, 10)
        data['input_field_count'] = np.random.poisson(2, n_samples).clip(0, 20)
        data['external_links_count'] = np.random.poisson(5, n_samples).clip(0, 50)
        data['suspicious_file_extensions'] = np.random.poisson(0.1, n_samples).clip(0, 3)
        data['crypto_mining_scripts'] = np.random.binomial(1, 0.01, n_samples)
        data['social_engineering_indicators'] = np.random.poisson(0.2, n_samples).clip(0, 3)
        data['urgency_language'] = np.random.binomial(1, 0.1, n_samples)
        data['trust_indicators_missing'] = np.random.binomial(1, 0.3, n_samples)
        
        # Create threat labels based on feature combinations
        threat_score = (
            data['homoglyph_score'] * 0.3 +
            data['typosquatting_score'] * 0.3 +
            data['dga_score'] * 0.2 +
            data['suspicious_tld'] * 0.1 +
            data['dynamic_dns'] * 0.1 +
            np.random.normal(0, 0.1, n_samples)  # Add noise
        ).clip(0, 1)
        
        data['is_threat'] = (threat_score > 0.5).astype(int)
        data['probability'] = threat_score
        
        # Create DataFrame and save
        df = pd.DataFrame(data)
        os.makedirs(os.path.dirname(csv_path) if os.path.dirname(csv_path) else '.', exist_ok=True)
        df.to_csv(csv_path, index=False)
        print(f"Created sample data with {len(df)} samples")
    
    def train_teacher_model(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
        """Train the teacher model (complex ensemble)"""
        print("Training teacher model (Random Forest)...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Train Random Forest as teacher
        teacher = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        teacher.fit(X_train_scaled, y_train)
        
        # Evaluate teacher
        y_pred = teacher.predict(X_val_scaled)
        y_prob = teacher.predict_proba(X_val_scaled)[:, 1]
        
        print(f"Teacher model accuracy: {accuracy_score(y_val, y_pred):.4f}")
        print(f"Teacher model AUC: {roc_auc_score(y_val, y_prob):.4f}")
        
        self.teacher_model = teacher
        return teacher
    
    def distill_student_model(self, X: np.ndarray, y: np.ndarray) -> LogisticRegression:
        """Distill knowledge into a simple student model"""
        print("Distilling student model (Logistic Regression)...")
        
        if self.teacher_model is None:
            raise ValueError("Teacher model must be trained first")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Get soft labels from teacher
        teacher_probs = self.teacher_model.predict_proba(X_train_scaled)[:, 1]
        
        # Train student model using teacher's soft labels
        student = LogisticRegression(
            penalty='l2',
            C=1.0,
            max_iter=1000,
            random_state=42
        )
        
        # Use teacher probabilities as targets for distillation
        student.fit(X_train_scaled, teacher_probs > 0.5)
        
        # Evaluate student
        y_pred = student.predict(X_val_scaled)
        y_prob = student.predict_proba(X_val_scaled)[:, 1]
        
        print(f"Student model accuracy: {accuracy_score(y_val, y_pred):.4f}")
        print(f"Student model AUC: {roc_auc_score(y_val, y_prob):.4f}")
        
        # Compare with teacher on validation set
        teacher_val_pred = self.teacher_model.predict(X_val_scaled)
        teacher_val_prob = self.teacher_model.predict_proba(X_val_scaled)[:, 1]
        
        print(f"Teacher validation accuracy: {accuracy_score(y_val, teacher_val_pred):.4f}")
        print(f"Teacher validation AUC: {roc_auc_score(y_val, teacher_val_prob):.4f}")
        
        self.student_model = student
        return student
    
    def export_student_model(self, output_path: str):
        """Export student model in JSON format for Rust engine"""
        if self.student_model is None:
            raise ValueError("Student model must be trained first")
        
        print(f"Exporting student model to {output_path}...")
        
        # Extract model parameters
        weights = self.student_model.coef_[0].tolist()
        bias = float(self.student_model.intercept_[0])
        
        # Create model export
        model_data = {
            "weights": weights,
            "bias": bias,
            "feature_names": self.feature_names,
            "version": f"distilled_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "created_at": datetime.now().isoformat(),
            "training_info": {
                "model_type": "logistic_regression",
                "distillation": True,
                "teacher_model": "random_forest",
                "feature_count": len(weights),
                "regularization": "l2"
            }
        }
        
        # Save to JSON
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(model_data, f, indent=2)
        
        print(f"Student model exported successfully")
        print(f"Model has {len(weights)} features")
        print(f"Top 10 most important features:")
        
        # Show feature importance (absolute weights)
        feature_importance = list(zip(self.feature_names, np.abs(weights)))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        for i, (feature, weight) in enumerate(feature_importance[:10]):
            print(f"  {i+1:2d}. {feature:25s}: {weight:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Train and distill student threat detection model")
    parser.add_argument("--input", "-i", required=True, help="Input CSV file with training data")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file for student model")
    parser.add_argument("--sample-data", action="store_true", help="Create sample data if input doesn't exist")
    
    args = parser.parse_args()
    
    trainer = StudentModelTrainer()
    
    try:
        # Load training data
        X, y = trainer.load_data(args.input)
        
        # Train teacher model
        trainer.train_teacher_model(X, y)
        
        # Distill student model
        trainer.distill_student_model(X, y)
        
        # Export student model
        trainer.export_student_model(args.output)
        
        print("\nTraining completed successfully!")
        print(f"Student model saved to: {args.output}")
        
    except Exception as e:
        print(f"Error during training: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())