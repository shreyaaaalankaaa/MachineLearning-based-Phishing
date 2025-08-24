import os
import logging
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from feature_extractor import URLFeatureExtractor
import json
from typing import Tuple, Dict, Any, Optional

class PhishingDetectionPipeline:
    """Complete ML pipeline for phishing URL detection."""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.logger = logging.getLogger(__name__)
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.feature_names = self.feature_extractor.get_feature_names()
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        self._load_model()
    
    def prepare_data(self, urls: list, labels: list) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data by extracting features from URLs."""
        self.logger.info(f"Preparing data for {len(urls)} URLs...")
        
        features_list = []
        valid_indices = []
        
        for i, url in enumerate(urls):
            try:
                features = self.feature_extractor.extract_features(url)
                features_list.append([features[name] for name in self.feature_names])
                valid_indices.append(i)
            except Exception as e:
                self.logger.warning(f"Skipping URL {i} due to feature extraction error: {e}")
        
        if not features_list:
            raise ValueError("No valid URLs could be processed for feature extraction")
        
        X = np.array(features_list)
        y = np.array([labels[i] for i in valid_indices])
        
        self.logger.info(f"Prepared {X.shape[0]} samples with {X.shape[1]} features")
        return X, y
    
    def train_model(self, urls: list, labels: list, test_size: float = 0.2) -> Dict[str, Any]:
        """Train the phishing detection model."""
        self.logger.info("Starting model training...")
        
        # Prepare data
        X, y = self.prepare_data(urls, labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        train_accuracy = self.model.score(X_train_scaled, y_train)
        test_accuracy = self.model.score(X_test_scaled, y_test)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        
        # Predictions for detailed metrics
        y_pred = self.model.predict(X_test_scaled)
        
        # Classification report
        class_report = classification_report(y_test, y_pred, output_dict=True)
        
        # Feature importance
        feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
        top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
        
        self.is_trained = True
        
        # Save model
        self._save_model()
        
        results = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': class_report,
            'top_features': top_features,
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'n_samples': len(X),
            'n_features': len(self.feature_names)
        }
        
        self.logger.info(f"Model training completed. Test accuracy: {test_accuracy:.4f}")
        return results
    
    def predict(self, url: str) -> Dict[str, Any]:
        """Predict if a URL is phishing or legitimate."""
        if not self.is_trained:
            return {
                'error': 'Model is not trained. Please train the model first.',
                'prediction': None,
                'confidence': 0.0,
                'features': {}
            }
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(url)
            feature_vector = np.array([[features[name] for name in self.feature_names]])
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Make prediction
            prediction = self.model.predict(feature_vector_scaled)[0]
            probabilities = self.model.predict_proba(feature_vector_scaled)[0]
            
            # Get confidence (probability of predicted class)
            confidence = float(probabilities[prediction])
            
            # Determine label
            label = 'phishing' if prediction == 1 else 'legitimate'
            
            result = {
                'prediction': label,
                'confidence': confidence,
                'probabilities': {
                    'legitimate': float(probabilities[0]),
                    'phishing': float(probabilities[1])
                },
                'features': features,
                'url': url
            }
            
            self.logger.info(f"Prediction for {url}: {label} (confidence: {confidence:.4f})")
            return result
            
        except Exception as e:
            self.logger.error(f"Error making prediction for {url}: {e}")
            return {
                'error': f'Error making prediction: {str(e)}',
                'prediction': None,
                'confidence': 0.0,
                'features': {}
            }
    
    def predict_batch(self, urls: list) -> list:
        """Predict multiple URLs at once."""
        return [self.predict(url) for url in urls]
    
    def _save_model(self):
        """Save the trained model and scaler."""
        if self.model is None or self.scaler is None:
            self.logger.warning("Cannot save model: model or scaler is None")
            return
        
        try:
            model_path = os.path.join(self.model_dir, 'phishing_model.joblib')
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            metadata_path = os.path.join(self.model_dir, 'model_metadata.json')
            
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'model_type': 'RandomForestClassifier',
                'is_trained': self.is_trained
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("Model saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def _load_model(self):
        """Load existing model and scaler if available."""
        try:
            model_path = os.path.join(self.model_dir, 'phishing_model.joblib')
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            metadata_path = os.path.join(self.model_dir, 'model_metadata.json')
            
            if all(os.path.exists(path) for path in [model_path, scaler_path, metadata_path]):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                self.feature_names = metadata.get('feature_names', self.feature_names)
                self.is_trained = metadata.get('is_trained', False)
                
                self.logger.info("Model loaded successfully")
            else:
                self.logger.info("No existing model found")
                
        except Exception as e:
            self.logger.warning(f"Error loading model: {e}")
            self.model = None
            self.scaler = None
            self.is_trained = False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        info = {
            'is_trained': self.is_trained,
            'feature_count': len(self.feature_names),
            'model_type': 'RandomForestClassifier' if self.model else None
        }
        
        if self.is_trained and self.model:
            info.update({
                'n_estimators': self.model.n_estimators,
                'max_depth': self.model.max_depth,
                'feature_names': self.feature_names[:10]  # First 10 features
            })
        
        return info

# Global pipeline instance
pipeline = PhishingDetectionPipeline()
