"""Anomaly detection implementations for security analysis."""

import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import joblib
import os

from backend.detectors.base import MLDetector, DetectionResult, DetectionSeverity
from backend.core.logging import get_logger


class NetworkAnomalyDetector(MLDetector):
    """Detects anomalies in network traffic patterns."""
    
    def __init__(self, model_path: Optional[str] = None):
        super().__init__(
            id="network_anomaly",
            name="Network Anomaly Detector",
            description="Detects anomalous network traffic patterns using Isolation Forest",
            model_path=model_path
        )
        self.scaler = StandardScaler()
        self.feature_columns = [
            'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'duration', 'port', 'protocol_tcp', 'protocol_udp', 'protocol_icmp'
        ]
        
    async def load_model(self) -> None:
        """Load the trained model and scaler."""
        try:
            if self.model_path and os.path.exists(self.model_path):
                self.model = joblib.load(f"{self.model_path}/network_anomaly_model.pkl")
                self.scaler = joblib.load(f"{self.model_path}/network_anomaly_scaler.pkl")
                self.logger.info("Network anomaly model loaded successfully")
            else:
                # Initialize with default parameters
                self.model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                self.logger.info("Initialized new network anomaly model")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    async def save_model(self) -> None:
        """Save the trained model and scaler."""
        try:
            if self.model_path:
                os.makedirs(self.model_path, exist_ok=True)
                joblib.dump(self.model, f"{self.model_path}/network_anomaly_model.pkl")
                joblib.dump(self.scaler, f"{self.model_path}/network_anomaly_scaler.pkl")
                self.logger.info("Network anomaly model saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            raise
    
    def _preprocess_data(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Preprocess network data for anomaly detection."""
        df = pd.DataFrame(data)
        
        # Create protocol dummy variables
        df['protocol_tcp'] = (df.get('protocol', '').str.lower() == 'tcp').astype(int)
        df['protocol_udp'] = (df.get('protocol', '').str.lower() == 'udp').astype(int)
        df['protocol_icmp'] = (df.get('protocol', '').str.lower() == 'icmp').astype(int)
        
        # Fill missing values
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
            df[col] = df[col].fillna(0)
        
        # Select and scale features
        features = df[self.feature_columns].values
        return self.scaler.fit_transform(features)
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process network data and detect anomalies."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            if not data:
                return []
            
            # Preprocess data
            features = self._preprocess_data(data)
            
            # Predict anomalies
            anomaly_scores = self.model.decision_function(features)
            predictions = self.model.predict(features)
            
            results = []
            for i, (score, prediction) in enumerate(zip(anomaly_scores, predictions)):
                if prediction == -1:  # Anomaly detected
                    confidence = min(abs(score) / 2.0, 1.0)  # Normalize score to confidence
                    
                    # Determine severity based on confidence
                    if confidence >= 0.9:
                        severity = DetectionSeverity.CRITICAL
                    elif confidence >= 0.7:
                        severity = DetectionSeverity.HIGH
                    elif confidence >= 0.5:
                        severity = DetectionSeverity.MEDIUM
                    else:
                        severity = DetectionSeverity.LOW
                    
                    result = DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=severity,
                        confidence=confidence,
                        description=f"Anomalous network traffic detected with score {score:.3f}",
                        raw_data=data[i],
                        entities=[data[i].get('src_ip', ''), data[i].get('dst_ip', '')],
                        tactics=["Discovery", "Lateral Movement"],
                        techniques=["T1046", "T1021"],
                        tags=["network", "anomaly", "traffic"],
                        metadata={
                            "anomaly_score": float(score),
                            "feature_importance": self._get_feature_importance(features[i])
                        }
                    )
                    results.append(result)
                    self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing data: {e}")
            raise
    
    def _get_feature_importance(self, features: np.ndarray) -> Dict[str, float]:
        """Get feature importance for the anomaly."""
        importance = {}
        for i, col in enumerate(self.feature_columns):
            if i < len(features):
                importance[col] = float(features[i])
        return importance
    
    async def train(self, training_data: Any) -> None:
        """Train the anomaly detection model."""
        try:
            if not isinstance(training_data, list):
                training_data = [training_data]
            
            # Preprocess training data
            features = self._preprocess_data(training_data)
            
            # Train the model
            self.model.fit(features)
            
            self.logger.info(f"Model trained on {len(training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "contamination": getattr(self.model, 'contamination', 0.1),
            "n_estimators": getattr(self.model, 'n_estimators', 100),
            "threshold": self.threshold,
            "feature_columns": self.feature_columns
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "contamination" in config:
            self.model.contamination = config["contamination"]
        if "n_estimators" in config:
            self.model.n_estimators = config["n_estimators"]
        if "threshold" in config:
            self.set_threshold(config["threshold"])


class UserBehaviorAnomalyDetector(MLDetector):
    """Detects anomalies in user behavior patterns."""
    
    def __init__(self, model_path: Optional[str] = None):
        super().__init__(
            id="user_behavior_anomaly",
            name="User Behavior Anomaly Detector",
            description="Detects anomalous user behavior using clustering and statistical analysis",
            model_path=model_path
        )
        self.user_profiles = {}
        self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
        
    async def load_model(self) -> None:
        """Load user behavior models."""
        try:
            if self.model_path and os.path.exists(self.model_path):
                self.user_profiles = joblib.load(f"{self.model_path}/user_profiles.pkl")
                self.clustering_model = joblib.load(f"{self.model_path}/clustering_model.pkl")
                self.logger.info("User behavior models loaded successfully")
            else:
                self.user_profiles = {}
                self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
                self.logger.info("Initialized new user behavior models")
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            raise
    
    async def save_model(self) -> None:
        """Save user behavior models."""
        try:
            if self.model_path:
                os.makedirs(self.model_path, exist_ok=True)
                joblib.dump(self.user_profiles, f"{self.model_path}/user_profiles.pkl")
                joblib.dump(self.clustering_model, f"{self.model_path}/clustering_model.pkl")
                self.logger.info("User behavior models saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
            raise
    
    def _extract_user_features(self, user_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral features from user data."""
        features = {
            'login_hour': float(user_data.get('login_hour', 0)),
            'session_duration': float(user_data.get('session_duration', 0)),
            'failed_logins': float(user_data.get('failed_logins', 0)),
            'unique_ips': float(user_data.get('unique_ips', 1)),
            'data_accessed_mb': float(user_data.get('data_accessed_mb', 0)),
            'privileged_actions': float(user_data.get('privileged_actions', 0)),
            'weekend_activity': float(user_data.get('weekend_activity', 0)),
            'off_hours_activity': float(user_data.get('off_hours_activity', 0))
        }
        return features
    
    def _calculate_anomaly_score(self, user_id: str, features: Dict[str, float]) -> float:
        """Calculate anomaly score for user behavior."""
        if user_id not in self.user_profiles:
            return 0.5  # Neutral score for new users
        
        profile = self.user_profiles[user_id]
        score = 0.0
        
        for feature, value in features.items():
            if feature in profile:
                mean = profile[feature]['mean']
                std = profile[feature]['std']
                if std > 0:
                    z_score = abs((value - mean) / std)
                    score += min(z_score / 3.0, 1.0)  # Normalize to 0-1
        
        return min(score / len(features), 1.0)
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process user behavior data and detect anomalies."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            results = []
            for user_data in data:
                user_id = user_data.get('user_id')
                if not user_id:
                    continue
                
                features = self._extract_user_features(user_data)
                anomaly_score = self._calculate_anomaly_score(user_id, features)
                
                if anomaly_score > self.threshold:
                    # Determine severity
                    if anomaly_score >= 0.9:
                        severity = DetectionSeverity.CRITICAL
                    elif anomaly_score >= 0.7:
                        severity = DetectionSeverity.HIGH
                    elif anomaly_score >= 0.5:
                        severity = DetectionSeverity.MEDIUM
                    else:
                        severity = DetectionSeverity.LOW
                    
                    result = DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=severity,
                        confidence=anomaly_score,
                        description=f"Anomalous behavior detected for user {user_id}",
                        raw_data=user_data,
                        entities=[user_id],
                        tactics=["Initial Access", "Persistence", "Privilege Escalation"],
                        techniques=["T1078", "T1098", "T1548"],
                        tags=["user", "behavior", "anomaly"],
                        metadata={
                            "anomaly_score": anomaly_score,
                            "features": features,
                            "baseline_profile": self.user_profiles.get(user_id, {})
                        }
                    )
                    results.append(result)
                    self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing user behavior data: {e}")
            raise
    
    async def train(self, training_data: Any) -> None:
        """Train user behavior profiles."""
        try:
            if not isinstance(training_data, list):
                training_data = [training_data]
            
            # Group data by user
            user_data = {}
            for record in training_data:
                user_id = record.get('user_id')
                if user_id:
                    if user_id not in user_data:
                        user_data[user_id] = []
                    user_data[user_id].append(self._extract_user_features(record))
            
            # Build profiles for each user
            for user_id, features_list in user_data.items():
                df = pd.DataFrame(features_list)
                profile = {}
                for column in df.columns:
                    profile[column] = {
                        'mean': float(df[column].mean()),
                        'std': float(df[column].std()),
                        'min': float(df[column].min()),
                        'max': float(df[column].max())
                    }
                self.user_profiles[user_id] = profile
            
            self.logger.info(f"Trained profiles for {len(user_data)} users")
            
        except Exception as e:
            self.logger.error(f"Error training user behavior model: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "threshold": self.threshold,
            "eps": self.clustering_model.eps,
            "min_samples": self.clustering_model.min_samples,
            "num_profiles": len(self.user_profiles)
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "threshold" in config:
            self.set_threshold(config["threshold"])
        if "eps" in config:
            self.clustering_model.eps = config["eps"]
        if "min_samples" in config:
            self.clustering_model.min_samples = config["min_samples"]


class TimeSeriesAnomalyDetector(MLDetector):
    """Detects anomalies in time series security data."""
    
    def __init__(self, model_path: Optional[str] = None):
        super().__init__(
            id="timeseries_anomaly",
            name="Time Series Anomaly Detector",
            description="Detects anomalies in time series security metrics",
            model_path=model_path
        )
        self.window_size = 24  # Hours
        self.seasonal_period = 168  # Weekly pattern (24 * 7)
        
    async def load_model(self) -> None:
        """Load time series model."""
        try:
            if self.model_path and os.path.exists(self.model_path):
                self.model = joblib.load(f"{self.model_path}/timeseries_model.pkl")
                self.logger.info("Time series model loaded successfully")
            else:
                self.model = IsolationForest(contamination=0.1, random_state=42)
                self.logger.info("Initialized new time series model")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    async def save_model(self) -> None:
        """Save time series model."""
        try:
            if self.model_path:
                os.makedirs(self.model_path, exist_ok=True)
                joblib.dump(self.model, f"{self.model_path}/timeseries_model.pkl")
                self.logger.info("Time series model saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            raise
    
    def _create_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Create time series features."""
        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Create time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        
        # Create rolling statistics
        df['value_rolling_mean'] = df['value'].rolling(window=self.window_size).mean()
        df['value_rolling_std'] = df['value'].rolling(window=self.window_size).std()
        
        # Create lag features
        for lag in [1, 24, 168]:  # 1 hour, 1 day, 1 week
            df[f'value_lag_{lag}'] = df['value'].shift(lag)
        
        # Fill missing values
        df = df.fillna(method='bfill').fillna(0)
        
        feature_columns = [
            'value', 'hour', 'day_of_week', 'is_weekend',
            'value_rolling_mean', 'value_rolling_std',
            'value_lag_1', 'value_lag_24', 'value_lag_168'
        ]
        
        return df[feature_columns].values
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process time series data and detect anomalies."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            if len(data) < self.window_size:
                return []  # Need enough data for analysis
            
            # Create features
            features = self._create_features(data)
            
            # Predict anomalies
            anomaly_scores = self.model.decision_function(features)
            predictions = self.model.predict(features)
            
            results = []
            for i, (score, prediction) in enumerate(zip(anomaly_scores, predictions)):
                if prediction == -1:  # Anomaly detected
                    confidence = min(abs(score) / 2.0, 1.0)
                    
                    if confidence >= 0.8:
                        severity = DetectionSeverity.HIGH
                    elif confidence >= 0.6:
                        severity = DetectionSeverity.MEDIUM
                    else:
                        severity = DetectionSeverity.LOW
                    
                    result = DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=severity,
                        confidence=confidence,
                        description=f"Time series anomaly detected at {data[i].get('timestamp')}",
                        raw_data=data[i],
                        entities=[],
                        tactics=["Discovery"],
                        techniques=["T1082"],
                        tags=["timeseries", "anomaly", "metrics"],
                        metadata={
                            "anomaly_score": float(score),
                            "timestamp": data[i].get('timestamp'),
                            "value": data[i].get('value')
                        }
                    )
                    results.append(result)
                    self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing time series data: {e}")
            raise
    
    async def train(self, training_data: Any) -> None:
        """Train the time series model."""
        try:
            if not isinstance(training_data, list):
                training_data = [training_data]
            
            features = self._create_features(training_data)
            self.model.fit(features)
            
            self.logger.info(f"Time series model trained on {len(training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error training time series model: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "threshold": self.threshold,
            "window_size": self.window_size,
            "seasonal_period": self.seasonal_period,
            "contamination": getattr(self.model, 'contamination', 0.1)
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "threshold" in config:
            self.set_threshold(config["threshold"])
        if "window_size" in config:
            self.window_size = config["window_size"]
        if "seasonal_period" in config:
            self.seasonal_period = config["seasonal_period"] 