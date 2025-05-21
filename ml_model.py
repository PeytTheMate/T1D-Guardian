import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, accuracy_score
import joblib
from datetime import datetime, timedelta

class DiabetesModel:
    """
    Machine learning models for diabetes prediction and analysis.
    Includes both regression (glucose prediction) and classification (hypoglycemia risk)
    """
    
    def __init__(self):
        # Initialize models
        self.glucose_predictor = RandomForestRegressor(n_estimators=100, random_state=42)
        self.hypo_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        
        # Feature lists
        self.predictor_features = [
            'glucose', 'glucose_rate', 'glucose_acceleration',
            'glucose_rolling_15min', 'glucose_rolling_1hr',
            'glucose_variability_1hr', 'hour', 'day_of_week',
            'is_overnight'
        ]
        
        # Model status
        self.is_trained = False
    
    def train(self, processed_data):
        """
        Train both glucose prediction and hypoglycemia risk models
        
        Parameters:
        processed_data (pd.DataFrame): Processed Dexcom data with engineered features
        
        Returns:
        dict: Training performance metrics
        """
        if processed_data.empty:
            raise ValueError("Cannot train model on empty dataset")
        
        # Create copies to avoid warnings
        data = processed_data.copy()
        
        # Prepare data for glucose prediction (30 min forecast)
        X_glucose = self._prepare_glucose_prediction_data(data)
        
        # Prepare data for hypoglycemia prediction
        X_hypo = self._prepare_hypoglycemia_prediction_data(data)
        
        if X_glucose is None or X_hypo is None:
            raise ValueError("Insufficient data for training models")
        
        # Train glucose prediction model
        glucose_metrics = self._train_glucose_model(X_glucose)
        
        # Train hypoglycemia prediction model
        hypo_metrics = self._train_hypoglycemia_model(X_hypo)
        
        self.is_trained = True
        
        return {
            "glucose_prediction": glucose_metrics,
            "hypoglycemia_prediction": hypo_metrics
        }
    
    def _prepare_glucose_prediction_data(self, data):
        """Prepare data for glucose prediction model"""
        if len(data) < 12:  # Need at least an hour of data
            return None
        
        # Create target: glucose value 30 minutes ahead (6 readings at 5-min intervals)
        data['future_glucose'] = data['glucose'].shift(-6)
        
        # Drop rows with NaN in target
        data_clean = data.dropna(subset=['future_glucose'])
        
        if len(data_clean) < 10:  # Need sufficient data after shifting
            return None
        
        # Select features and target
        X = data_clean[self.predictor_features].copy()
        y = data_clean['future_glucose'].copy()
        
        return (X, y)
    
    def _prepare_hypoglycemia_prediction_data(self, data):
        """Prepare data for hypoglycemia prediction model"""
        if len(data) < 12:  # Need at least an hour of data
            return None
        
        # Create binary target: will glucose go below 70 mg/dL in next 30 minutes?
        window_size = 6  # 30 minutes (6 readings at 5-min intervals)
        data['future_hypo'] = data['glucose'].rolling(window=window_size, min_periods=1).min().shift(-window_size) < 70
        data['future_hypo'] = data['future_hypo'].fillna(False).astype(int)
        
        # Drop rows with NaN in features
        data_clean = data.dropna(subset=self.predictor_features)
        
        if len(data_clean) < 10:  # Need sufficient data after preprocessing
            return None
        
        # Select features and target
        X = data_clean[self.predictor_features].copy()
        y = data_clean['future_hypo'].copy()
        
        return (X, y)
    
    def _train_glucose_model(self, data_tuple):
        """Train the glucose prediction model"""
        X, y = data_tuple
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.glucose_predictor.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.glucose_predictor.predict(X_test_scaled)
        rmse = np.sqrt(mean_squared_error(y_test, y_pred))
        
        return {
            "rmse": rmse,
            "test_size": len(X_test)
        }
    
    def _train_hypoglycemia_model(self, data_tuple):
        """Train the hypoglycemia prediction model"""
        X, y = data_tuple
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features (use the same scaler as for glucose prediction)
        X_train_scaled = self.scaler.transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.hypo_predictor.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.hypo_predictor.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Calculate class distribution (important for imbalanced data)
        class_distribution = {
            "hypo_events": int(y.sum()),
            "total_events": len(y)
        }
        
        return {
            "accuracy": accuracy,
            "class_distribution": class_distribution,
            "test_size": len(X_test)
        }
    
    def predict_glucose(self, current_data):
        """
        Predict glucose level 30 minutes in the future
        
        Parameters:
        current_data (pd.DataFrame): Recent glucose data with engineered features
        
        Returns:
        float: Predicted glucose value (mg/dL)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Please train the model first.")
        
        if current_data.empty:
            raise ValueError("Cannot make prediction with empty data")
        
        # Get the most recent data point with all required features
        latest_data = current_data.tail(1)
        
        # Ensure all needed features are present
        missing_features = [f for f in self.predictor_features if f not in latest_data.columns]
        if missing_features:
            raise ValueError(f"Missing features for prediction: {missing_features}")
        
        # Extract features and scale
        X = latest_data[self.predictor_features].values
        X_scaled = self.scaler.transform(X)
        
        # Make prediction
        predicted_glucose = self.glucose_predictor.predict(X_scaled)[0]
        
        return predicted_glucose
    
    def predict_hypoglycemia_risk(self, current_data):
        """
        Predict risk of hypoglycemia in the next 30 minutes
        
        Parameters:
        current_data (pd.DataFrame): Recent glucose data with engineered features
        
        Returns:
        dict: Prediction result with risk probability and binary classification
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Please train the model first.")
        
        if current_data.empty:
            raise ValueError("Cannot make prediction with empty data")
        
        # Get the most recent data point with all required features
        latest_data = current_data.tail(1)
        
        # Ensure all needed features are present
        missing_features = [f for f in self.predictor_features if f not in latest_data.columns]
        if missing_features:
            raise ValueError(f"Missing features for prediction: {missing_features}")
        
        # Extract features and scale
        X = latest_data[self.predictor_features].values
        X_scaled = self.scaler.transform(X)
        
        # Predict probability
        risk_prob = self.hypo_predictor.predict_proba(X_scaled)[0][1]  # Probability of class 1 (hypo)
        
        # Binary prediction (will/won't go low)
        will_go_low = self.hypo_predictor.predict(X_scaled)[0]
        
        return {
            "risk_probability": risk_prob,
            "predicted_hypoglycemia": bool(will_go_low)
        }
    
    def generate_insights(self, data):
        """
        Generate personalized insights based on glucose data
        
        Parameters:
        data (pd.DataFrame): Processed glucose data
        
        Returns:
        dict: Dictionary of insights
        """
        if data.empty:
            return {"error": "No data available for insights"}
        
        insights = {}
        
        # Calculate time in range
        in_range_pct = (data['glucose'].between(70, 180).mean() * 100)
        below_range_pct = (data['glucose'] < 70).mean() * 100
        above_range_pct = (data['glucose'] > 180).mean() * 100
        
        insights["time_in_range"] = {
            "in_range": round(in_range_pct, 1),
            "below_range": round(below_range_pct, 1),
            "above_range": round(above_range_pct, 1)
        }
        
        # Calculate glucose variability
        cv = data['glucose'].std() / data['glucose'].mean() * 100
        insights["glucose_variability"] = {
            "coefficient_of_variation": round(cv, 1),
            "standard_deviation": round(data['glucose'].std(), 1)
        }
        
        # Identify problem times of day
        hours = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]
        hourly_avg = [data[data.index.hour == hour]['glucose'].mean() for hour in hours]
        hourly_lows = [data[(data.index.hour == hour) & (data['glucose'] < 70)].shape[0] for hour in hours]
        
        problem_hours = []
        for hour, avg, lows in zip(hours, hourly_avg, hourly_lows):
            if avg > 180 or avg < 70 or lows > 0:
                time_str = f"{hour}:00-{(hour+1)%24}:00"
                status = "high" if avg > 180 else "low" if avg < 70 else "normal"
                problem_hours.append({
                    "time_range": time_str,
                    "avg_glucose": round(avg, 1),
                    "status": status,
                    "low_events": lows
                })
        
        insights["problem_times"] = problem_hours
        
        # Personalized recommendations
        recommendations = []
        
        if below_range_pct > 4:
            recommendations.append("Your time below range is higher than recommended. Consider adjusting your insulin dosing or discussing with your healthcare provider.")
        
        if above_range_pct > 25:
            recommendations.append("Your time above range is higher than ideal. Consider reviewing carb counting or insulin timing.")
        
        if cv > 36:
            recommendations.append("Your glucose variability is high. More consistent meal timing or adjusting insulin strategies may help reduce swings.")
        
        if problem_hours and any(h['status'] == 'low' for h in problem_hours):
            low_times = [h['time_range'] for h in problem_hours if h['status'] == 'low']
            recommendations.append(f"You tend to go low during: {', '.join(low_times)}. Consider adjusting insulin or having a snack before these times.")
        
        insights["recommendations"] = recommendations
        
        return insights
