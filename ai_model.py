import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, accuracy_score
from sklearn.pipeline import Pipeline

def prepare_features(df, target_column='glucose_value', forecast_minutes=30):
    """
    Prepare features for machine learning model
    
    Args:
        df (pd.DataFrame): Processed and feature-engineered data
        target_column (str): Column to predict
        forecast_minutes (int): How many minutes into the future to predict
    
    Returns:
        tuple: X (features), y (target values)
    """
    # Create future glucose values for prediction target
    # Find average time between readings
    avg_time_diff = df['time_diff'].mean()
    if np.isnan(avg_time_diff) or avg_time_diff == 0:
        avg_time_diff = 5  # Assume 5 min interval if unknown
    
    # Calculate how many rows to shift for the forecast window
    forecast_steps = int(forecast_minutes / avg_time_diff)
    
    # Create target by shifting glucose values
    df['future_glucose'] = df[target_column].shift(-forecast_steps)
    
    # Create binary target for hypoglycemia prediction
    df['future_hypo'] = (df['future_glucose'] < 70).astype(int)
    
    # Drop rows where we don't have future values
    df = df.dropna(subset=['future_glucose', 'future_hypo'])
    
    # Define features for ML model
    feature_columns = [
        'glucose_value',
        'glucose_rate_of_change',
        'glucose_ma_15',
        'glucose_ma_60',
        'glucose_variability',
        'hour_of_day',
        'day_of_week',
        'is_weekend'
    ]
    
    # Filter out any columns that don't exist in the dataframe
    feature_columns = [col for col in feature_columns if col in df.columns]
    
    # Ensure we have at least some features
    if len(feature_columns) < 2:
        # Use what we definitely have
        feature_columns = ['glucose_value']
        if 'hour_of_day' in df.columns:
            feature_columns.append('hour_of_day')
    
    # Create feature matrix and target vector
    X = df[feature_columns].copy()
    y_glucose = df['future_glucose'].copy()
    y_hypo = df['future_hypo'].copy()
    
    return X, y_glucose, y_hypo, feature_columns

def train_model(df):
    """
    Train machine learning models for glucose prediction and hypoglycemia risk
    
    Args:
        df (pd.DataFrame): Processed data with engineered features
    
    Returns:
        dict: Trained models and related information
    """
    # Prepare features and targets
    X, y_glucose, y_hypo, feature_columns = prepare_features(df)
    
    # Split data for training and validation
    X_train, X_test, y_glucose_train, y_glucose_test, y_hypo_train, y_hypo_test = train_test_split(
        X, y_glucose, y_hypo, test_size=0.2, random_state=42
    )
    
    # Create regression model for glucose prediction
    glucose_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', RandomForestRegressor(n_estimators=100, random_state=42))
    ])
    
    # Create classification model for hypoglycemia prediction
    hypo_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    # Train the models
    glucose_pipeline.fit(X_train, y_glucose_train)
    hypo_pipeline.fit(X_train, y_hypo_train)
    
    # Evaluate the models
    glucose_pred = glucose_pipeline.predict(X_test)
    glucose_rmse = np.sqrt(mean_squared_error(y_glucose_test, glucose_pred))
    
    hypo_pred = hypo_pipeline.predict(X_test)
    hypo_accuracy = accuracy_score(y_hypo_test, hypo_pred)
    
    model_info = {
        'glucose_model': glucose_pipeline,
        'hypo_model': hypo_pipeline,
        'feature_columns': feature_columns,
        'performance': {
            'glucose_rmse': glucose_rmse,
            'hypo_accuracy': hypo_accuracy
        }
    }
    
    return model_info

def predict_glucose_future(model_info, new_data, steps=6):
    """
    Predict future glucose values
    
    Args:
        model_info (dict): Model information from train_model
        new_data (pd.DataFrame): Current data for prediction
        steps (int): Number of prediction steps
    
    Returns:
        np.array: Predicted glucose values
    """
    # Get the most recent data
    recent_data = new_data.iloc[-1:].copy()
    feature_columns = model_info['feature_columns']
    
    # Make sure all required features are present
    for column in feature_columns:
        if column not in recent_data.columns:
            if column == 'glucose_rate_of_change':
                recent_data[column] = 0
            elif column == 'glucose_variability':
                recent_data[column] = new_data['glucose_value'].std()
            elif column == 'glucose_ma_15':
                recent_data[column] = new_data['glucose_value'].tail(3).mean()
            elif column == 'glucose_ma_60':
                recent_data[column] = new_data['glucose_value'].tail(12).mean()
            else:
                recent_data[column] = 0
    
    # Make predictions
    X_pred = recent_data[feature_columns]
    predictions = []
    
    for _ in range(steps):
        # Predict next glucose value
        next_glucose = model_info['glucose_model'].predict(X_pred)[0]
        predictions.append(next_glucose)
        
        # Update features for next prediction
        X_pred.loc[:, 'glucose_value'] = next_glucose
        
        # Update other features if they're used
        if 'glucose_ma_15' in feature_columns:
            X_pred.loc[:, 'glucose_ma_15'] = (X_pred.loc[:, 'glucose_ma_15'] * 2 + next_glucose) / 3
        
        if 'glucose_ma_60' in feature_columns:
            X_pred.loc[:, 'glucose_ma_60'] = (X_pred.loc[:, 'glucose_ma_60'] * 11 + next_glucose) / 12
    
    return np.array(predictions)

def predict_hypoglycemia_risk(model_info, new_data):
    """
    Predict risk of hypoglycemia
    
    Args:
        model_info (dict): Model information from train_model
        new_data (pd.DataFrame): Current data for prediction
    
    Returns:
        np.array: Probability of hypoglycemia for each data point
    """
    # Get the feature columns
    feature_columns = model_info['feature_columns']
    
    # Make sure all required features are present
    features = new_data.copy()
    for column in feature_columns:
        if column not in features.columns:
            if column == 'glucose_rate_of_change':
                features[column] = 0
            elif column == 'glucose_variability':
                features[column] = features['glucose_value'].rolling(window=6, min_periods=1).std()
            elif column == 'glucose_ma_15':
                features[column] = features['glucose_value'].rolling(window=3, min_periods=1).mean()
            elif column == 'glucose_ma_60':
                features[column] = features['glucose_value'].rolling(window=12, min_periods=1).mean()
            else:
                features[column] = 0
    
    # Get just the most recent reading for prediction
    X_pred = features.iloc[-6:][feature_columns]
    
    # Predict probability of hypoglycemia
    if hasattr(model_info['hypo_model'], 'predict_proba'):
        risk_probabilities = model_info['hypo_model'].predict_proba(X_pred)[:, 1]
    else:
        # Fall back to binary predictions if probabilities not available
        risk_probabilities = model_info['hypo_model'].predict(X_pred).astype(float)
    
    return risk_probabilities
