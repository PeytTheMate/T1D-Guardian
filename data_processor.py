import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def preprocess_dexcom_data(df):
    """
    Preprocess Dexcom CGM data:
    - Handle missing values
    - Convert timestamps to datetime
    - Standardize column names
    - Sort by timestamp
    
    Args:
        df (pd.DataFrame): Raw Dexcom data
    
    Returns:
        pd.DataFrame: Preprocessed data
    """
    # Create a copy to avoid modifying the original
    processed_df = df.copy()
    
    # Detect Dexcom format and standardize column names
    # Common Dexcom column names: 'Timestamp', 'Glucose Value (mg/dL)', 'Event Type'
    # Or: 'timestamp', 'glucose', 'event_type'
    
    # Identify glucose column
    glucose_cols = [col for col in processed_df.columns if 'glucose' in col.lower() or 'mg/dl' in col.lower()]
    if glucose_cols:
        processed_df.rename(columns={glucose_cols[0]: 'glucose_value'}, inplace=True)
    else:
        # If no clear glucose column, try to infer from data types
        numeric_cols = processed_df.select_dtypes(include=['int64', 'float64']).columns
        if len(numeric_cols) > 0:
            processed_df.rename(columns={numeric_cols[0]: 'glucose_value'}, inplace=True)
        else:
            raise ValueError("Could not identify glucose value column in the data")
    
    # Identify timestamp column
    time_cols = [col for col in processed_df.columns if 'time' in col.lower() or 'date' in col.lower()]
    if time_cols:
        processed_df.rename(columns={time_cols[0]: 'timestamp'}, inplace=True)
    else:
        # If no clear timestamp column, try first column as a default
        processed_df.rename(columns={processed_df.columns[0]: 'timestamp'}, inplace=True)
    
    # Convert timestamp to datetime
    try:
        processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'])
    except:
        # Try different format if the default doesn't work
        try:
            processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'], format='%Y-%m-%d %H:%M:%S')
        except:
            raise ValueError("Could not convert timestamp column to datetime format")
    
    # Sort by timestamp
    processed_df.sort_values('timestamp', inplace=True)
    
    # Handle missing glucose values
    processed_df['glucose_value'] = pd.to_numeric(processed_df['glucose_value'], errors='coerce')
    
    # Remove rows with NaN glucose values
    processed_df = processed_df.dropna(subset=['glucose_value'])
    
    # Reset index
    processed_df.reset_index(drop=True, inplace=True)
    
    return processed_df

def engineer_features(df):
    """
    Engineer additional features for glucose analysis:
    - Rate of change (mg/dL per minute)
    - Moving averages
    - Time-based features
    
    Args:
        df (pd.DataFrame): Preprocessed Dexcom data
    
    Returns:
        pd.DataFrame: Enhanced dataframe with additional features
    """
    # Create a copy to avoid modifying the original
    enhanced_df = df.copy()
    
    # Calculate time differences in minutes
    enhanced_df['time_diff'] = enhanced_df['timestamp'].diff().dt.total_seconds() / 60
    
    # Calculate glucose rate of change (mg/dL per minute)
    enhanced_df['glucose_diff'] = enhanced_df['glucose_value'].diff()
    enhanced_df['glucose_rate_of_change'] = enhanced_df['glucose_diff'] / enhanced_df['time_diff']
    
    # Replace infinite values with NaN and then drop or fill
    enhanced_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    enhanced_df['glucose_rate_of_change'].fillna(0, inplace=True)
    
    # Calculate moving averages
    enhanced_df['glucose_ma_15'] = enhanced_df['glucose_value'].rolling(window=3, min_periods=1).mean()  # ~15 min
    enhanced_df['glucose_ma_60'] = enhanced_df['glucose_value'].rolling(window=12, min_periods=1).mean() # ~60 min
    
    # Calculate glucose variability (standard deviation)
    enhanced_df['glucose_variability'] = enhanced_df['glucose_value'].rolling(window=12, min_periods=1).std()
    
    # Extract time-based features
    enhanced_df['hour_of_day'] = enhanced_df['timestamp'].dt.hour
    enhanced_df['day_of_week'] = enhanced_df['timestamp'].dt.dayofweek
    enhanced_df['is_weekend'] = enhanced_df['day_of_week'].isin([5, 6]).astype(int)
    
    # Categorize glucose values according to ranges
    enhanced_df['glucose_category'] = pd.cut(
        enhanced_df['glucose_value'], 
        bins=[0, 54, 70, 180, 250, 9999],
        labels=['Very Low', 'Low', 'In Range', 'High', 'Very High']
    )
    
    return enhanced_df
