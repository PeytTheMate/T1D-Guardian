import pandas as pd
import numpy as np

def display_glucose_stats(df):
    """
    Calculate key glucose statistics from dataframe
    
    Args:
        df (pd.DataFrame): Processed glucose data
    
    Returns:
        dict: Dictionary of glucose statistics
    """
    # Calculate basic statistics
    avg_glucose = df['glucose_value'].mean()
    min_glucose = df['glucose_value'].min()
    max_glucose = df['glucose_value'].max()
    median_glucose = df['glucose_value'].median()
    std_glucose = df['glucose_value'].std()
    
    # Total number of readings
    total_readings = len(df)
    
    # Date range
    start_date = df['timestamp'].min()
    end_date = df['timestamp'].max()
    date_range = (end_date - start_date).total_seconds() / 86400  # Convert to days
    
    # Calculate number of low, in-range, and high readings
    low_readings = (df['glucose_value'] < 70).sum()
    very_low_readings = (df['glucose_value'] < 54).sum()
    in_range_readings = ((df['glucose_value'] >= 70) & (df['glucose_value'] <= 180)).sum()
    high_readings = (df['glucose_value'] > 180).sum()
    very_high_readings = (df['glucose_value'] > 250).sum()
    
    # Calculate percentages
    low_percent = (low_readings / total_readings) * 100
    very_low_percent = (very_low_readings / total_readings) * 100
    in_range_percent = (in_range_readings / total_readings) * 100
    high_percent = (high_readings / total_readings) * 100
    very_high_percent = (very_high_readings / total_readings) * 100
    
    # Calculate GMI (Glucose Management Indicator) - rough estimate of HbA1c
    gmi = 3.31 + (0.02392 * avg_glucose)
    
    # Return statistics as dictionary
    return {
        'avg_glucose': avg_glucose,
        'min_glucose': min_glucose,
        'max_glucose': max_glucose,
        'median_glucose': median_glucose,
        'std_glucose': std_glucose,
        'total_readings': total_readings,
        'date_range_days': date_range,
        'start_date': start_date,
        'end_date': end_date,
        'low_readings': low_readings,
        'very_low_readings': very_low_readings,
        'in_range_readings': in_range_readings,
        'high_readings': high_readings,
        'very_high_readings': very_high_readings,
        'low_percent': low_percent,
        'very_low_percent': very_low_percent,
        'in_range_percent': in_range_percent,
        'high_percent': high_percent,
        'very_high_percent': very_high_percent,
        'gmi': gmi
    }

def time_in_range(df):
    """
    Calculate Time In Range metrics
    
    Args:
        df (pd.DataFrame): Processed glucose data
    
    Returns:
        dict: Dictionary of time in range metrics
    """
    # Count readings in each range
    total = len(df)
    below_range = (df['glucose_value'] < 70).sum()
    in_range = ((df['glucose_value'] >= 70) & (df['glucose_value'] <= 180)).sum()
    above_range = (df['glucose_value'] > 180).sum()
    
    # Calculate percentages
    below_range_pct = (below_range / total) * 100
    in_range_pct = (in_range / total) * 100
    above_range_pct = (above_range / total) * 100
    
    # Additional breakdown
    very_low = (df['glucose_value'] < 54).sum()
    very_low_pct = (very_low / total) * 100
    
    very_high = (df['glucose_value'] > 250).sum()
    very_high_pct = (very_high / total) * 100
    
    return {
        'below_range': below_range_pct,
        'in_range': in_range_pct,
        'above_range': above_range_pct,
        'very_low': very_low_pct,
        'very_high': very_high_pct
    }

def calculate_coefficient_of_variation(df):
    """
    Calculate coefficient of variation (CV) for glucose values
    
    Args:
        df (pd.DataFrame): Processed glucose data
    
    Returns:
        float: Coefficient of variation (CV) as a percentage
    """
    # Calculate mean and standard deviation
    mean = df['glucose_value'].mean()
    std = df['glucose_value'].std()
    
    # Calculate CV (as a percentage)
    cv = (std / mean) * 100
    
    return cv

def identify_patterns(df):
    """
    Identify common glucose patterns
    
    Args:
        df (pd.DataFrame): Processed glucose data
    
    Returns:
        dict: Dictionary of identified patterns
    """
    patterns = {}
    
    # Group by hour of day
    hourly_data = df.groupby(df['timestamp'].dt.hour)['glucose_value'].mean()
    
    # Check for dawn phenomenon (rise in glucose between 4am-8am)
    dawn_hours = hourly_data.loc[4:8]
    if dawn_hours.iloc[-1] > dawn_hours.iloc[0] * 1.2:  # 20% increase
        patterns['dawn_phenomenon'] = True
    else:
        patterns['dawn_phenomenon'] = False
    
    # Check for afternoon dips (lower glucose in afternoon)
    if hourly_data.loc[14:17].mean() < hourly_data.mean():
        patterns['afternoon_dip'] = True
    else:
        patterns['afternoon_dip'] = False
    
    # Check for evening rises
    if hourly_data.loc[18:22].mean() > hourly_data.mean():
        patterns['evening_rise'] = True
    else:
        patterns['evening_rise'] = False
    
    # Check for overnight lows
    if hourly_data.loc[0:4].min() < 70:
        patterns['overnight_lows'] = True
    else:
        patterns['overnight_lows'] = False
    
    return patterns
