import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Data Analysis - T1D-Guardian",
    page_icon="📊",
    layout="wide"
)

st.title("Glucose Data Analysis")
st.write("Detailed analysis of your glucose data with privacy-preserving technology")

# Check if data is loaded
if 'processed_data' not in st.session_state or st.session_state.processed_data is None:
    st.warning("No data loaded. Please upload your Dexcom data on the home page.")
    st.stop()

# Get the processed data
glucose_data = st.session_state.processed_data

# Data analysis section
st.header("Glucose Statistics")

# Display basic statistics
if 'glucose_value' in glucose_data.columns:
    avg_glucose = glucose_data['glucose_value'].mean()
    min_glucose = glucose_data['glucose_value'].min()
    max_glucose = glucose_data['glucose_value'].max()
    
    # Create columns for displaying statistics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Average Glucose", f"{avg_glucose:.1f} mg/dL")
    with col2:
        st.metric("Min Glucose", f"{min_glucose:.1f} mg/dL")
    with col3:
        st.metric("Max Glucose", f"{max_glucose:.1f} mg/dL")
    
    # Time in range analysis
    st.subheader("Time in Range Analysis")
    
    # Calculate time in different ranges
    total_readings = len(glucose_data)
    below_range = (glucose_data['glucose_value'] < 70).sum()
    in_range = ((glucose_data['glucose_value'] >= 70) & (glucose_data['glucose_value'] <= 180)).sum()
    above_range = (glucose_data['glucose_value'] > 180).sum()
    
    # Calculate percentages
    below_range_pct = (below_range / total_readings) * 100
    in_range_pct = (in_range / total_readings) * 100
    above_range_pct = (above_range / total_readings) * 100
    
    # Display time in range metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Below Range (<70 mg/dL)", f"{below_range_pct:.1f}%")
    with col2:
        st.metric("In Range (70-180 mg/dL)", f"{in_range_pct:.1f}%")
    with col3:
        st.metric("Above Range (>180 mg/dL)", f"{above_range_pct:.1f}%")
    
    # Create time in range pie chart
    labels = ['Below Range (<70)', 'In Range (70-180)', 'Above Range (>180)']
    values = [below_range_pct, in_range_pct, above_range_pct]
    colors = ['red', 'green', 'orange']
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.4,
        marker=dict(colors=colors)
    )])
    
    fig.update_layout(
        title_text="Time in Range Distribution",
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Glucose trend plot
    st.subheader("Glucose Trends")
    
    trend_fig = px.line(
        glucose_data, 
        x='timestamp', 
        y='glucose_value',
        title="Glucose Readings Over Time"
    )
    
    # Add range threshold lines
    trend_fig.add_hline(y=70, line_dash="dash", line_color="red", annotation_text="Low")
    trend_fig.add_hline(y=180, line_dash="dash", line_color="red", annotation_text="High")
    
    st.plotly_chart(trend_fig, use_container_width=True)

    # Daily patterns analysis
    st.header("Daily Patterns")
    
    # Convert timestamp to hour of day for analysis
    if 'hour_of_day' not in glucose_data.columns:
        glucose_data['hour_of_day'] = pd.to_datetime(glucose_data['timestamp']).dt.hour
    
    # Group by hour and calculate mean glucose
    hourly_data = glucose_data.groupby('hour_of_day')['glucose_value'].mean().reset_index()
    
    # Create hourly pattern plot
    hourly_fig = px.line(
        hourly_data, 
        x='hour_of_day', 
        y='glucose_value',
        title="Average Glucose by Hour of Day",
        labels={"hour_of_day": "Hour of Day", "glucose_value": "Average Glucose (mg/dL)"}
    )
    hourly_fig.update_layout(xaxis=dict(tickmode='linear', tick0=0, dtick=2))
    st.plotly_chart(hourly_fig, use_container_width=True)
    
    # Check if rate of change data is available
    if 'glucose_rate_of_change' in glucose_data.columns:
        st.header("Rate of Change Analysis")
        
        # Distribution of rate of change
        rate_fig = px.histogram(
            glucose_data, 
            x='glucose_rate_of_change',
            nbins=30,
            title="Distribution of Glucose Rate of Change",
            labels={"glucose_rate_of_change": "Rate of Change (mg/dL/min)"}
        )
        
        # Add vertical line at 0
        rate_fig.add_vline(x=0, line_dash="solid", line_color="black")
        
        st.plotly_chart(rate_fig, use_container_width=True)
        
        # Correlation between rate of change and glucose level
        if st.checkbox("Show Rate of Change vs. Glucose Correlation"):
            corr_fig = px.scatter(
                glucose_data,
                x='glucose_value', 
                y='glucose_rate_of_change',
                title="Correlation: Glucose Level vs. Rate of Change",
                labels={
                    "glucose_value": "Glucose Level (mg/dL)",
                    "glucose_rate_of_change": "Rate of Change (mg/dL/min)"
                }
            )
            st.plotly_chart(corr_fig, use_container_width=True)
else:
    st.error("Glucose data not found in the processed dataset. Please check your data format.")