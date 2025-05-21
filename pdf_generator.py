from fpdf import FPDF
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import io
import os
import time
from datetime import datetime, timedelta
import json
import tempfile

class T1DReportPDF(FPDF):
    """
    Custom PDF class for T1D-Guardian medical reports with privacy features
    """
    def __init__(self, orientation='P', unit='mm', format='A4'):
        super().__init__(orientation, unit, format)
        self.set_author("T1D-Guardian")
        self.set_creator("T1D-Guardian Analytics System")
        self.set_title("Diabetes Data Report")
        
        # Add document metadata including privacy notice
        self.set_subject("Private Medical Data - Confidential")
        
        # Configure margins
        self.set_margins(15, 15, 15)
        
        # Track whether the footer logo has been added
        self.footer_set = False
    
    def header(self):
        """Custom header with logo and title"""
        # Add logo if available (would need to create/upload a logo image)
        # self.image("logo.png", 10, 8, 33)
        
        # Set font for header
        self.set_font('Arial', 'B', 15)
        
        # Move to the right
        self.cell(80)
        
        # Title
        self.cell(30, 10, 'T1D-Guardian: Diabetes Data Report', 0, 0, 'C')
        
        # Date
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 0, 'R')
        
        # Line break
        self.ln(20)
    
    def footer(self): # lol foot
        """Custom footer with privacy notice and page number"""
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        
        # Privacy notice in italic small font
        self.set_font('Arial', 'I', 6)
        self.cell(0, 5, 'CONFIDENTIAL - This document contains private medical data protected by encryption', 0, 0, 'C')
        
        # Page number
        self.set_font('Arial', 'I', 8)
        self.cell(0, 5, f'Page {self.page_no()}/{{nb}}', 0, 0, 'R')
        
        # Data integrity hash
        self.set_font('Arial', 'I', 6)
        self.set_text_color(100, 100, 100)
        if hasattr(self, 'data_hash'):
            self.set_x(15)
            self.cell(0, 5, f'Data verification: {self.data_hash[:16]}...', 0, 0, 'L')
        self.set_text_color(0, 0, 0)
    
    def add_data_hash(self, data_hash):
        """Add blockchain verification hash to document"""
        self.data_hash = data_hash

    def chapter_title(self, title):
        """Add a chapter title"""
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)
    
    def chapter_body(self, text):
        """Add body text to a chapter"""
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, text)
        self.ln()
    
    def add_metric(self, label, value, unit=''):
        """Add a metric with a label and value"""
        self.set_font('Arial', 'B', 10)
        self.cell(60, 6, label, 0, 0, 'L')
        self.set_font('Arial', '', 10)
        self.cell(0, 6, f"{value} {unit}", 0, 1, 'L')
    
    def add_metrics_table(self, metrics, columns=2):
        """Add a table of metrics with multiple columns"""
        # Calculate column width
        col_width = (self.w - 2 * self.l_margin) / columns
        row_height = 6
        
        # Add each metric
        for i, (label, value, unit) in enumerate(metrics):
            col = i % columns
            if col == 0 and i > 0:
                self.ln()
            
            self.set_x(self.l_margin + col * col_width)
            self.set_font('Arial', 'B', 9)
            self.cell(col_width * 0.6, row_height, label, 0, 0, 'L')
            self.set_font('Arial', '', 9)
            self.cell(col_width * 0.4, row_height, f"{value} {unit}", 0, 0, 'L')
    
    def add_tir_chart(self, tir_data):
        """Add a Time in Range chart"""
        # Create a temporary file for the chart
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            # Create Time in Range pie chart
            plt.figure(figsize=(4, 3))
            labels = ['Below Range (<70)', 'In Range (70-180)', 'Above Range (>180)']
            sizes = [tir_data['below_range'], tir_data['in_range'], tir_data['above_range']]
            colors = ['#FF9999', '#66B266', '#FFCC99']
            
            plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.axis('equal')
            plt.title('Time in Range Distribution')
            
            # Save to temp file
            plt.savefig(tmp.name, bbox_inches='tight')
            plt.close()
            
            # Add to PDF
            self.image(tmp.name, x=40, w=120)
            
            # Clean up
            os.unlink(tmp.name)
    
    def add_glucose_chart(self, glucose_data):
        """Add a glucose trend chart"""
        # Create a temporary file for the chart
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            # Prepare data
            timestamps = pd.to_datetime(glucose_data['timestamp'])
            values = glucose_data['glucose_value']
            
            # Create chart
            plt.figure(figsize=(7, 3))
            plt.plot(timestamps, values, '-b')
            
            # Add reference lines
            plt.axhline(y=70, color='r', linestyle='--')
            plt.axhline(y=180, color='r', linestyle='--')
            plt.fill_between(timestamps, 70, 180, color='green', alpha=0.1)
            
            # Set labels and title
            plt.xlabel('Time')
            plt.ylabel('Glucose (mg/dL)')
            plt.title('Glucose Readings')
            
            # Format x-axis dates
            plt.gcf().autofmt_xdate()
            
            # Ensure y-axis scale is appropriate
            plt.ylim(max(0, values.min() - 20), values.max() + 20)
            
            # Save to temp file
            plt.savefig(tmp.name, bbox_inches='tight')
            plt.close()
            
            # Add to PDF
            self.image(tmp.name, x=15, w=180)
            
            # Clean up
            os.unlink(tmp.name)

    def add_daily_patterns_chart(self, glucose_data):
        """Add a daily patterns chart showing glucose by hour of day"""
        # Create a temporary file for the chart
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            # Prepare data - group by hour of day
            if 'hour_of_day' not in glucose_data.columns:
                glucose_data['hour_of_day'] = pd.to_datetime(glucose_data['timestamp']).dt.hour
            
            hourly_avg = glucose_data.groupby('hour_of_day')['glucose_value'].mean()
            
            # Create chart
            plt.figure(figsize=(7, 3))
            plt.plot(hourly_avg.index, hourly_avg.values, '-g', marker='o')
            
            # Add reference lines
            plt.axhline(y=70, color='r', linestyle='--')
            plt.axhline(y=180, color='r', linestyle='--')
            plt.fill_between(hourly_avg.index, 70, 180, color='green', alpha=0.1)
            
            # Set labels and title
            plt.xlabel('Hour of Day')
            plt.ylabel('Glucose (mg/dL)')
            plt.title('Average Glucose by Hour of Day')
            
            # Set x-axis ticks
            plt.xticks(range(0, 24, 2))
            
            # Save to temp file
            plt.savefig(tmp.name, bbox_inches='tight')
            plt.close()
            
            # Add to PDF
            self.image(tmp.name, x=15, w=180)
            
            # Clean up
            os.unlink(tmp.name)


def generate_diabetes_report(glucose_data, metadata=None, data_hash=None, encryption_info=None):
    """
    Generate a comprehensive diabetes report in PDF format
    
    Args:
        glucose_data (pd.DataFrame): Processed glucose data
        metadata (dict): Additional metadata for the report
        data_hash (str): Blockchain verification hash
        encryption_info (dict): Information about data encryption
    
    Returns:
        bytes: PDF report as bytes
    """
    # Create PDF object
    pdf = T1DReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Add data verification hash if available
    if data_hash:
        pdf.add_data_hash(data_hash)
    
    # Add report title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Diabetes Glucose Data Report', 0, 1, 'C')
    pdf.ln(5)
    
    # Patient information
    if metadata and 'patient_info' in metadata:
        pdf.chapter_title('Patient Information')
        patient = metadata['patient_info']
        
        # Only include non-sensitive information if specified
        for key, value in patient.items():
            if key not in ['full_name', 'address', 'contact_number', 'email', 'insurance_id']:
                pdf.add_metric(key.replace('_', ' ').title(), value)
        
        pdf.ln(5)
    
    # Data overview
    pdf.chapter_title('Data Overview')
    
    # Date range
    start_date = pd.to_datetime(glucose_data['timestamp']).min()
    end_date = pd.to_datetime(glucose_data['timestamp']).max()
    days = (end_date - start_date).days + 1
    
    pdf.add_metric('Report Period', f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
    pdf.add_metric('Days of Data', days)
    pdf.add_metric('Number of Readings', len(glucose_data))
    pdf.add_metric('Readings per Day', f"{len(glucose_data)/days:.1f}")
    
    pdf.ln(5)
    
    # Glucose statistics
    pdf.chapter_title('Glucose Statistics')
    
    # Calculate basic statistics
    avg_glucose = glucose_data['glucose_value'].mean()
    std_glucose = glucose_data['glucose_value'].std()
    cv = (std_glucose / avg_glucose) * 100
    gmi = 3.31 + (0.02392 * avg_glucose)
    
    # Calculate time in ranges
    total = len(glucose_data)
    below_range = (glucose_data['glucose_value'] < 70).sum() / total * 100
    in_range = ((glucose_data['glucose_value'] >= 70) & (glucose_data['glucose_value'] <= 180)).sum() / total * 100
    above_range = (glucose_data['glucose_value'] > 180).sum() / total * 100
    
    very_low = (glucose_data['glucose_value'] < 54).sum() / total * 100
    very_high = (glucose_data['glucose_value'] > 250).sum() / total * 100
    
    # Add metrics
    metrics = [
        ('Average Glucose', f"{avg_glucose:.1f}", 'mg/dL'),
        ('Standard Deviation', f"{std_glucose:.1f}", 'mg/dL'),
        ('Coefficient of Variation', f"{cv:.1f}", '%'),
        ('Glucose Management Indicator', f"{gmi:.1f}", '%'),
        ('Time Below Range (<70 mg/dL)', f"{below_range:.1f}", '%'),
        ('Time in Range (70-180 mg/dL)', f"{in_range:.1f}", '%'),
        ('Time Above Range (>180 mg/dL)', f"{above_range:.1f}", '%'),
        ('Time in Very Low (<54 mg/dL)', f"{very_low:.1f}", '%'),
        ('Time in Very High (>250 mg/dL)', f"{very_high:.1f}", '%')
    ]
    
    pdf.add_metrics_table(metrics, columns=2)
    pdf.ln(10)
    
    # Add Time in Range chart
    tir_data = {
        'below_range': below_range,
        'in_range': in_range,
        'above_range': above_range
    }
    pdf.add_tir_chart(tir_data)
    pdf.ln(10)
    
    # Glucose Trends
    pdf.add_page()
    pdf.chapter_title('Glucose Trends')
    pdf.add_glucose_chart(glucose_data)
    pdf.ln(10)
    
    # Daily Patterns
    pdf.chapter_title('Daily Patterns')
    pdf.add_daily_patterns_chart(glucose_data)
    pdf.ln(10)
    
    # If we have rate of change data, add advanced analytics
    if 'glucose_rate_of_change' in glucose_data.columns:
        pdf.add_page()
        pdf.chapter_title('Advanced Analytics')
        
        # Add information about glucose variability
        pdf.chapter_body("Glucose variability is an important factor in diabetes management. " 
                         "High variability can increase risk of complications and make glucose " 
                         "control more challenging.")
        
        # Add metrics for variability
        metrics = [
            ('Average Rate of Change', f"{glucose_data['glucose_rate_of_change'].mean():.2f}", 'mg/dL/min'),
            ('Maximum Rate of Increase', f"{glucose_data['glucose_rate_of_change'].max():.2f}", 'mg/dL/min'),
            ('Maximum Rate of Decrease', f"{glucose_data['glucose_rate_of_change'].min():.2f}", 'mg/dL/min')
        ]
        
        pdf.add_metrics_table(metrics, columns=1)
        pdf.ln(10)
    
    # Privacy and data integrity information
    pdf.add_page()
    pdf.chapter_title('Data Privacy & Integrity')
    
    privacy_text = ("This report contains private health information that has been processed "
                   "with privacy-preserving technology. The data used to generate this report "
                   "is protected using encryption and blockchain verification to ensure its "
                   "integrity and authenticity.")
    
    pdf.chapter_body(privacy_text)
    
    if data_hash:
        pdf.ln(5)
        pdf.add_metric('Data Verification Hash', data_hash)
        pdf.chapter_body("This hash can be verified on the Ethereum blockchain to prove the data has not been tampered with.")
    
    if encryption_info:
        pdf.ln(5)
        pdf.chapter_body("This data is protected with end-to-end encryption. Only individuals with the proper encryption key can access the raw data.")
    
    # Output the PDF
    return pdf.output(dest='S').encode('latin1')


def save_pdf_report(glucose_data, filename, metadata=None, data_hash=None, encryption_info=None):
    """
    Generate and save a diabetes report to a file
    
    Args:
        glucose_data (pd.DataFrame): Processed glucose data
        filename (str): Output filename for the PDF
        metadata (dict): Additional metadata for the report
        data_hash (str): Blockchain verification hash
        encryption_info (dict): Information about data encryption
    
    Returns:
        bool: True if successful
    """
    try:
        pdf_bytes = generate_diabetes_report(glucose_data, metadata, data_hash, encryption_info)
        
        with open(filename, 'wb') as f:
            f.write(pdf_bytes)
            
        return True
    except Exception as e:
        print(f"Error saving PDF report: {e}")
        return False
    
    