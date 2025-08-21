#!/usr/bin/env python3
"""
Utility functions for Garuda Python Analyzer
"""

import logging
import os
import re
from datetime import datetime
from typing import Optional

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"logs/analyzer_{datetime.now().strftime('%Y%m%d')}.log"),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

def create_screenshot_filename(domain: str) -> str:
    """Create a unique screenshot filename for a domain"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Clean domain name for filename
    clean_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
    return f"{clean_domain}_{timestamp}.png"

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem operations"""
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    for char in unsafe_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename

def validate_url(url: str) -> bool:
    """Basic URL validation"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        # Simple domain extraction
        if url.startswith(('http://', 'https://')):
            domain = url.split('/')[2]
        else:
            domain = url.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        return domain
    except (IndexError, AttributeError):
        return None

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"

def truncate_text(text: str, max_length: int = 1000) -> str:
    """Truncate text to specified length"""
    if len(text) <= max_length:
        return text
    
    # Try to truncate at word boundary
    truncated = text[:max_length]
    last_space = truncated.rfind(' ')
    
    if last_space > max_length * 0.8:  # If we can find a good break point
        return truncated[:last_space] + "..."
    else:
        return truncated + "..."

def create_analysis_summary(domain: str, verdict: str, confidence: float, 
                          reasons: list, duration: float) -> str:
    """Create a human-readable analysis summary"""
    summary = f"""
Analysis Summary for {domain}
================================
Verdict: {verdict}
Confidence: {confidence:.1%}
Duration: {format_duration(duration)}

Reasons:
"""
    
    for i, reason in enumerate(reasons, 1):
        summary += f"{i}. {reason}\n"
    
    return summary.strip()

def get_file_size_mb(file_path: str) -> float:
    """Get file size in megabytes"""
    try:
        size_bytes = os.path.getsize(file_path)
        return size_bytes / (1024 * 1024)
    except OSError:
        return 0.0

def cleanup_old_files(directory: str, max_age_hours: int = 24) -> int:
    """Clean up old files in directory"""
    try:
        current_time = datetime.now()
        cleaned_count = 0
        
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            
            if os.path.isfile(file_path):
                file_age = current_time - datetime.fromtimestamp(os.path.getctime(file_path))
                
                if file_age.total_seconds() > max_age_hours * 3600:
                    os.remove(file_path)
                    cleaned_count += 1
        
        return cleaned_count
        
    except Exception as e:
        logging.error(f"Failed to cleanup old files: {e}")
        return 0