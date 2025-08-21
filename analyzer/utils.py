#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path
from typing import Dict, Any

from loguru import logger


def setup_logging(level: str = "INFO"):
    """Setup structured logging"""
    logger.remove()
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level
    )
    logger.add(
        "logs/analyzer.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=level,
        rotation="100 MB",
        retention="30 days"
    )


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_path} not found")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for filesystem safety"""
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'https?://', '', filename)
    filename = filename.replace('.', '_')
    
    # Limit length
    if len(filename) > 100:
        filename = filename[:100]
    
    return filename


def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "screenshots",
        "temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logger.info(f"Created directory: {directory}")


def validate_url(url: str) -> bool:
    """Basic URL validation"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return url_pattern.match(url) is not None


def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def calculate_file_hash(filepath: str) -> str:
    """Calculate SHA-256 hash of a file"""
    import hashlib
    
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate hash for {filepath}: {e}")
        return ""


def format_bytes(bytes_count: int) -> str:
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def clean_html_content(html: str) -> str:
    """Clean and truncate HTML content"""
    # Remove script and style tags
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove HTML tags but keep text content
    html = re.sub(r'<[^>]+>', ' ', html)
    
    # Clean up whitespace
    html = re.sub(r'\s+', ' ', html)
    
    # Truncate if too long
    if len(html) > 10000:
        html = html[:10000] + "... [truncated]"
    
    return html.strip()


def extract_text_features(text: str) -> Dict[str, Any]:
    """Extract features from text content"""
    if not text:
        return {}
    
    features = {
        "length": len(text),
        "word_count": len(text.split()),
        "line_count": len(text.splitlines()),
        "uppercase_ratio": sum(1 for c in text if c.isupper()) / len(text),
        "digit_ratio": sum(1 for c in text if c.isdigit()) / len(text),
        "special_char_ratio": sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text)
    }
    
    # Suspicious patterns
    suspicious_patterns = [
        r'click here',
        r'urgent',
        r'immediate',
        r'verify.*account',
        r'suspended',
        r'winner',
        r'congratulations',
        r'free.*money',
        r'bitcoin',
        r'cryptocurrency'
    ]
    
    features["suspicious_pattern_count"] = sum(
        1 for pattern in suspicious_patterns 
        if re.search(pattern, text, re.IGNORECASE)
    )
    
    return features


class PerformanceMonitor:
    """Simple performance monitoring utility"""
    
    def __init__(self):
        self.metrics = {}
    
    def start_timer(self, name: str):
        """Start a timer"""
        import time
        self.metrics[name] = {"start": time.time()}
    
    def end_timer(self, name: str):
        """End a timer and calculate duration"""
        import time
        if name in self.metrics:
            self.metrics[name]["end"] = time.time()
            self.metrics[name]["duration"] = self.metrics[name]["end"] - self.metrics[name]["start"]
            return self.metrics[name]["duration"]
        return 0
    
    def get_duration(self, name: str) -> float:
        """Get duration of a timer"""
        return self.metrics.get(name, {}).get("duration", 0)
    
    def get_summary(self) -> Dict[str, float]:
        """Get summary of all timers"""
        return {
            name: data.get("duration", 0) 
            for name, data in self.metrics.items()
        }


# Initialize directories on import
create_directories()