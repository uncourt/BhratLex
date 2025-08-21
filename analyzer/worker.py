#!/usr/bin/env python3
"""
Garuda Python Analyzer Worker
Handles async threat analysis using Playwright, OCR, and VLM
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

import clickhouse_connect
import redis.asyncio as redis
from playwright.async_api import async_playwright, Browser, Page

from vlm_client import VLMClient
from utils import setup_logging, create_screenshot_filename

# Configure logging
logger = setup_logging()

class GarudaAnalyzer:
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        self.clickhouse_url = os.getenv("CLICKHOUSE_URL", "http://localhost:8123")
        self.vlm_url = os.getenv("VLM_URL", "http://localhost:8000/v1/chat/completions")
        
        self.redis_client: Optional[redis.Redis] = None
        self.clickhouse_client: Optional[clickhouse_connect.driver.Client] = None
        self.vlm_client: Optional[VLMClient] = None
        self.browser: Optional[Browser] = None
        
        # Analysis settings
        self.screenshot_dir = "screenshots"
        self.max_retries = 3
        self.timeout_ms = 30000
        
    async def initialize(self):
        """Initialize all clients and services"""
        try:
            # Initialize Redis
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis client initialized")
            
            # Initialize ClickHouse
            self.clickhouse_client = clickhouse_connect.get_client(
                host='localhost',
                port=8123,
                database='garuda'
            )
            logger.info("ClickHouse client initialized")
            
            # Initialize VLM client
            self.vlm_client = VLMClient(self.vlm_url)
            logger.info("VLM client initialized")
            
            # Initialize Playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            logger.info("Playwright browser initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize analyzer: {e}")
            raise
    
    async def process_analysis_queue(self):
        """Main loop to process analysis queue"""
        logger.info("Starting analysis queue processor")
        
        while True:
            try:
                # Dequeue analysis task
                task_data = await self.redis_client.brpop("analysis_queue", timeout=1)
                
                if task_data:
                    _, task_json = task_data
                    task = json.loads(task_json)
                    logger.info(f"Processing analysis task: {task['decision_id']}")
                    
                    # Process the task
                    await self.analyze_domain(task)
                    
                else:
                    # No tasks, wait a bit
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error processing analysis queue: {e}")
                await asyncio.sleep(5)
    
    async def analyze_domain(self, task: Dict):
        """Analyze a domain using multiple techniques"""
        decision_id = task['decision_id']
        domain = task['domain']
        url = task.get('url', f"http://{domain}")
        
        start_time = time.time()
        
        try:
            logger.info(f"Starting analysis for domain: {domain}")
            
            # Create screenshot
            screenshot_path = await self.capture_screenshot(url, domain)
            
            # Extract OCR text
            ocr_text = await self.extract_ocr_text(screenshot_path)
            
            # Get VLM analysis
            vlm_result = await self.get_vlm_analysis(domain, url, ocr_text, screenshot_path)
            
            # Calculate analysis duration
            analysis_duration = (time.time() - start_time) * 1000  # Convert to ms
            
            # Store results in ClickHouse
            await self.store_analysis_results(
                decision_id, domain, url, screenshot_path, 
                ocr_text, vlm_result, analysis_duration
            )
            
            # Update Redis status
            await self.redis_client.set(
                f"analysis_status:{decision_id}",
                "COMPLETED",
                ex=3600
            )
            
            logger.info(f"Analysis completed for {domain} in {analysis_duration:.1f}ms")
            
        except Exception as e:
            logger.error(f"Analysis failed for {domain}: {e}")
            
            # Update status to failed
            await self.redis_client.set(
                f"analysis_status:{decision_id}",
                "FAILED",
                ex=3600
            )
            
            # Store failed result
            await self.store_analysis_results(
                decision_id, domain, url, "", "", 
                {"verdict": "ERROR", "confidence": 0.0, "reasons": [str(e)]}, 
                (time.time() - start_time) * 1000
            )
    
    async def capture_screenshot(self, url: str, domain: str) -> str:
        """Capture screenshot using Playwright"""
        try:
            page = await self.browser.new_page()
            
            # Set viewport and timeout
            await page.set_viewport_size({"width": 1920, "height": 1080})
            await page.set_default_timeout(self.timeout_ms)
            
            # Navigate to URL
            await page.goto(url, wait_until="networkidle")
            
            # Wait for page to load
            await asyncio.sleep(2)
            
            # Create screenshot filename
            screenshot_path = create_screenshot_filename(domain)
            full_path = os.path.join(self.screenshot_dir, screenshot_path)
            
            # Take screenshot
            await page.screenshot(path=full_path, full_page=True)
            await page.close()
            
            logger.info(f"Screenshot captured: {full_path}")
            return screenshot_path
            
        except Exception as e:
            logger.error(f"Screenshot capture failed for {url}: {e}")
            raise
    
    async def extract_ocr_text(self, screenshot_path: str) -> str:
        """Extract text from screenshot using PaddleOCR"""
        try:
            from paddleocr import PaddleOCR
            
            # Initialize PaddleOCR
            ocr = PaddleOCR(use_angle_cls=True, lang='en')
            
            # Read image
            full_path = os.path.join(self.screenshot_dir, screenshot_path)
            result = ocr.ocr(full_path, cls=True)
            
            # Extract text from results
            text_lines = []
            if result and result[0]:
                for line in result[0]:
                    if line and len(line) >= 2:
                        text_lines.append(line[1][0])  # Extract text from OCR result
            
            ocr_text = " ".join(text_lines)
            logger.info(f"OCR extracted {len(text_lines)} text lines")
            
            return ocr_text
            
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            return ""
    
    async def get_vlm_analysis(self, domain: str, url: str, ocr_text: str, screenshot_path: str) -> Dict:
        """Get analysis from Vision Language Model"""
        try:
            # Prepare prompt for VLM
            prompt = f"""
            Analyze this domain and webpage for potential threats:
            
            Domain: {domain}
            URL: {url}
            OCR Text: {ocr_text[:1000]}  # Limit text length
            
            Please provide a threat assessment with:
            1. Verdict: SAFE, SUSPICIOUS, or MALICIOUS
            2. Confidence: 0.0 to 1.0
            3. Reasons: List specific threats or suspicious elements found
            
            Focus on detecting:
            - Phishing attempts
            - Malware distribution
            - Scam websites
            - Suspicious content
            - Security issues
            
            Respond in JSON format:
            {{
                "verdict": "SAFE|SUSPICIOUS|MALICIOUS",
                "confidence": 0.85,
                "reasons": ["reason1", "reason2"]
            }}
            """
            
            # Get VLM response
            response = await self.vlm_client.analyze(prompt, screenshot_path)
            
            logger.info(f"VLM analysis completed: {response.get('verdict', 'UNKNOWN')}")
            return response
            
        except Exception as e:
            logger.error(f"VLM analysis failed: {e}")
            return {
                "verdict": "ERROR",
                "confidence": 0.0,
                "reasons": [f"VLM analysis failed: {str(e)}"]
            }
    
    async def store_analysis_results(self, decision_id: str, domain: str, url: str, 
                                   screenshot_path: str, ocr_text: str, vlm_result: Dict, 
                                   analysis_duration: float):
        """Store analysis results in ClickHouse"""
        try:
            # Prepare data for insertion
            data = {
                'decision_id': decision_id,
                'timestamp': datetime.now(),
                'domain': domain,
                'url': url or "",
                'screenshot_path': screenshot_path,
                'ocr_text': ocr_text,
                'vlm_verdict': vlm_result.get('verdict', 'UNKNOWN'),
                'vlm_confidence': vlm_result.get('confidence', 0.0),
                'vlm_reasons': vlm_result.get('reasons', []),
                'analysis_duration_ms': analysis_duration,
                'status': 'COMPLETED'
            }
            
            # Insert into ClickHouse
            self.clickhouse_client.insert('analyzer', [data])
            
            logger.info(f"Analysis results stored for {decision_id}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis results: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.browser:
                await self.browser.close()
            
            if self.playwright:
                await self.playwright.stop()
            
            if self.redis_client:
                await self.redis_client.close()
            
            if self.clickhouse_client:
                self.clickhouse_client.close()
                
            logger.info("Cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

async def main():
    """Main entry point"""
    analyzer = GarudaAnalyzer()
    
    try:
        await analyzer.initialize()
        await analyzer.process_analysis_queue()
        
    except KeyboardInterrupt:
        logger.info("Shutting down analyzer...")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        
    finally:
        await analyzer.cleanup()

if __name__ == "__main__":
    asyncio.run(main())