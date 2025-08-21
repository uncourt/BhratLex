#!/usr/bin/env python3

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiofiles
import clickhouse_connect
import redis.asyncio as redis
from loguru import logger
from playwright.async_api import async_playwright, Browser, Page
from paddleocr import PaddleOCR

from vlm_client import VLMClient
from utils import setup_logging, load_config, sanitize_filename


class ThreatAnalyzer:
    def __init__(self, config_path: str = "config.json"):
        self.config = load_config(config_path)
        self.vlm_client = VLMClient(
            endpoint=self.config["vlm_endpoint"],
            api_key=self.config["vlm_api_key"]
        )
        
        # Initialize OCR
        self.ocr = PaddleOCR(
            use_angle_cls=True,
            lang=self.config["ocr"]["lang"],
            use_gpu=self.config["ocr"]["use_gpu"]
        )
        
        # Create screenshot directory
        os.makedirs(self.config["screenshot_dir"], exist_ok=True)
        
        # Initialize connections (will be set up in start())
        self.redis_client = None
        self.clickhouse_client = None
        self.browser = None
        
    async def start(self):
        """Initialize all async connections"""
        logger.info("Starting Threat Analyzer...")
        
        # Setup Redis connection
        self.redis_client = redis.Redis.from_url(self.config["redis"]["url"])
        await self.redis_client.ping()
        logger.info("Redis connection established")
        
        # Setup ClickHouse connection
        self.clickhouse_client = clickhouse_connect.get_client(
            host=self.config["clickhouse"]["host"],
            port=self.config["clickhouse"]["port"],
            database=self.config["clickhouse"]["database"],
            username=self.config["clickhouse"]["username"],
            password=self.config["clickhouse"]["password"]
        )
        logger.info("ClickHouse connection established")
        
        # Setup Playwright browser
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.config["browser"]["headless"]
        )
        logger.info("Browser launched")
        
        logger.info("Threat Analyzer started successfully")
    
    async def stop(self):
        """Clean up all connections"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Threat Analyzer stopped")
    
    async def run_worker(self):
        """Main worker loop"""
        logger.info("Starting analyzer worker...")
        
        while True:
            try:
                # Dequeue task from Redis
                task_data = await self.redis_client.brpop(
                    self.config["redis"]["queue_name"],
                    timeout=5
                )
                
                if task_data:
                    _, task_json = task_data
                    task = json.loads(task_json)
                    
                    logger.info(f"Processing task for domain: {task['domain']}")
                    await self.process_task(task)
                    
            except KeyboardInterrupt:
                logger.info("Worker interrupted by user")
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await asyncio.sleep(1)
    
    async def process_task(self, task: Dict):
        """Process a single analyzer task"""
        start_time = time.time()
        decision_id = task["decision_id"]
        domain = task["domain"]
        url = task.get("url", f"https://{domain}")
        
        screenshot_path = ""
        html_content = ""
        ocr_text = ""
        vlm_verdict = ""
        vlm_confidence = 0.0
        is_threat = False
        threat_categories = []
        error_message = ""
        
        try:
            # Step 1: Take screenshot and get HTML
            screenshot_path, html_content = await self.capture_page(url)
            logger.info(f"Captured page: {url}")
            
            # Step 2: Extract text using OCR
            if screenshot_path and os.path.exists(screenshot_path):
                ocr_text = await self.extract_text_ocr(screenshot_path)
                logger.info(f"Extracted OCR text: {len(ocr_text)} characters")
            
            # Step 3: Analyze with VLM
            if screenshot_path:
                vlm_result = await self.analyze_with_vlm(
                    screenshot_path, url, domain, html_content, ocr_text
                )
                vlm_verdict = vlm_result.get("verdict", "")
                vlm_confidence = vlm_result.get("confidence", 0.0)
                is_threat = vlm_result.get("is_threat", False)
                threat_categories = vlm_result.get("categories", [])
                logger.info(f"VLM analysis complete: threat={is_threat}, confidence={vlm_confidence}")
            
        except Exception as e:
            error_message = str(e)
            logger.error(f"Error processing task {decision_id}: {e}")
        
        # Calculate processing time
        processing_time_ms = int((time.time() - start_time) * 1000)
        
        # Log results to ClickHouse
        await self.log_results(
            decision_id=decision_id,
            domain=domain,
            url=url,
            screenshot_path=screenshot_path,
            html_content=html_content,
            ocr_text=ocr_text,
            vlm_verdict=vlm_verdict,
            vlm_confidence=vlm_confidence,
            is_threat=is_threat,
            threat_categories=threat_categories,
            processing_time_ms=processing_time_ms,
            error_message=error_message
        )
        
        # Send reward signal back to engine if threat detected
        if is_threat:
            await self.send_reward_signal(decision_id, 1.0, True)
    
    async def capture_page(self, url: str) -> Tuple[str, str]:
        """Capture screenshot and HTML content of a page"""
        context = await self.browser.new_context(
            viewport={
                "width": self.config["browser"]["viewport_width"],
                "height": self.config["browser"]["viewport_height"]
            },
            user_agent=self.config["browser"]["user_agent"]
        )
        
        page = await context.new_page()
        
        try:
            # Navigate to page with timeout
            await page.goto(url, timeout=self.config["browser_timeout"] * 1000)
            await page.wait_for_load_state("networkidle", timeout=10000)
            
            # Get HTML content
            html_content = await page.content()
            
            # Take screenshot
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{sanitize_filename(url)}_{timestamp}.png"
            screenshot_path = os.path.join(self.config["screenshot_dir"], filename)
            
            await page.screenshot(path=screenshot_path, full_page=True)
            
            return screenshot_path, html_content
            
        finally:
            await context.close()
    
    async def extract_text_ocr(self, image_path: str) -> str:
        """Extract text from screenshot using PaddleOCR"""
        try:
            result = self.ocr.ocr(image_path, cls=True)
            
            text_lines = []
            for line in result[0] if result and result[0] else []:
                if line and len(line) > 1:
                    text_lines.append(line[1][0])
            
            return "\n".join(text_lines)
            
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            return ""
    
    async def analyze_with_vlm(
        self, 
        screenshot_path: str, 
        url: str, 
        domain: str, 
        html_content: str, 
        ocr_text: str
    ) -> Dict:
        """Analyze page content using Vision Language Model"""
        try:
            # Prepare context for VLM
            context = {
                "url": url,
                "domain": domain,
                "html_snippet": html_content[:2000],  # First 2000 chars
                "ocr_text": ocr_text[:1000],  # First 1000 chars
            }
            
            result = await self.vlm_client.analyze_threat(screenshot_path, context)
            return result
            
        except Exception as e:
            logger.error(f"VLM analysis failed: {e}")
            return {
                "verdict": f"Analysis failed: {str(e)}",
                "confidence": 0.0,
                "is_threat": False,
                "categories": []
            }
    
    async def log_results(
        self,
        decision_id: str,
        domain: str,
        url: str,
        screenshot_path: str,
        html_content: str,
        ocr_text: str,
        vlm_verdict: str,
        vlm_confidence: float,
        is_threat: bool,
        threat_categories: List[str],
        processing_time_ms: int,
        error_message: str
    ):
        """Log analysis results to ClickHouse"""
        try:
            self.clickhouse_client.insert(
                "analyzer",
                [
                    [
                        datetime.now(),
                        decision_id,
                        domain,
                        url,
                        screenshot_path,
                        html_content[:10000],  # Truncate large content
                        ocr_text,
                        vlm_verdict,
                        vlm_confidence,
                        is_threat,
                        threat_categories,
                        processing_time_ms,
                        error_message
                    ]
                ]
            )
            logger.info(f"Logged results for decision: {decision_id}")
            
        except Exception as e:
            logger.error(f"Failed to log results: {e}")
    
    async def send_reward_signal(self, decision_id: str, reward: float, actual_threat: bool):
        """Send reward signal back to the engine"""
        try:
            # This would typically call the engine's /feedback endpoint
            # For now, we'll just log it
            logger.info(f"Reward signal: decision_id={decision_id}, reward={reward}, threat={actual_threat}")
            
        except Exception as e:
            logger.error(f"Failed to send reward signal: {e}")


async def main():
    setup_logging()
    
    analyzer = ThreatAnalyzer()
    
    try:
        await analyzer.start()
        await analyzer.run_worker()
    except KeyboardInterrupt:
        logger.info("Shutting down analyzer...")
    finally:
        await analyzer.stop()


if __name__ == "__main__":
    asyncio.run(main())