#!/usr/bin/env python3
"""
Vision Language Model Client
Communicates with local vLLM server for threat analysis
"""

import base64
import json
import logging
from typing import Dict, Optional
import httpx

logger = logging.getLogger(__name__)

class VLMClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.timeout = 60.0
        self.max_retries = 3
        
    async def analyze(self, prompt: str, image_path: str) -> Dict:
        """Analyze image and text using VLM"""
        try:
            # Encode image to base64
            image_base64 = self._encode_image(image_path)
            
            # Prepare OpenAI-compatible request
            request_data = {
                "model": "Qwen2-VL-7B-Instruct-AWQ",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 1000,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }
            
            # Make request to VLM server
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.base_url,
                    json=request_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                    
                    # Parse JSON response
                    try:
                        parsed_content = json.loads(content)
                        logger.info(f"VLM analysis successful: {parsed_content.get('verdict', 'UNKNOWN')}")
                        return parsed_content
                    except json.JSONDecodeError:
                        logger.warning("VLM returned non-JSON response, attempting to parse")
                        return self._parse_text_response(content)
                        
                else:
                    logger.error(f"VLM request failed with status {response.status_code}: {response.text}")
                    return self._create_error_response(f"HTTP {response.status_code}")
                    
        except Exception as e:
            logger.error(f"VLM analysis failed: {e}")
            return self._create_error_response(str(e))
    
    def _encode_image(self, image_path: str) -> str:
        """Encode image file to base64"""
        try:
            with open(image_path, "rb") as image_file:
                return base64.b64encode(image_file.read()).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encode image {image_path}: {e}")
            raise
    
    def _parse_text_response(self, text: str) -> Dict:
        """Parse text response when JSON parsing fails"""
        try:
            # Try to extract verdict and confidence from text
            text_lower = text.lower()
            
            if "malicious" in text_lower:
                verdict = "MALICIOUS"
            elif "suspicious" in text_lower:
                verdict = "SUSPICIOUS"
            elif "safe" in text_lower:
                verdict = "SAFE"
            else:
                verdict = "UNKNOWN"
            
            # Try to extract confidence (look for numbers 0.0 to 1.0)
            import re
            confidence_match = re.search(r'0\.\d+|1\.0', text)
            confidence = float(confidence_match.group()) if confidence_match else 0.5
            
            # Extract reasons (split by common delimiters)
            reasons = []
            if "reason" in text_lower:
                # Simple extraction of reasons
                lines = text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and len(line) > 10 and not line.startswith('{'):
                        reasons.append(line)
            
            if not reasons:
                reasons = ["Analysis completed by VLM"]
            
            return {
                "verdict": verdict,
                "confidence": confidence,
                "reasons": reasons[:3]  # Limit to 3 reasons
            }
            
        except Exception as e:
            logger.error(f"Failed to parse text response: {e}")
            return self._create_error_response("Failed to parse VLM response")
    
    def _create_error_response(self, error_msg: str) -> Dict:
        """Create error response when VLM analysis fails"""
        return {
            "verdict": "ERROR",
            "confidence": 0.0,
            "reasons": [f"VLM analysis failed: {error_msg}"]
        }
    
    async def health_check(self) -> bool:
        """Check if VLM server is healthy"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.base_url.replace("/v1/chat/completions", "/health"))
                return response.status_code == 200
        except Exception:
            return False
    
    def get_model_info(self) -> Dict:
        """Get information about the VLM model"""
        return {
            "model": "Qwen2-VL-7B-Instruct-AWQ",
            "type": "vision-language-model",
            "capabilities": ["image_analysis", "text_analysis", "threat_detection"],
            "endpoint": self.base_url
        }