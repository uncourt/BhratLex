#!/usr/bin/env python3

import base64
import json
from typing import Dict, List, Optional
from pathlib import Path

import httpx
from loguru import logger


class VLMClient:
    def __init__(self, endpoint: str, api_key: str = "dummy"):
        self.endpoint = endpoint
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=60.0)
    
    async def analyze_threat(self, image_path: str, context: Dict) -> Dict:
        """Analyze a screenshot for threats using VLM"""
        try:
            # Encode image to base64
            image_b64 = await self._encode_image(image_path)
            
            # Prepare the prompt
            prompt = self._build_threat_analysis_prompt(context)
            
            # Prepare the request
            messages = [
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
                                "url": f"data:image/png;base64,{image_b64}"
                            }
                        }
                    ]
                }
            ]
            
            payload = {
                "model": "Qwen2-VL-7B-Instruct",
                "messages": messages,
                "max_tokens": 1000,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Send request to VLM
            response = await self.client.post(
                self.endpoint,
                json=payload,
                headers=headers
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Parse the response
            content = result["choices"][0]["message"]["content"]
            analysis = json.loads(content)
            
            return self._parse_vlm_response(analysis)
            
        except Exception as e:
            logger.error(f"VLM analysis failed: {e}")
            return {
                "verdict": f"VLM analysis failed: {str(e)}",
                "confidence": 0.0,
                "is_threat": False,
                "categories": []
            }
    
    async def _encode_image(self, image_path: str) -> str:
        """Encode image to base64"""
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
    
    def _build_threat_analysis_prompt(self, context: Dict) -> str:
        """Build the threat analysis prompt for the VLM"""
        return f"""
You are a cybersecurity expert analyzing a website screenshot for potential threats. 

Context:
- URL: {context.get('url', 'Unknown')}
- Domain: {context.get('domain', 'Unknown')}
- HTML snippet: {context.get('html_snippet', 'Not available')[:500]}...
- OCR text: {context.get('ocr_text', 'Not available')[:300]}...

Analyze this screenshot and determine if it represents a cybersecurity threat. Look for:

1. **Phishing indicators**: Login forms mimicking legitimate services, urgent language, suspicious URLs
2. **Malware distribution**: Download prompts, fake software updates, suspicious file offerings
3. **Scam content**: Get-rich-quick schemes, fake prizes, social engineering attempts
4. **Brand impersonation**: Fake banking sites, counterfeit e-commerce, spoofed services
5. **Cryptojacking**: Cryptocurrency mining scripts, wallet-related scams
6. **Social engineering**: Fake tech support, urgent security warnings, deceptive messaging

Provide your analysis in the following JSON format:
{{
    "verdict": "Detailed explanation of your analysis and reasoning",
    "confidence": 0.85,
    "is_threat": true,
    "categories": ["phishing", "brand_impersonation"],
    "indicators": ["Fake login form", "Suspicious domain", "Urgent language"],
    "risk_level": "high"
}}

Be thorough but concise. Focus on concrete visual evidence in the screenshot.
"""
    
    def _parse_vlm_response(self, analysis: Dict) -> Dict:
        """Parse and validate VLM response"""
        try:
            return {
                "verdict": analysis.get("verdict", "No analysis provided"),
                "confidence": float(analysis.get("confidence", 0.0)),
                "is_threat": bool(analysis.get("is_threat", False)),
                "categories": analysis.get("categories", []),
                "indicators": analysis.get("indicators", []),
                "risk_level": analysis.get("risk_level", "unknown")
            }
        except Exception as e:
            logger.error(f"Failed to parse VLM response: {e}")
            return {
                "verdict": "Failed to parse VLM response",
                "confidence": 0.0,
                "is_threat": False,
                "categories": []
            }
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


# Test function
async def test_vlm_client():
    """Test the VLM client with a sample image"""
    client = VLMClient("http://localhost:8001/v1/chat/completions")
    
    # Create a test context
    context = {
        "url": "https://example.com",
        "domain": "example.com",
        "html_snippet": "<html><body><h1>Test Page</h1></body></html>",
        "ocr_text": "Test Page"
    }
    
    # This would need an actual image file to test
    # result = await client.analyze_threat("test_image.png", context)
    # print(json.dumps(result, indent=2))
    
    await client.close()


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_vlm_client())