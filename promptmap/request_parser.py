#!/usr/bin/env python3
"""
Request Parser - SQLMap-style raw HTTP request file parser

Author: Jai

Usage:
    python cli.py scan -r request.txt
    python cli.py scan -r burp_request.txt --injection-point "FUZZ"

Supports:
    - Raw HTTP requests from Burp Suite
    - Requests saved from browser DevTools
    - Custom injection point markers (*, FUZZ, {{prompt}})
"""

import re
import json
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from pathlib import Path


class RequestParser:
    """
    Parse raw HTTP request files (like SQLMap's -r option)
    
    Example request file:
    ```
    POST /api/chat HTTP/1.1
    Host: chatbot.example.com
    Content-Type: application/json
    Authorization: Bearer token123
    Cookie: session=abc
    
    {"message": "Hello", "user_id": "123"}
    ```
    """
    
    # Injection point markers (like SQLMap's *)
    INJECTION_MARKERS = ['*', 'FUZZ', '{{prompt}}', '{{payload}}', '[INJECT]', '$PAYLOAD$']
    
    def __init__(self):
        self.url: str = ""
        self.method: str = "POST"
        self.headers: Dict[str, str] = {}
        self.body: str = ""
        self.body_template: str = ""
        self.injection_point: Optional[str] = None
        self.host: str = ""
        self.path: str = ""
        self.protocol: str = "https"
    
    def parse_file(self, filepath: str, injection_marker: str = None) -> dict:
        """
        Parse a raw HTTP request file
        
        Args:
            filepath: Path to request file
            injection_marker: Custom marker for injection point (default: auto-detect)
            
        Returns:
            dict: Parsed request config compatible with scanner
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return self.parse_raw(content, injection_marker)
    
    def parse_raw(self, raw_request: str, injection_marker: str = None) -> dict:
        """
        Parse raw HTTP request string
        
        Args:
            raw_request: Raw HTTP request text
            injection_marker: Custom marker for injection point
            
        Returns:
            dict: Parsed request config
        """
        # Normalize line endings
        raw_request = raw_request.replace('\r\n', '\n').replace('\r', '\n')
        
        # Split headers and body
        if '\n\n' in raw_request:
            header_section, self.body = raw_request.split('\n\n', 1)
        else:
            header_section = raw_request
            self.body = ""
        
        lines = header_section.strip().split('\n')
        
        # Parse request line (GET /path HTTP/1.1)
        request_line = lines[0]
        self._parse_request_line(request_line)
        
        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                self.headers[key] = value
                
                # Extract host
                if key.lower() == 'host':
                    self.host = value
        
        # Build full URL
        self._build_url()
        
        # Find injection point
        self._find_injection_point(injection_marker)
        
        # Create body template
        self._create_body_template()
        
        return self._to_config()
    
    def _parse_request_line(self, line: str):
        """Parse: POST /api/chat HTTP/1.1"""
        parts = line.split()
        if len(parts) >= 2:
            self.method = parts[0].upper()
            self.path = parts[1]
        if len(parts) >= 3 and 'HTTP' in parts[2]:
            # HTTP/1.1 or HTTP/2
            pass
    
    def _build_url(self):
        """Build full URL from host and path"""
        if self.host:
            # Check if host has port indicating HTTP
            if ':80' in self.host and ':8080' not in self.host:
                self.protocol = 'http'
            elif ':443' in self.host:
                self.protocol = 'https'
            
            # Remove port from host for URL if standard
            host = self.host.replace(':443', '').replace(':80', '')
            
            self.url = f"{self.protocol}://{host}{self.path}"
        else:
            self.url = self.path
    
    def _find_injection_point(self, custom_marker: str = None):
        """Find where to inject payloads"""
        markers_to_check = [custom_marker] if custom_marker else self.INJECTION_MARKERS
        
        # Check body first
        for marker in markers_to_check:
            if marker and marker in self.body:
                self.injection_point = marker
                return
        
        # Check URL/path
        for marker in markers_to_check:
            if marker and marker in self.path:
                self.injection_point = marker
                return
        
        # Auto-detect: Look for common message fields in JSON body
        if self.body:
            try:
                body_json = json.loads(self.body)
                message_fields = [
                    'message', 'content', 'text', 'query', 'input', 'prompt',
                    'question', 'user_message', 'user_input', 'chat_input',
                    'msg', 'q', 'request', 'body'
                ]
                
                for field in message_fields:
                    if field in body_json:
                        # Mark this field for injection
                        self.injection_point = f"JSON_FIELD:{field}"
                        return
                
                # Check nested messages array (OpenAI format)
                if 'messages' in body_json and isinstance(body_json['messages'], list):
                    for i, msg in enumerate(body_json['messages']):
                        if isinstance(msg, dict) and msg.get('role') == 'user':
                            self.injection_point = f"JSON_PATH:messages[{i}].content"
                            return
                            
            except json.JSONDecodeError:
                pass
        
        # Default: inject into body as-is
        self.injection_point = "BODY"
    
    def _create_body_template(self):
        """Create Jinja2 body template with {{ prompt }} placeholder"""
        if not self.body:
            self.body_template = '{"message": "{{ prompt }}"}'
            return
        
        template = self.body
        
        # Replace injection marker with {{ prompt }}
        if self.injection_point:
            if self.injection_point in self.INJECTION_MARKERS:
                template = template.replace(self.injection_point, '{{ prompt }}')
            
            elif self.injection_point.startswith('JSON_FIELD:'):
                field = self.injection_point.split(':')[1]
                try:
                    body_json = json.loads(self.body)
                    body_json[field] = '{{ prompt }}'
                    template = json.dumps(body_json, indent=2)
                except:
                    pass
            
            elif self.injection_point.startswith('JSON_PATH:'):
                # Handle nested paths like messages[0].content
                path = self.injection_point.split(':')[1]
                try:
                    body_json = json.loads(self.body)
                    
                    # Parse path: messages[0].content
                    if 'messages' in path:
                        match = re.search(r'messages\[(\d+)\]\.(\w+)', path)
                        if match:
                            idx = int(match.group(1))
                            key = match.group(2)
                            body_json['messages'][idx][key] = '{{ prompt }}'
                    
                    template = json.dumps(body_json, indent=2)
                except:
                    pass
        
        self.body_template = template
    
    def _to_config(self) -> dict:
        """Convert parsed request to scanner config format"""
        # Remove headers that shouldn't be sent
        skip_headers = ['host', 'content-length', 'accept-encoding', 'connection']
        headers = {k: v for k, v in self.headers.items() 
                   if k.lower() not in skip_headers}
        
        return {
            'target': {
                'url': self.url,
                'method': self.method,
                'headers': headers,
                'body_template': self.body_template,
                'response_path': 'auto'  # Will try common paths
            },
            '_parsed': {
                'original_body': self.body,
                'injection_point': self.injection_point,
                'host': self.host,
                'path': self.path
            }
        }
    
    @staticmethod
    def from_burp(filepath: str) -> 'RequestParser':
        """Parse Burp Suite saved request"""
        parser = RequestParser()
        parser.parse_file(filepath)
        return parser
    
    @staticmethod
    def from_curl(curl_command: str) -> dict:
        """
        Parse curl command to config
        
        Example:
            curl -X POST https://api.example.com/chat \
                -H "Authorization: Bearer token" \
                -d '{"message": "hello"}'
        """
        parser = RequestParser()
        
        # Extract URL
        url_match = re.search(r"curl\s+(?:-X\s+\w+\s+)?['\"]?(https?://[^\s'\"]+)", curl_command)
        if url_match:
            parser.url = url_match.group(1)
        
        # Extract method
        method_match = re.search(r'-X\s+(\w+)', curl_command)
        parser.method = method_match.group(1) if method_match else 'GET'
        
        # Extract headers
        for match in re.finditer(r"-H\s+['\"]([^:]+):\s*([^'\"]+)['\"]", curl_command):
            parser.headers[match.group(1)] = match.group(2)
        
        # Extract body
        body_match = re.search(r"(?:-d|--data|--data-raw)\s+['\"](.+?)['\"]", curl_command, re.DOTALL)
        if body_match:
            parser.body = body_match.group(1)
            parser._find_injection_point(None)
            parser._create_body_template()
        
        return parser._to_config()


def create_sample_request_file(filepath: str = "sample_request.txt"):
    """Create a sample request file for testing"""
    sample = """POST /api/v1/chat HTTP/1.1
Host: chatbot.example.com
Content-Type: application/json
Authorization: Bearer YOUR_TOKEN_HERE
Cookie: session=abc123; user=test
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

{"message": "*", "conversation_id": "conv_001", "user_id": "pentester"}"""
    
    with open(filepath, 'w') as f:
        f.write(sample)
    
    print(f"✅ Sample request file created: {filepath}")
    print("   Replace * with your injection point marker")
    print("   Or the tool will auto-detect message fields")


# Test
if __name__ == "__main__":
    # Test with sample request
    sample_request = """POST /api/chat HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer sk-test123

{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}"""
    
    parser = RequestParser()
    config = parser.parse_raw(sample_request)
    
    print("=" * 50)
    print("Parsed Request:")
    print("=" * 50)
    print(f"URL: {config['target']['url']}")
    print(f"Method: {config['target']['method']}")
    print(f"Headers: {json.dumps(config['target']['headers'], indent=2)}")
    print(f"Body Template:\n{config['target']['body_template']}")
    print(f"Injection Point: {config['_parsed']['injection_point']}")
    
    print("\n" + "=" * 50)
    print("Test curl parser:")
    print("=" * 50)
    curl_cmd = '''curl -X POST "https://api.openai.com/v1/chat/completions" -H "Authorization: Bearer sk-xxx" -H "Content-Type: application/json" -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]}'
    '''
    curl_config = RequestParser.from_curl(curl_cmd)
    print(f"URL: {curl_config['target']['url']}")
    print(f"Headers: {curl_config['target']['headers']}")
