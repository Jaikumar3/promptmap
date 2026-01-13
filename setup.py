#!/usr/bin/env python3
"""
Setup script for promptmap
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="promptmap",
    version="2.0.0",
    author="Jai",
    description="LLM Security Testing Tool for Prompt Injection Vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Jaikumar3/promptmap",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.25.0",
        "asyncio-throttle>=1.0.2",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "aiofiles>=23.0.0",
        "python-dotenv>=1.0.0",
        "click>=8.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "isort>=5.12.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "promptmap=promptmap.cli:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "llm", "security", "prompt-injection", "jailbreak", 
        "red-team", "penetration-testing", "ai-safety"
    ],
)
