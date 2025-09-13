from setuptools import setup, find_packages

setup(
    name="wifi-sprite",
    version="1.0.0",
    description="WiFi Security Analyzer - Educational cybersecurity tool",
    author="WiFi Sprite Team",
    packages=find_packages(),
    install_requires=[
        "scapy==2.5.0",
        "psutil==5.9.6",
        "requests==2.31.0",
        "cryptography==41.0.7",
        "netifaces==0.11.0"
    ],
    entry_points={
        'console_scripts': [
            'wifi-sprite=src.main:main',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
    ],
)