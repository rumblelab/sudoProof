#!/bin/bash
# Install pyOpenSSL first to avoid build errors
pip install --upgrade pip setuptools wheel
pip install pyOpenSSL==23.2.0
pip install -r requirements.txt