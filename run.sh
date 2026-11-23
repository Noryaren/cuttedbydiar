#!/usr/bin/env bash
# Wrapper script for cuttedbydiar on Linux
# Automatically handles root privileges and virtual environment Python.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run with sudo: sudo ./run.sh gui"
  echo "    or: sudo ./run.sh scan"
  exit 1
fi

if [ ! -d "venv" ]; then
  echo "[+] Creating virtual environment..."
  python3 -m venv venv
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install -r requirements.txt
fi

exec ./venv/bin/python run.py "$@"
