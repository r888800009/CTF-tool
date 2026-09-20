#!/usr/bin/env bash
set -euo pipefail

apt-get update -y
apt-get install -y sagemath

python3 -m pip install \
    z3-solver \
    pycryptodome \
    sympy
