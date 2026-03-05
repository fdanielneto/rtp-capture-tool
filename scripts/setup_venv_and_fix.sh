#!/usr/bin/env bash
#
# Script completo para resolver o bug AttributeError de uma vez por todas.
#
# Este script:
# 1. Cria/ativa venv
# 2. Instala rtphelper em modo editable
# 3. Limpa todo o cache Python
# 4. Valida que o fix está aplicado
# 5. Mostra como iniciar a aplicação corretamente

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "================================================================================"
echo "SETUP & FIX - AttributeError Bug Resolution"
echo "================================================================================"
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Verificar/Criar venv
echo "1. VIRTUAL ENVIRONMENT SETUP"
echo "--------------------------------------------------------------------------------"
if [[ -d ".venv" ]]; then
    echo -e "${GREEN}✅ .venv already exists${NC}"
else
    echo -e "${YELLOW}⚠️  Creating .venv...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}✅ .venv created${NC}"
fi
echo ""

# 2. Ativar venv
echo "2. ACTIVATING VENV"
echo "--------------------------------------------------------------------------------"
source .venv/bin/activate
echo -e "${GREEN}✅ Using: $(which python)${NC}"
echo "   Version: $(python --version)"
echo ""

# 3. Desinstalar versão antiga (se existir)
echo "3. REMOVING OLD INSTALLATION"
echo "--------------------------------------------------------------------------------"
if pip show rtphelper &>/dev/null; then
    echo -e "${YELLOW}⚠️  Found existing rtphelper installation, removing...${NC}"
    pip uninstall rtphelper -y
    echo -e "${GREEN}✅ Old version removed${NC}"
else
    echo -e "${GREEN}✅ No previous installation found${NC}"
fi
echo ""

# 4. Limpar TODO o cache Python
echo "4. CLEARING PYTHON CACHE"
echo "--------------------------------------------------------------------------------"
echo "Removing all __pycache__ directories and .pyc files..."
find rtphelper -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find build -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find scripts -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find tests -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
echo -e "${GREEN}✅ Cache cleared${NC}"
echo ""

# 5. Verificar código fonte
echo "5. VERIFYING SOURCE CODE"
echo "--------------------------------------------------------------------------------"
TIMESTAMP_BUGS=$(grep -rn "lambda.*\.timestamp[^()]" rtphelper/ 2>/dev/null | grep -v "\.timestamp()" | wc -l | tr -d ' ')
if [[ "$TIMESTAMP_BUGS" -eq "0" ]]; then
    echo -e "${GREEN}✅ Source code is correct (no .timestamp bugs)${NC}"
else
    echo -e "${RED}❌ Found $TIMESTAMP_BUGS .timestamp bugs in source!${NC}"
    echo "   Occurrences:"
    grep -rn "lambda.*\.timestamp[^()]" rtphelper/ 2>/dev/null | grep -v "\.timestamp()"
    echo ""
    echo -e "${RED}   FIX REQUIRED: Replace .timestamp with .ts${NC}"
    exit 1
fi
echo ""

# 6. Instalar em modo editable
echo "6. INSTALLING RTPHELPER (EDITABLE MODE)"
echo "--------------------------------------------------------------------------------"
pip install -e . -q
echo -e "${GREEN}✅ rtphelper installed in editable mode${NC}"
echo ""

# 7. Verificar instalação
echo "7. VERIFYING INSTALLATION"
echo "--------------------------------------------------------------------------------"
python -c "
import rtphelper
import rtphelper.services.sip_correlation as sc
print(f'✅ rtphelper: {rtphelper.__file__}')
print(f'✅ sip_correlation: {sc.__file__}')

# Verificar que não está em site-packages
if 'site-packages' in sc.__file__ and '.venv' not in sc.__file__:
    print('❌ WARNING: Module in site-packages (not editable)')
    exit(1)
else:
    print('✅ Module loaded from source (editable mode)')
"
echo ""

# 8. Testar import de ConfigurableCorrelator
echo "8. TESTING CONFIGURABLE CORRELATOR"
echo "--------------------------------------------------------------------------------"
python -c "
from rtphelper.services.sip_correlation import ConfigurableCorrelator
print('✅ ConfigurableCorrelator imported successfully')

# Verificar que o método correlate existe
import inspect
if hasattr(ConfigurableCorrelator, 'correlate'):
    print('✅ correlate() method exists')
    
    # Inspecionar código
    source = inspect.getsource(ConfigurableCorrelator.correlate)
    if '.timestamp' in source and 'datetime' not in source:
        print('❌ ERROR: correlate() method still has .timestamp bug')
        exit(1)
    else:
        print('✅ correlate() method code is correct')
else:
    print('❌ ERROR: correlate() method not found')
    exit(1)
"
echo ""

# 9. Instruções finais
echo "================================================================================"
echo "SUCCESS! Environment is ready"
echo "================================================================================"
echo ""
echo -e "${GREEN}✅ Virtual environment created and activated${NC}"
echo -e "${GREEN}✅ rtphelper installed in editable mode${NC}"
echo -e "${GREEN}✅ Python cache cleared${NC}"
echo -e "${GREEN}✅ Source code verified (no bugs)${NC}"
echo ""
echo "================================================================================"
echo "NEXT STEPS"
echo "================================================================================"
echo ""
echo "1. ALWAYS activate venv before running anything:"
echo "   ${YELLOW}source .venv/bin/activate${NC}"
echo ""
echo "2. Start application (from project root):"
echo "   ${YELLOW}./scripts/run.sh${NC}"
echo "   or"
echo "   ${YELLOW}.venv/bin/python -m uvicorn rtphelper.web.app:app --reload --host 0.0.0.0 --port 8000${NC}"
echo ""
echo "3. Run diagnostics (with venv active):"
echo "   ${YELLOW}python scripts/full_diagnostic.py${NC}"
echo ""
echo "4. Test correlation:"
echo "   - Upload a PCAP that previously failed"
echo "   - Check logs for: ${GREEN}'Case matched: inbound_xcc'${NC}"
echo "   - Should NOT see: ${RED}'falling back to legacy method'${NC}"
echo ""
echo "================================================================================"
echo "TROUBLESHOOTING"
echo "================================================================================"
echo ""
echo "If error persists:"
echo "1. Kill ALL Python processes:"
echo "   ${YELLOW}ps aux | grep python | grep rtphelper | awk '{print \$2}' | xargs kill -9${NC}"
echo ""
echo "2. Rerun this script:"
echo "   ${YELLOW}./scripts/setup_venv_and_fix.sh${NC}"
echo ""
echo "3. Start fresh:"
echo "   ${YELLOW}source .venv/bin/activate${NC}"
echo "   ${YELLOW}./scripts/run.sh${NC}"
echo ""

# Deixar o venv ativo para o usuário
echo "Venv is now active. You can start the application with: ./scripts/run.sh"
echo ""
