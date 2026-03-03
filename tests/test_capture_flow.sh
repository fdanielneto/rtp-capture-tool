#!/bin/bash

# Script de teste para verificar lista de ficheiros RTP capturados
# Execute: chmod +x test_capture_flow.sh && ./test_capture_flow.sh

set -e

echo "🧪 Teste de Fluxo de Captura - Lista de Ficheiros RTP"
echo "=================================================="
echo ""

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}📋 Passo 1: Preparação${NC}"
echo "  - Certifique-se de que não há capturas em execução"
echo "  - Abra o browser em http://localhost:8000 ou a porta configurada"
echo ""

echo -e "${YELLOW}📋 Passo 2: Iniciar Captura${NC}"
echo "  1. Selecione environment (e.g., PRD)"
echo "  2. Selecione region (e.g., US)"
echo "  3. Selecione sub-region (e.g., us-east-1)"
echo "  4. Deixe 'all' marcado para hosts"
echo "  5. Clique em 'Start Capture'"
echo "  6. Aguarde 5-10 segundos (para capturar alguns pacotes)"
echo ""

echo -e "${YELLOW}📋 Passo 3: Parar Captura${NC}"
echo "  1. Clique no botão 'Stop Capture' (⏹)"
echo "  2. Aguarde o processamento (1-3 segundos)"
echo ""

echo -e "${YELLOW}📋 Passo 4: Verificações (CRÍTICO)${NC}"
echo "  Abra o Browser DevTools (F12) → Console tab"
echo ""
echo "  Verificar LOGS da consola:"
echo "  ✓ Deve ver: 'Stop capture response: {...}'"
echo "  ✓ Deve ver: 'raw_files: {...}' com conteúdo"
echo "  ✓ Deve ver: 'renderRawFiles called with: {...}'"
echo "  ✓ Deve ver: 'rawFiles.hidden: false'"
echo "  ✓ Deve ver: '✅ RAW FILES SHOULD BE VISIBLE'"
echo ""
echo "  Se vir ALERT:"
echo "  ❌ 'rawFiles is hidden or empty' → Problema no backend ou lógica"
echo "  ❌ 'rawFiles is hidden by CSS' → Problema de estilo"
echo ""

echo -e "${YELLOW}📋 Passo 5: Verificação Visual${NC}"
echo "  Na secção 'Correlate Call (SIP -> RTP/SRTP)':"
echo ""
echo "  ✅ DEVE VER:"
echo "    - 'Files are stored in: /caminho/para/ficheiros'"
echo "    - 'Captured RTP Files' (título h4)"
echo "    - Lista expandível por host (▼ prd-xxx-rtpengine-1)"
echo "    - Links de ficheiros .pcap sob cada host"
echo ""
echo "  ❌ SE NÃO VIR:"
echo "    - Painel 'Correlate Call' não está visível → postSection hidden"
echo "    - Vê localização mas não vê lista → rawFiles hidden ou vazio"
echo "    - Não vê nada → Problema grave"
echo ""

echo -e "${YELLOW}📋 Passo 6: Verificação via DevTools Elements${NC}"
echo "  No DevTools → Elements tab:"
echo ""
echo "  1. Procure por '<section class=\"panel\" id=\"postSection\"'"
echo "     → Não deve ter atributo 'hidden'"
echo "     → Styles devem mostrar display: block (ou similar)"
echo ""
echo "  2. Dentro de postSection, procure '<div id=\"rawFiles\"'"
echo "     → Não deve ter atributo 'hidden'"
echo "     → innerHTML deve conter HTML da lista"
echo "     → Styles devem mostrar display: block, visibility: visible"
echo ""

echo -e "${YELLOW}📋 Passo 7: Debug Extra (se ainda não aparecer)${NC}"
echo "  Na Console do browser, execute:"
echo ""
echo "    document.getElementById('rawFiles').hidden"
echo "    document.getElementById('rawFiles').innerHTML.length"
echo "    window.getComputedStyle(document.getElementById('rawFiles')).display"
echo "    window.getComputedStyle(document.getElementById('rawFiles')).visibility"
echo "    document.getElementById('postSection').hidden"
echo ""
echo "  Copie os resultados e analise:"
echo "    - hidden: deve ser 'false'"
echo "    - innerHTML.length: deve ser > 100"
echo "    - display: deve ser 'block' ou '' (não 'none')"
echo "    - visibility: deve ser 'visible' (não 'hidden')"
echo ""

echo -e "${GREEN}📋 Passo 8: Teste Standalone${NC}"
echo "  Abra o ficheiro test_rawfiles_visibility.html diretamente no browser:"
echo "    open test_rawfiles_visibility.html"
echo ""
echo "  Este teste elimina toda a complexidade da app principal."
echo "  Se funcionar aqui mas não na app → problema no fluxo da app"
echo "  Se não funcionar aqui → problema no browser/CSS"
echo ""

echo -e "${GREEN}✅ Teste Completo!${NC}"
echo ""
echo "Se após todos estes passos a lista NÃO aparecer,"
echo "copie TODOS os logs da console e partilhe para análise."
echo ""
