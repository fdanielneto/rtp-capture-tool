#!/usr/bin/env python3
"""
Diagnóstico completo do ambiente para identificar fonte do bug AttributeError.

Este script verifica:
1. Qual versão do código está sendo importada
2. Se há cache Python problemático
3. Se há instalações pip conflitantes
4. Se o código fonte está correto
"""

import os
import sys
from pathlib import Path
import importlib.util
import subprocess

def main():
    print("="*80)
    print("DIAGNÓSTICO COMPLETO - AttributeError Bug")
    print("="*80)
    print()
    
    # 1. Verificar qual Python está sendo usado
    print("1. PYTHON ENVIRONMENT")
    print("-" * 80)
    print(f"Python executable: {sys.executable}")
    print(f"Python version: {sys.version}")
    print(f"Is venv: {hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix}")
    print()
    
    # 2. Verificar onde rtphelper está instalado
    print("2. RTPHELPER MODULE LOCATION")
    print("-" * 80)
    try:
        import rtphelper
        print(f"✅ rtphelper imported from: {rtphelper.__file__}")
        
        # Verificar se é do source ou site-packages
        rtphelper_path = Path(rtphelper.__file__)
        if 'site-packages' in str(rtphelper_path):
            print("⚠️  WARNING: Module loaded from site-packages (pip installed)")
            print("   This may override your source code changes!")
        elif '.venv' in str(rtphelper_path):
            print("⚠️  WARNING: Module in venv but might be pip-installed")
        else:
            print("✅ Module loaded from source directory")
        
        # Verificar sip_correlation.py especificamente
        import rtphelper.services.sip_correlation as sc
        print(f"✅ sip_correlation module: {sc.__file__}")
    except ImportError as e:
        print(f"❌ Cannot import rtphelper: {e}")
        return 1
    print()
    
    # 3. Verificar código fonte
    print("3. SOURCE CODE VERIFICATION")
    print("-" * 80)
    project_root = Path(__file__).parent.parent
    sip_correlation_src = project_root / "rtphelper" / "services" / "sip_correlation.py"
    
    if sip_correlation_src.exists():
        content = sip_correlation_src.read_text()
        timestamp_count = content.count('.timestamp')
        
        # Excluir comentários e métodos legítimos
        lines_with_timestamp = []
        for i, line in enumerate(content.split('\n'), 1):
            if '.timestamp' in line:
                stripped = line.strip()
                # Ignorar comentários e métodos datetime.timestamp()
                if not stripped.startswith('#') and '.timestamp()' not in line:
                    lines_with_timestamp.append((i, line))
        
        if lines_with_timestamp:
            print(f"❌ BUGS FOUND: {len(lines_with_timestamp)} linha(s) com .timestamp")
            for line_num, line in lines_with_timestamp:
                print(f"   Linha {line_num}: {line.strip()}")
        else:
            print("✅ Source code is correct (no .timestamp bugs)")
    else:
        print(f"❌ Source file not found: {sip_correlation_src}")
    print()
    
    # 4. Verificar instalação pip
    print("4. PIP INSTALLATION CHECK")
    print("-" * 80)
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', 'rtphelper'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("⚠️  rtphelper IS pip-installed:")
            print(result.stdout)
            print("\n💡 SOLUTION: Uninstall and reinstall in editable mode:")
            print(f"   {sys.executable} -m pip uninstall rtphelper")
            print(f"   {sys.executable} -m pip install -e .")
        else:
            print("✅ rtphelper is NOT pip-installed (good)")
    except Exception as e:
        print(f"⚠️  Could not check pip: {e}")
    print()
    
    # 5. Verificar cache Python
    print("5. PYTHON CACHE CHECK")
    print("-" * 80)
    cache_dirs = list(project_root.rglob("**/__pycache__"))
    if cache_dirs:
        print(f"⚠️  Found {len(cache_dirs)} __pycache__ directories")
        print("   Cache may contain old bytecode")
        print("\n💡 SOLUTION: Run cache clearing script:")
        print(f"   python scripts/clear_python_cache.py")
    else:
        print("✅ No __pycache__ directories found")
    print()
    
    # 6. Verificar código compilado no módulo carregado
    print("6. RUNTIME CODE INSPECTION")
    print("-" * 80)
    try:
        import rtphelper.services.sip_correlation as sc
        import inspect
        
        # Tentar inspecionar ConfigurableCorrelator.correlate
        if hasattr(sc, 'ConfigurableCorrelator'):
            cls = sc.ConfigurableCorrelator
            if hasattr(cls, 'correlate'):
                source = inspect.getsource(cls.correlate)
                
                # Procurar por .timestamp no código carregado
                if '.timestamp' in source and 'datetime' not in source:
                    print("❌ RUNTIME CODE HAS BUG: .timestamp found in loaded code")
                    print("   This means Python is using OLD bytecode or pip version")
                    print()
                    # Mostrar linhas problemáticas
                    for i, line in enumerate(source.split('\n'), 1):
                        if '.timestamp' in line and not line.strip().startswith('#'):
                            print(f"   Line {i}: {line}")
                else:
                    print("✅ Runtime code looks correct (no .timestamp found)")
            else:
                print("⚠️  correlate method not found")
        else:
            print("⚠️  ConfigurableCorrelator class not found")
    except Exception as e:
        print(f"⚠️  Could not inspect runtime code: {e}")
    print()
    
    # 7. Recomendações finais
    print("="*80)
    print("RECOMMENDED ACTIONS")
    print("="*80)
    print()
    print("Execute these commands in order:")
    print()
    print("1. Uninstall pip version (if installed):")
    print(f"   {sys.executable} -m pip uninstall rtphelper -y")
    print()
    print("2. Clear all Python cache:")
    print(f"   python scripts/clear_python_cache.py")
    print()
    print("3. Reinstall in editable mode:")
    print(f"   {sys.executable} -m pip install -e .")
    print()
    print("4. Restart application:")
    print("   - Kill ALL Python processes")
    print("   - Start fresh with: uvicorn rtphelper.web.app:app --reload")
    print()
    print("5. Test correlation:")
    print("   - Upload PCAP that previously failed")
    print("   - Check logs for 'Case matched' message")
    print("   - Should NOT see 'falling back to legacy'")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
