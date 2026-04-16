#!/usr/bin/env python3
"""
Script para limpar cache Python e forçar recompilação dos módulos.

Uso:
    python scripts/clear_python_cache.py
"""

import os
import shutil
from pathlib import Path

project_root = Path(__file__).parent.parent

def clear_pycache_dirs():
    """Remove todos os diretórios __pycache__"""
    count = 0
    for pycache_dir in project_root.rglob("__pycache__"):
        if pycache_dir.is_dir():
            print(f"Removendo: {pycache_dir}")
            shutil.rmtree(pycache_dir, ignore_errors=True)
            count += 1
    return count

def clear_pyc_files():
    """Remove todos os arquivos .pyc individuais"""
    count = 0
    for pyc_file in project_root.rglob("*.pyc"):
        if pyc_file.is_file():
            print(f"Removendo: {pyc_file}")
            pyc_file.unlink(missing_ok=True)
            count += 1
    return count

def main():
    print("="*70)
    print("LIMPEZA DE CACHE PYTHON")
    print("="*70)
    print(f"\nDiretório: {project_root}\n")
    
    # Limpar __pycache__
    print("Removendo diretórios __pycache__...")
    pycache_count = clear_pycache_dirs()
    print(f"✓ {pycache_count} diretórios __pycache__ removidos\n")
    
    # Limpar .pyc
    print("Removendo arquivos .pyc...")
    pyc_count = clear_pyc_files()
    print(f"✓ {pyc_count} arquivos .pyc removidos\n")
    
    print("="*70)
    print("LIMPEZA CONCLUÍDA")
    print("="*70)
    print("\n⚠️  IMPORTANTE: Reinicie a aplicação para carregar código atualizado!")
    print("\nPassos:")
    print("1. Parar todos os processos Python (web app, workers)")
    print("2. Reiniciar a aplicação")
    print("3. Testar novamente a correlação")
    
    return 0

if __name__ == "__main__":
    exit(main())
