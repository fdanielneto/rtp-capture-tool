#!/usr/bin/env python3
"""
Script para verificar TODOS os atributos .timestamp no código e reportar onde ainda existem.

Este script identifica qualquer ocorrência de .timestamp que não deveria existir
(deveria ser .ts no contexto de SipMessage).
"""

import re
from pathlib import Path

project_root = Path(__file__).parent.parent

def scan_for_timestamp_bugs():
    """Verifica todos os arquivos Python por possíveis bugs de .timestamp"""
    
    issues_found = []
    
    # Padrões a procurar
    patterns = [
        (r'\.timestamp(?!s)', 'Uso de .timestamp (deveria ser .ts)'),
        (r'lambda\s+\w+:\s+\w+\.timestamp', 'Lambda com .timestamp'),
        (r'sort\(key=lambda.*\.timestamp\)', 'Sort com .timestamp'),
        (r'sorted\(.*key=lambda.*\.timestamp\)', 'Sorted com .timestamp'),
    ]
    
    # Arquivos Python relevantes
    py_files = list(project_root.rglob("rtphelper/**/*.py"))
    py_files.extend(project_root.rglob("scripts/*.py"))
    
    print(f"Verificando {len(py_files)} arquivos Python...\n")
    
    for py_file in py_files:
        try:
            content = py_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in patterns:
                    if re.search(pattern, line):
                        # Ignorar comentários
                        if not line.strip().startswith('#'):
                            issues_found.append({
                                'file': py_file.relative_to(project_root),
                                'line': line_num,
                                'content': line.strip(),
                                'issue': description
                            })
        except Exception as e:
            print(f"Erro ao processar {py_file}: {e}")
    
    return issues_found


def main():
    print("="*70)
    print("VERIFICAÇÃO DE BUGS .timestamp")
    print("="*70)
    print()
    
    issues = scan_for_timestamp_bugs()
    
    if not issues:
        print("✅ NENHUM BUG ENCONTRADO!")
        print("\nTodos os usos de .timestamp foram corrigidos para .ts")
        print("\n⚠️  Se o erro persiste, execute:")
        print("1. python scripts/clear_python_cache.py")
        print("2. Reinicie TODOS os processos Python")
        print("3. Verifique se não há múltiplas instalações do pacote")
        return 0
    
    print(f"❌ ENCONTRADOS {len(issues)} PROBLEMAS:\n")
    
    for issue in issues:
        print(f"Arquivo: {issue['file']}")
        print(f"Linha {issue['line']}: {issue['issue']}")
        print(f"  Código: {issue['content']}")
        print()
    
    print("="*70)
    print("AÇÃO NECESSÁRIA")
    print("="*70)
    print("\nCorreções automatizadas disponíveis:\n")
    print("Para cada arquivo listado acima:")
    print("  1. Abrir o arquivo")
    print("  2. Buscar pela linha indicada")
    print("  3. Substituir .timestamp por .ts")
    print("\nOu use o comando:")
    print("  sed -i '' 's/\\.timestamp/.ts/g' <arquivo>")
    
    return 1


if __name__ == "__main__":
    exit(main())
