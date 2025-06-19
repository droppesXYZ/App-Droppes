#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de Backup Automático - Droppes App
Protege contra perda de dados com backups automáticos
"""

import os
import shutil
import sqlite3
import datetime
import logging
from pathlib import Path

class BackupManager:
    def __init__(self):
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
        self.max_backups = 10  # Manter apenas os 10 backups mais recentes
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def create_backup(self, db_path="app.db"):
        """Criar backup do banco de dados"""
        try:
            if not os.path.exists(db_path):
                self.logger.warning(f"Banco {db_path} não encontrado")
                return False
            
            # Nome do backup com timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}.db"
            backup_path = self.backup_dir / backup_name
            
            # Fazer backup usando SQLite3
            if db_path.endswith('.db'):
                self._backup_sqlite(db_path, str(backup_path))
            else:
                # Para outros tipos, fazer cópia simples
                shutil.copy2(db_path, backup_path)
            
            self.logger.info(f"✅ Backup criado: {backup_path}")
            
            # Limpar backups antigos
            self._cleanup_old_backups()
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao criar backup: {str(e)}")
            return False

    def _backup_sqlite(self, source_path, backup_path):
        """Fazer backup seguro de SQLite"""
        source_conn = sqlite3.connect(source_path)
        backup_conn = sqlite3.connect(backup_path)
        
        try:
            # Usar o método backup do SQLite para segurança
            source_conn.backup(backup_conn)
            self.logger.info(f"Backup SQLite concluído: {backup_path}")
        finally:
            source_conn.close()
            backup_conn.close()

    def _cleanup_old_backups(self):
        """Remover backups antigos, mantendo apenas os mais recentes"""
        try:
            backup_files = list(self.backup_dir.glob("backup_*.db"))
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Remover backups excedentes
            for old_backup in backup_files[self.max_backups:]:
                old_backup.unlink()
                self.logger.info(f"🗑️ Backup antigo removido: {old_backup.name}")
                
        except Exception as e:
            self.logger.error(f"❌ Erro na limpeza de backups: {str(e)}")

    def restore_backup(self, backup_name, target_path="app.db"):
        """Restaurar backup"""
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                self.logger.error(f"Backup {backup_name} não encontrado")
                return False
            
            # Fazer backup do arquivo atual antes de restaurar
            if os.path.exists(target_path):
                current_backup = f"pre_restore_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                shutil.copy2(target_path, self.backup_dir / current_backup)
                self.logger.info(f"Backup preventivo criado: {current_backup}")
            
            # Restaurar
            shutil.copy2(backup_path, target_path)
            self.logger.info(f"✅ Backup restaurado: {backup_name} -> {target_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao restaurar backup: {str(e)}")
            return False

    def list_backups(self):
        """Listar backups disponíveis"""
        try:
            backup_files = list(self.backup_dir.glob("backup_*.db"))
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            if not backup_files:
                print("📁 Nenhum backup encontrado")
                return []
            
            print("📋 Backups disponíveis:")
            backups_info = []
            
            for backup_file in backup_files:
                stat = backup_file.stat()
                size_mb = stat.st_size / (1024 * 1024)
                modified = datetime.datetime.fromtimestamp(stat.st_mtime)
                
                info = {
                    'name': backup_file.name,
                    'size_mb': round(size_mb, 2),
                    'date': modified.strftime('%Y-%m-%d %H:%M:%S')
                }
                backups_info.append(info)
                
                print(f"  📄 {info['name']} - {info['size_mb']}MB - {info['date']}")
            
            return backups_info
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao listar backups: {str(e)}")
            return []

    def auto_backup_if_needed(self, db_path="app.db"):
        """Criar backup automático se necessário"""
        try:
            if not os.path.exists(db_path):
                return False
            
            # Verificar se já existe um backup recente (últimas 24h)
            backup_files = list(self.backup_dir.glob("backup_*.db"))
            now = datetime.datetime.now()
            
            recent_backup = False
            for backup_file in backup_files:
                backup_time = datetime.datetime.fromtimestamp(backup_file.stat().st_mtime)
                if (now - backup_time).total_seconds() < 24 * 3600:  # 24 horas
                    recent_backup = True
                    break
            
            if not recent_backup:
                self.logger.info("🔄 Criando backup automático...")
                return self.create_backup(db_path)
            else:
                self.logger.info("✅ Backup recente encontrado, pulando...")
                return True
                
        except Exception as e:
            self.logger.error(f"❌ Erro no backup automático: {str(e)}")
            return False

def main():
    """Função principal para uso em linha de comando"""
    import sys
    
    backup_manager = BackupManager()
    
    if len(sys.argv) < 2:
        print("Uso: python backup_manager.py [create|list|restore|auto]")
        return
    
    command = sys.argv[1]
    
    if command == "create":
        db_path = sys.argv[2] if len(sys.argv) > 2 else "app.db"
        success = backup_manager.create_backup(db_path)
        exit(0 if success else 1)
        
    elif command == "list":
        backup_manager.list_backups()
        
    elif command == "restore":
        if len(sys.argv) < 3:
            print("Uso: python backup_manager.py restore <nome_do_backup>")
            return
        backup_name = sys.argv[2]
        target = sys.argv[3] if len(sys.argv) > 3 else "app.db"
        success = backup_manager.restore_backup(backup_name, target)
        exit(0 if success else 1)
        
    elif command == "auto":
        db_path = sys.argv[2] if len(sys.argv) > 2 else "app.db"
        success = backup_manager.auto_backup_if_needed(db_path)
        exit(0 if success else 1)
        
    else:
        print("Comando inválido. Use: create, list, restore ou auto")

if __name__ == "__main__":
    main() 