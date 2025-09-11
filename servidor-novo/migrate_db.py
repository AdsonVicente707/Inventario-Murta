import sqlite3
import os

# --- Define o caminho absoluto para o banco de dados ---
basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(basedir, 'inventory.db')

def add_column_if_not_exists(db_path, table_name, column_name, column_type):
    """Adiciona uma coluna a uma tabela se ela não existir."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Pega a informação da tabela para verificar as colunas existentes
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [info[1] for info in cursor.fetchall()]
        
        if column_name not in columns:
            print(f"A coluna '{column_name}' não foi encontrada na tabela '{table_name}'. Adicionando...")
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            conn.commit()
            print(f"Coluna '{column_name}' adicionada com sucesso!")
        else:
            print(f"A coluna '{column_name}' já existe na tabela '{table_name}'. Nenhuma alteração necessária.")
            
    except sqlite3.Error as e:
        print(f"Ocorreu um erro no banco de dados: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    print("Iniciando a verificação e migração do banco de dados...")
    
    if not os.path.exists(DATABASE_PATH):
        print(f"Erro: O arquivo de banco de dados 'inventory.db' não foi encontrado em '{basedir}'.")
        print("Certifique-se de que o script está na mesma pasta que o seu 'app.py'.")
    else:
        add_column_if_not_exists(DATABASE_PATH, 'items', 'model', 'TEXT')
        add_column_if_not_exists(DATABASE_PATH, 'items', 'availability_status', 'TEXT')
        add_column_if_not_exists(DATABASE_PATH, 'users', 'role', "TEXT NOT NULL DEFAULT 'user'")

    print("\nVerificação concluída. Seu banco de dados está atualizado!")
