import sqlite3
import os
from werkzeug.security import generate_password_hash

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
 
def create_requests_table_if_not_exists(db_path):
    """Cria a tabela de requisições de itens se ela não existir."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Verificando a existência da tabela 'item_requests'...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS item_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                request_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'Pendente', -- Pendente, Aprovado, Recusado
                notes TEXT,
                FOREIGN KEY (item_id) REFERENCES items (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        print("Tabela 'item_requests' verificada/criada com sucesso.")
    except sqlite3.Error as e:
        print(f"Ocorreu um erro no banco de dados ao criar a tabela de requisições: {e}")

def create_notifications_table_if_not_exists(db_path):
    """Cria a tabela de notificações se ela não existir."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Verificando a existência da tabela 'notifications'...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                link TEXT,
                is_read INTEGER NOT NULL DEFAULT 0, -- 0 para não lida, 1 para lida
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        print("Tabela 'notifications' verificada/criada com sucesso.")
    except sqlite3.Error as e:
        print(f"Ocorreu um erro no banco de dados ao criar a tabela de notificações: {e}")

def create_or_update_default_admin(db_path):
    """Cria ou atualiza o usuário administrador padrão para garantir que ele exista e tenha os dados corretos."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verifica se o usuário 'admin' já existe
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
 
        # Criptografa a senha padrão
        hashed_password = generate_password_hash('admin123')
 
        if admin_user is None:
            print("Usuário 'admin' padrão não encontrado. Criando...")
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin', hashed_password, 'admin')
            )
            print("Usuário 'admin' criado com sucesso com a senha 'admin123'.")
        else:
            print("Usuário 'admin' padrão encontrado. Atualizando senha e papel para garantir o acesso...")
            cursor.execute(
                "UPDATE users SET password = ?, role = ? WHERE username = ?",
                (hashed_password, 'admin', 'admin')
            )
            print("Usuário 'admin' atualizado com sucesso.")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Ocorreu um erro no banco de dados ao criar o admin padrão: {e}")
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
        
        # Garante que o usuário admin padrão exista
        create_or_update_default_admin(DATABASE_PATH)

        # Garante que a tabela de requisições exista
        create_requests_table_if_not_exists(DATABASE_PATH)

        # Garante que a tabela de notificações exista
        create_notifications_table_if_not_exists(DATABASE_PATH)
 
    print("\nVerificação concluída. Seu banco de dados está atualizado!")
