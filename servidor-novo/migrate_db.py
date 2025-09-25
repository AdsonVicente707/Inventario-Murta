import sqlite3
import os
from werkzeug.security import generate_password_hash

# --- Define o caminho absoluto para o banco de dados ---
basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(basedir, 'inventory.db')

def add_column_if_not_exists(cursor, table_name, column_name, column_type):
    """Adiciona uma coluna a uma tabela se ela não existir."""
    # Pega a informação da tabela para verificar as colunas existentes
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [info[1] for info in cursor.fetchall()]
    
    if column_name not in columns:
        print(f"A coluna '{column_name}' não foi encontrada na tabela '{table_name}'. Adicionando...")
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        print(f"Coluna '{column_name}' adicionada com sucesso!")
    else:
        print(f"A coluna '{column_name}' já existe na tabela '{table_name}'. Nenhuma alteração necessária.")

def create_users_table_if_not_exists(cursor):
    """Cria a tabela de usuários se ela não existir."""
    print("Verificando a existência da tabela 'users'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)
    print("Tabela 'users' verificada/criada com sucesso.")

def create_items_table_if_not_exists(cursor):
    """Cria a tabela de itens se ela não existir."""
    print("Verificando a existência da tabela 'items'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                model TEXT,
                category TEXT,
                location TEXT,
                purchase_date DATE,
                serial_number TEXT,
                status TEXT,
                availability_status TEXT,
                image_file TEXT,
                assigned_to TEXT,
                authorized_by TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
    print("Tabela 'items' verificada/criada com sucesso.")
 
def create_requests_table_if_not_exists(cursor):
    """Cria a tabela de requisições de itens se ela não existir."""
    print("Verificando a existência da tabela 'item_requests'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS item_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                request_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'Pendente', -- Pendente, Aprovado, Recusado
                notes TEXT,
                response_notes TEXT, -- Adicionado para justificativa do admin
                return_notes TEXT,   -- Adicionado para justificativa do usuário na devolução
                FOREIGN KEY (item_id) REFERENCES items (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
    print("Tabela 'item_requests' verificada/criada com sucesso.")

def create_notifications_table_if_not_exists(cursor):
    """Cria a tabela de notificações se ela não existir."""
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

def create_stock_settings_table_if_not_exists(cursor):
    """Cria a tabela para configurações de nível de estoque por categoria."""
    print("Verificando a existência da tabela 'category_stock_settings'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS category_stock_settings (
                category_name TEXT PRIMARY KEY,
                min_stock_level INTEGER NOT NULL DEFAULT 0,
                last_notified_at TIMESTAMP
            )
        """)
    print("Tabela 'category_stock_settings' verificada/criada com sucesso.")

def create_activity_log_table_if_not_exists(cursor):
    """Cria a tabela de log de atividades se ela não existir."""
    print("Verificando a existência da tabela 'activity_log'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT,
                item_id INTEGER,
                item_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
    print("Tabela 'activity_log' verificada/criada com sucesso.")

def create_status_history_table_if_not_exists(cursor):
    """Cria a tabela de histórico de status dos itens se ela não existir."""
    print("Verificando a existência da tabela 'status_history'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                item_name TEXT,
                old_status TEXT,
                new_status TEXT,
                notes TEXT,
                changed_by_user_id INTEGER,
                changed_by_username TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE,
                FOREIGN KEY (changed_by_user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
    print("Tabela 'status_history' verificada/criada com sucesso.")

def create_or_update_default_admin(cursor):
    """Cria ou atualiza o usuário administrador padrão para garantir que ele exista e tenha os dados corretos."""
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

def main():
    """Função principal para executar a migração do banco de dados."""
    print("Iniciando a verificação e migração do banco de dados...")
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # 1. Garante que todas as tabelas existam (cria o DB se necessário)
        create_users_table_if_not_exists(cursor)
        create_items_table_if_not_exists(cursor)
        create_requests_table_if_not_exists(cursor)
        create_notifications_table_if_not_exists(cursor)
        create_stock_settings_table_if_not_exists(cursor)
        create_activity_log_table_if_not_exists(cursor)
        create_status_history_table_if_not_exists(cursor)

        # 2. Adiciona colunas que podem estar faltando em instalações antigas
        add_column_if_not_exists(cursor, 'items', 'model', 'TEXT')
        add_column_if_not_exists(cursor, 'items', 'availability_status', 'TEXT')
        add_column_if_not_exists(cursor, 'users', 'role', "TEXT NOT NULL DEFAULT 'user'")
        add_column_if_not_exists(cursor, 'item_requests', 'response_notes', 'TEXT')
        add_column_if_not_exists(cursor, 'item_requests', 'return_notes', 'TEXT')
        add_column_if_not_exists(cursor, 'users', 'profile_image_file', 'TEXT')

        # 3. Garante que o usuário admin padrão exista e esteja atualizado
        create_or_update_default_admin(cursor)

        conn.commit()
        print("\nVerificação concluída. Seu banco de dados está atualizado!")
    except sqlite3.Error as e:
        print(f"Ocorreu um erro no banco de dados durante a migração: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()
