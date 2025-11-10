import mysql.connector
import os
from werkzeug.security import generate_password_hash

# --- Configuração do Banco de Dados MySQL ---
# **IMPORTANTE**: Use as mesmas credenciais do seu app.py.
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root', # <-- COLOQUE SEU USUÁRIO REAL DO MYSQL AQUI
    'password': 'sua_senha_real', # <-- SUBSTITUA PELA SUA SENHA REAL DO MYSQL AQUI
    'database': 'inventory_db' # O script vai criar este DB se não existir
}

def add_column_if_not_exists(cursor, table_name, column_name, column_type):
    """Adiciona uma coluna a uma tabela se ela não existir."""
    cursor.execute(f"SHOW COLUMNS FROM `{table_name}` LIKE '{column_name}'")
    exists = cursor.fetchone()
    
    if not exists:
        print(f"A coluna '{column_name}' não foi encontrada na tabela '{table_name}'. Adicionando...")
        cursor.execute(f"ALTER TABLE `{table_name}` ADD COLUMN `{column_name}` {column_type}")
        print(f"Coluna '{column_name}' adicionada com sucesso!")
    else:
        print(f"A coluna '{column_name}' já existe na tabela '{table_name}'. Nenhuma alteração necessária.")

def create_users_table_if_not_exists(cursor):
    """Cria a tabela de usuários se ela não existir."""
    print("Verificando a existência da tabela 'users'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user'
            )
        """)
    print("Tabela 'users' verificada/criada com sucesso.")

def create_items_table_if_not_exists(cursor):
    """Cria a tabela de itens se ela não existir."""
    print("Verificando a existência da tabela 'items'...")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                model VARCHAR(255),
                category VARCHAR(255),
                location VARCHAR(255),
                purchase_date DATE,
                serial_number VARCHAR(255),
                status VARCHAR(50),
                availability_status VARCHAR(50),
                image_file VARCHAR(255),
                item_uuid VARCHAR(36) UNIQUE,
                assigned_to VARCHAR(255),
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
                id INT PRIMARY KEY AUTO_INCREMENT,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                request_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) NOT NULL DEFAULT 'Pendente', -- Pendente, Aprovado, Recusado
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
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                link VARCHAR(255),
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
                category_name VARCHAR(255) PRIMARY KEY,
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
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INTEGER,
                username VARCHAR(255),
                action VARCHAR(255),
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
                id INT PRIMARY KEY AUTO_INCREMENT,
                item_id INTEGER NOT NULL,
                item_name VARCHAR(255),
                change_type VARCHAR(50) NOT NULL, -- 'Condição', 'Atribuição', etc.
                old_value TEXT,
                new_value TEXT,
                notes TEXT,
                changed_by_user_id INTEGER,
                changed_by_username VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE,
                FOREIGN KEY (changed_by_user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
    print("Tabela 'status_history' verificada/criada com sucesso.")

def create_or_update_default_admin(cursor):
    """Cria ou atualiza o usuário administrador padrão para garantir que ele exista e tenha os dados corretos."""
    # Verifica se o usuário 'admin' já existe
    cursor.execute("SELECT id FROM users WHERE username = %s", ('admin',))
    admin_user = cursor.fetchone()

    # Criptografa a senha padrão
    hashed_password = generate_password_hash('admin123')

    if admin_user is None:
        print("Usuário 'admin' padrão não encontrado. Criando...")
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            ('admin', hashed_password, 'admin')
        )
        print("Usuário 'admin' criado com sucesso com a senha 'admin123'.")
    else:
        print("Usuário 'admin' padrão encontrado. Atualizando senha e papel para garantir o acesso...")
        cursor.execute(
            "UPDATE users SET password = %s, role = %s WHERE username = %s",
            (hashed_password, 'admin', 'admin')
        )
        print("Usuário 'admin' atualizado com sucesso.")

def populate_uuid_for_existing_items(cursor):
    """Popula o campo item_uuid para todos os itens que ainda não o possuem."""
    import uuid
    cursor.execute("SELECT id FROM items WHERE item_uuid IS NULL OR item_uuid = ''")
    items_to_update = cursor.fetchall()
    
    if items_to_update:
        print(f"Encontrados {len(items_to_update)} itens sem UUID. Gerando novos UUIDs...")
        updated_count = 0
        for item in items_to_update:
            new_uuid = str(uuid.uuid4())
            cursor.execute("UPDATE items SET item_uuid = %s WHERE id = %s", (new_uuid, item[0]))
            updated_count += 1
        print(f"{updated_count} itens foram atualizados com um UUID.")
    else:
        print("Todos os itens já possuem um UUID. Nenhuma alteração necessária.")

def main():
    """Função principal para executar a migração do banco de dados."""
    print("Iniciando a verificação e migração do banco de dados...")
    conn = None
    db_name = DB_CONFIG.pop('database') # Remove o nome do DB para conectar ao servidor
    try:
        # Conecta ao servidor MySQL sem especificar um banco de dados
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Cria o banco de dados se ele não existir
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARACTER SET 'utf8mb4'")
        print(f"Banco de dados '{db_name}' verificado/criado com sucesso.")
        
        # Agora, conecta-se ao banco de dados específico
        cursor.execute(f"USE `{db_name}`")

        # 1. Garante que todas as tabelas existam (cria o DB se necessário)
        create_users_table_if_not_exists(cursor)
        create_items_table_if_not_exists(cursor)
        create_requests_table_if_not_exists(cursor)
        create_notifications_table_if_not_exists(cursor)
        create_stock_settings_table_if_not_exists(cursor)
        create_activity_log_table_if_not_exists(cursor)
        create_status_history_table_if_not_exists(cursor)

        # 2. Adiciona colunas que podem estar faltando em instalações antigas
        add_column_if_not_exists(cursor, 'items', 'model', 'VARCHAR(255)')
        add_column_if_not_exists(cursor, 'items', 'availability_status', 'VARCHAR(50)')
        add_column_if_not_exists(cursor, 'users', 'role', "VARCHAR(20) NOT NULL DEFAULT 'user'")
        add_column_if_not_exists(cursor, 'item_requests', 'response_notes', 'TEXT')
        add_column_if_not_exists(cursor, 'item_requests', 'return_notes', 'TEXT')
        add_column_if_not_exists(cursor, 'users', 'profile_image_file', 'VARCHAR(255)')
        add_column_if_not_exists(cursor, 'items', 'item_uuid', 'VARCHAR(36) UNIQUE')

        # 3. Garante que o usuário admin padrão exista e esteja atualizado
        create_or_update_default_admin(cursor)

        # 4. Popula o UUID para itens existentes que não o possuem
        populate_uuid_for_existing_items(cursor)

        conn.commit()
        print("\nVerificação concluída. Seu banco de dados está atualizado!")
    except mysql.connector.Error as e:
        print(f"Ocorreu um erro no banco de dados durante a migração: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()
