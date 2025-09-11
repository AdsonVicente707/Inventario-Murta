import sqlite3
import os

# Obtém o caminho absoluto do diretório onde este script está localizado
basedir = os.path.dirname(os.path.abspath(__file__))
# Constrói o caminho absoluto para o arquivo do banco de dados
db_path = os.path.join(basedir, 'inventory.db')
# Constrói o caminho absoluto para o arquivo de schema
schema_path = os.path.join(basedir, 'schema.sql')

def init_db():
    """
    Inicializa o banco de dados criando as tabelas a partir do schema.sql,
    garantindo que os caminhos corretos sejam usados.
    """
    connection = sqlite3.connect(db_path)
    with open(schema_path) as f:
        connection.executescript(f.read())
    connection.close()
    print("Banco de dados inicializado com sucesso no caminho correto.")

if __name__ == '__main__':
    init_db()