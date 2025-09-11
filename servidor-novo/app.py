import sqlite3
import functools
import os

# --- CORREÇÃO PARA WEASYPRINT NO WINDOWS ---
# Adiciona o diretório de bibliotecas do MSYS2/MinGW64 ao caminho de busca de DLLs.
# Isso é necessário para que o WeasyPrint encontre suas dependências (Pango, GObject, etc.).
# **Atenção**: Altere o caminho abaixo se você instalou o MSYS2 em um local diferente de 'C:\msys64'.
msys2_path = 'C:\\msys64\\mingw64\\bin'
if os.path.isdir(msys2_path):
    # Para Python 3.8+, usa os.add_dll_directory(), que é a forma recomendada e mais robusta.
    if hasattr(os, 'add_dll_directory'):
        os.add_dll_directory(msys2_path)
    # Para versões mais antigas, mantém a modificação do PATH como fallback.
    elif msys2_path not in os.environ['PATH']:
        os.environ['PATH'] = msys2_path + os.pathsep + os.environ['PATH']

import pathlib
from flask import Flask, render_template, request, redirect, url_for, g, abort, session, flash, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import math
import csv
import io
from datetime import datetime
from weasyprint import HTML, CSS

app = Flask(__name__)
# A SECRET_KEY é necessária para manter as sessões seguras.
# Mude para um valor aleatório e complexo em produção!
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-forte-e-dificil-de-adivinhar'

# --- Configuração para upload de arquivos ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- CORREÇÃO: Define o caminho absoluto para o banco de dados ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['DATABASE'] = os.path.join(basedir, 'inventory.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, UPLOAD_FOLDER)

# Garante que a pasta de uploads exista
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    """Abre uma nova conexão com o banco de dados se não houver uma no contexto."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        # Retorna linhas como dicionários
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Fecha a conexão com o banco de dados ao final da requisição."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.context_processor
def inject_categories():
    """Injecta a lista de categorias em todos os templates para o menu."""
    if g.user:
        db = get_db()
        # Pega categorias distintas que não sejam nulas ou vazias
        categories = db.execute('SELECT DISTINCT category FROM items WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
        return dict(all_categories=categories)
    return dict(all_categories=[])

@app.before_request
def load_logged_in_user():
    """Se um user_id está na sessão, carrega o usuário do DB."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()

def login_required(view):
    """Decorator que redireciona usuários anônimos para a página de login."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def log_activity(db, action, item_id=None, item_name=None):
    """Registra uma ação no log de atividades."""
    if g.user:
        db.execute(
            'INSERT INTO activity_log (user_id, username, action, item_id, item_name) VALUES (?, ?, ?, ?, ?)',
            (g.user['id'], g.user['username'], action, item_id, item_name)
        )

def log_status_change(db, item_id, item_name, old_status, new_status, notes=None):
    """Registra uma mudança de status no histórico."""
    if g.user:
        db.execute(
            'INSERT INTO status_history (item_id, item_name, old_status, new_status, notes, changed_by_user_id, changed_by_username) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (item_id, item_name, old_status, new_status, notes, g.user['id'], g.user['username'])
        )
        # O commit será feito junto com a operação principal (add/edit)

def get_item(item_id):
    """Busca um único item pelo seu ID."""
    db = get_db()
    item = db.execute(
        'SELECT * FROM items WHERE id = ?', (item_id,)
    ).fetchone()
    if item is None:
        abort(404) # Se o item não existir, retorna um erro "Not Found".
    return item

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/dashboard')
@login_required
def dashboard():
    """Página do dashboard com estatísticas."""
    db = get_db()
    from collections import OrderedDict
    
    total_items = db.execute('SELECT COUNT(id) FROM items').fetchone()[0]

    # Query para contar itens por setor (localização)
    items_by_location_cursor = db.execute(
        'SELECT location, COUNT(id) as count FROM items WHERE location IS NOT NULL AND location != "" GROUP BY location ORDER BY count DESC LIMIT 10'
    )
    items_by_location = items_by_location_cursor.fetchall()
    location_labels = [item['location'] for item in items_by_location]
    location_data = [item['count'] for item in items_by_location]

    # Query para contar itens por categoria
    items_by_category_cursor = db.execute(
        'SELECT category, COUNT(id) as count FROM items WHERE category IS NOT NULL AND category != "" GROUP BY category ORDER BY count DESC LIMIT 10'
    )
    items_by_category = items_by_category_cursor.fetchall()
    category_labels = [item['category'] for item in items_by_category]
    category_data = [item['count'] for item in items_by_category]

    # Query para itens adicionados por mês (últimos 12 meses)
    monthly_counts = OrderedDict()
    today = datetime.today()
    for i in range(11, -1, -1):
        # Calcula o ano e mês para os últimos 12 meses
        year = today.year
        month = today.month - i
        if month <= 0:
            year -= 1
            month += 12
        monthly_counts[f"{year:04d}-{month:02d}"] = 0

    items_per_month_cursor = db.execute(
        "SELECT strftime('%Y-%m', created_at) as month, COUNT(id) as count FROM items WHERE created_at >= date('now', '-1 year') GROUP BY month"
    )
    for row in items_per_month_cursor.fetchall():
        if row['month'] in monthly_counts:
            monthly_counts[row['month']] = row['count']
            
    monthly_labels = list(monthly_counts.keys())
    monthly_data = list(monthly_counts.values())

    # --- Métricas para os novos data cards ---
    # Itens com avaria (contagem absoluta e porcentagem do total)
    broken_items_count = 0
    broken_items_percentage = 0
    if total_items > 0:
        broken_items_count = db.execute('SELECT COUNT(id) FROM items WHERE status = ?', ('Quebrado',)).fetchone()[0]
        broken_items_percentage = round((broken_items_count / total_items) * 100)

    # Novos itens este mês e mudança percentual em relação ao mês anterior
    new_items_current_month = monthly_data[-1] if monthly_data else 0
    new_items_last_month = monthly_data[-2] if len(monthly_data) > 1 else 0
    new_items_change = 0
    if new_items_last_month > 0:
        new_items_change = round(((new_items_current_month - new_items_last_month) / new_items_last_month) * 100)

    # Total de categorias distintas
    total_categories = db.execute('SELECT COUNT(DISTINCT category) FROM items WHERE category IS NOT NULL AND category != ""').fetchone()[0]

    return render_template('dashboard.html', 
                           total_items=total_items,
                           broken_items_count=broken_items_count,
                           broken_items_percentage=broken_items_percentage,
                           new_items_current_month=new_items_current_month,
                           new_items_change=new_items_change,
                           total_categories=total_categories,
                           location_labels=location_labels, location_data=location_data,
                           category_labels=category_labels, category_data=category_data,
                           monthly_labels=monthly_labels, monthly_data=monthly_data)

@app.route('/categories', methods=('GET', 'POST'))
@login_required
def manage_categories():
    """Página para gerenciar (renomear e remover) categorias."""
    db = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'edit':
            old_name = request.form['old_name']
            new_name = request.form['new_name'].strip()
            if new_name and old_name != new_name:
                try:
                    # Verifica se o novo nome de categoria já existe para evitar duplicatas
                    exists = db.execute('SELECT 1 FROM items WHERE category = ?', (new_name,)).fetchone()
                    if exists:
                        flash(f'A categoria "{new_name}" já existe. Escolha um nome diferente.', 'warning')
                    else:
                        db.execute('UPDATE items SET category = ? WHERE category = ?', (new_name, old_name))
                        log_activity(db, f'Renomeou categoria de "{old_name}" para "{new_name}"')
                        db.commit()
                        flash(f'Categoria "{old_name}" foi renomeada para "{new_name}".', 'success')
                except sqlite3.Error as e:
                    db.rollback()
                    flash(f'Erro ao renomear categoria: {e}', 'danger')
            else:
                flash('O novo nome da categoria não pode ser vazio ou igual ao antigo.', 'warning')

        elif action == 'delete':
            name_to_delete = request.form['name_to_delete']
            try:
                # Esta ação remove a categoria dos itens, mas não exclui os itens.
                db.execute('UPDATE items SET category = NULL WHERE category = ?', (name_to_delete,))
                log_activity(db, f'Removeu categoria "{name_to_delete}" dos itens.')
                db.commit()
                flash(f'Categoria "{name_to_delete}" foi removida de todos os itens associados.', 'info')
            except sqlite3.Error as e:
                db.rollback()
                flash(f'Erro ao remover categoria: {e}', 'danger')
        
        return redirect(url_for('manage_categories'))

    categories = db.execute('SELECT DISTINCT category FROM items WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
    return render_template('manage_categories.html', categories=categories)

@app.route('/')
@login_required
def index():
    """Página principal que lista todos os itens do inventário, com filtro de busca e paginação."""
    search_query = request.args.get('q', '')
    category_filter = request.args.get('category')
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Itens por página
    offset = (page - 1) * per_page

    db = get_db()

    # Parâmetros e cláusulas para a consulta SQL
    params = []
    where_clauses = []

    if category_filter:
        where_clauses.append("category = ?")
        params.append(category_filter)

    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(name LIKE ? OR model LIKE ? OR category LIKE ? OR location LIKE ?)")
        params.extend([search_term, search_term, search_term, search_term])

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # Contar o total de itens para a paginação
    total_items = db.execute(f"SELECT COUNT(id) FROM items {where_sql}", params).fetchone()[0]
    total_pages = math.ceil(total_items / per_page)

    # Buscar os itens para a página atual
    params.extend([per_page, offset])
    items = db.execute(f"SELECT * FROM items {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?", params).fetchall()

    return render_template('index.html', items=items, page=page, total_pages=total_pages)

@app.route('/avarias')
@login_required
def broken_items():
    """Página que lista todos os itens com status 'Quebrado'."""
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Itens por página
    offset = (page - 1) * per_page

    db = get_db()

    # Parâmetros e cláusulas para a consulta SQL
    params = []
    where_clauses = ["status = ?"]
    params.append('Quebrado')

    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(name LIKE ? OR model LIKE ? OR category LIKE ? OR location LIKE ?)")
        params.extend([search_term, search_term, search_term, search_term])

    where_sql = "WHERE " + " AND ".join(where_clauses)

    # Contar o total de itens para a paginação
    total_items = db.execute(f"SELECT COUNT(id) FROM items {where_sql}", params).fetchone()[0]
    total_pages = math.ceil(total_items / per_page)

    # Buscar os itens para a página atual
    params.extend([per_page, offset])
    items = db.execute(f"SELECT * FROM items {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?", params).fetchall()

    # Reutiliza o template index.html, passando um título e endpoint específicos
    return render_template('index.html', items=items, page=page, total_pages=total_pages, title='Itens com Avaria', endpoint='broken_items')

@app.route('/export/csv')
@login_required
def export_csv():
    """Exporta a lista de itens filtrada para um arquivo CSV."""
    search_query = request.args.get('q', '')
    category_filter = request.args.get('category')

    db = get_db()

    # Reutiliza a lógica de filtragem da rota index
    params = []
    where_clauses = []

    if category_filter:
        where_clauses.append("category = ?")
        params.append(category_filter)

    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(name LIKE ? OR model LIKE ? OR category LIKE ? OR location LIKE ?)")
        params.extend([search_term, search_term, search_term, search_term])

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # Busca todos os itens que correspondem ao filtro, sem paginação
    items = db.execute(f"SELECT * FROM items {where_sql} ORDER BY created_at DESC", params).fetchall()

    # Gera o CSV em memória
    output = io.StringIO()
    writer = csv.writer(output)

    # Escreve o cabeçalho
    writer.writerow(['ID', 'Nome', 'Modelo', 'Categoria', 'Localização', 'Data de Aquisição', 'Nº de Série', 'Condição/Uso', 'Disponibilidade', 'Atribuído a', 'Autorizado por', 'Data de Criação'])

    # Escreve as linhas de dados
    for item in items:
        writer.writerow([
            item['id'], item['name'], item['model'], item['category'], item['location'],
            item['purchase_date'], item['serial_number'], item['status'], item['availability_status'],
            item['assigned_to'], item['authorized_by'], item['created_at']
        ])

    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=inventario.csv"}
    )

@app.route('/add', methods=('GET', 'POST'))
@login_required
def add():
    """Página para adicionar um novo item."""
    if request.method == 'POST':
        name = request.form['name']
        model = request.form['model']
        category = request.form['category']
        location = request.form['location']
        purchase_date = request.form['purchase_date']
        serial_number = request.form.get('serial_number')
        status = request.form['status'] # Condição/Uso
        availability_status = request.form['availability_status'] # Novo campo: Disponibilidade
        assigned_to = request.form.get('assigned_to') # Novo campo
        authorized_by = request.form.get('authorized_by') # Novo campo

        db = get_db()
        try:
            cursor = db.execute( # Adicionado assigned_to e authorized_by
                'INSERT INTO items (name, model, category, location, purchase_date, serial_number, status, availability_status, assigned_to, authorized_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (name, model, category, location, purchase_date, serial_number, status, availability_status, assigned_to, authorized_by)
            )
            new_item_id = cursor.lastrowid

            # Agrupa os logs na mesma transação
            log_activity(db, 'Criou item', item_id=new_item_id, item_name=name)
            log_status_change(db, new_item_id, name, None, status, notes="Criação inicial do item.")
            db.commit() # Salva o item e os logs de uma só vez

            flash(f'Item "{name}" foi adicionado com sucesso!', 'success')
            return redirect(url_for('index'))
        except sqlite3.Error as e:
            db.rollback() # Reverte a transação em caso de erro
            flash(f'Erro ao adicionar item: {e}', 'danger')
            print(f"Erro no banco de dados ao adicionar item: {e}") # Imprime o erro no console do servidor
            return render_template('add_item.html') # Permanece na página de adição para exibir o erro

    return render_template('add_item.html')

@app.route('/<int:id>/edit', methods=('GET', 'POST'))
@login_required
def edit(id):
    """Página para editar um item existente."""
    item = get_item(id)

    if request.method == 'POST':
        name = request.form['name']
        model = request.form['model']
        category = request.form['category']
        location = request.form['location']
        purchase_date = request.form['purchase_date']
        serial_number = request.form.get('serial_number')
        status = request.form['status'] # Condição/Uso
        availability_status = request.form['availability_status'] # Novo campo: Disponibilidade
        assigned_to = request.form.get('assigned_to') # Novo campo
        authorized_by = request.form.get('authorized_by') # Novo campo
        status_notes = request.form.get('status_notes', '').strip() # Campo de observações

        try:
            db = get_db()
            # Se o status mudou, registra no histórico
            if status != item['status']:
                log_status_change(db, id, name, item['status'], status, notes=status_notes)

            db.execute( # Adicionado assigned_to e authorized_by
                'UPDATE items SET name = ?, model = ?, category = ?, location = ?, purchase_date = ?, serial_number = ?, status = ?, availability_status = ?, assigned_to = ?, authorized_by = ?'
                ' WHERE id = ?',
                (name, model, category, location, purchase_date, serial_number, status, availability_status, assigned_to, authorized_by, id)
            )
            # Log da edição do item
            log_activity(db, 'Editou item', item_id=id, item_name=name)

            db.commit()

            flash(f'Item "{name}" foi atualizado com sucesso!', 'success')
            return redirect(url_for('index'))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Erro ao editar o item: {e}', 'danger')
            print(f"Erro no banco de dados ao editar item: {e}")
            return render_template('edit_item.html', item=item)

    return render_template('edit_item.html', item=item)

@app.route('/item/<int:id>/history')
@login_required
def item_history(id):
    """Exibe o histórico de status de um item específico."""
    item = get_item(id) # Pega os detalhes do item para o título da página
    db = get_db()
    history_entries = db.execute(
        'SELECT * FROM status_history WHERE item_id = ? ORDER BY timestamp DESC', (id,)
    ).fetchall()
    return render_template('item_history.html', item=item, history_entries=history_entries)

@app.route('/item/<int:id>/pdf')
@login_required
def generate_pdf_report(id):
    """Gera um relatório em PDF para um item específico."""
    item = get_item(id)

    # Renderiza o template HTML específico para o PDF
    html_string = render_template(
        'report_template.html',
        item=item,
        now=datetime.now() # Passa a data/hora atual para o template
    )

    # Gera o PDF a partir do HTML renderizado
    pdf_bytes = HTML(string=html_string, base_url=request.base_url).write_pdf()

    # Cria a resposta HTTP com o PDF para ser exibido no navegador
    filename = f"relatorio_{secure_filename(item['name'].replace(' ', '_'))}.pdf"
    return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': f'inline; filename={filename}'})

@app.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    """Rota para excluir um item."""
    item = get_item(id) # Verifica se o item existe e pega os dados para o log.
    try:
        db = get_db()
        db.execute('DELETE FROM items WHERE id = ?', (id,))
        log_activity(db, 'Excluiu item', item_id=id, item_name=item['name'])
        db.commit()
    except sqlite3.Error as e:
        flash(f'Erro ao excluir o item: {e}', 'danger')
    flash(f'Item "{item["name"]}" foi excluído com sucesso.', 'info')
    return redirect(url_for('index'))

@app.route('/logs')
@login_required
def logs():
    """Exibe o log de atividades com paginação."""
    page = request.args.get('page', 1, type=int)
    per_page = 20 # Logs podem ser mais densos
    offset = (page - 1) * per_page
    db = get_db()
    total_logs = db.execute('SELECT COUNT(id) FROM activity_log').fetchone()[0]
    total_pages = math.ceil(total_logs / per_page)
    
    # Adiciona a lógica de busca ao log de atividades
    search_query = request.args.get('q', '')
    search_param = f"%{search_query}%"

    log_entries = db.execute(
        'SELECT * FROM activity_log WHERE username LIKE ? OR action LIKE ? OR item_name LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?',
        (search_param, search_param, search_param, per_page, offset)
    ).fetchall()
    return render_template('logs.html', log_entries=log_entries, page=page, total_pages=total_pages)

@app.route('/register', methods=('GET', 'POST'))
def register():
    """Registra um novo usuário."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        db = get_db()
        error = None

        if not username:
            error = 'Nome de usuário é obrigatório.'
        elif not password:
            error = 'Senha é obrigatória.'
        elif password != confirm_password:
            error = 'As senhas não coincidem.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"Usuário {username} já está registrado."
            else:
                flash('Conta criada com sucesso! Por favor, faça o login.', 'success')
                return redirect(url_for("login"))
        
        flash(error, 'danger')

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    """Faz o login do usuário."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None or not check_password_hash(user['password'], password):
            error = 'Usuário ou senha inválidos.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        
        flash(error, 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Faz o logout do usuário."""
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)