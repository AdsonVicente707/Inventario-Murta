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
from datetime import datetime, date, timedelta
from weasyprint import HTML, CSS

app = Flask(__name__)
# A SECRET_KEY é necessária para manter as sessões seguras.
# Mude para um valor aleatório e complexo em produção!
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-forte-e-dificil-de-adivinhar'

# --- Configuração para upload de arquivos ---
UPLOAD_FOLDER = 'uploads'
PROFILE_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_pics')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- CORREÇÃO: Define o caminho absoluto para o banco de dados ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['DATABASE'] = os.path.join(basedir, 'inventory.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, UPLOAD_FOLDER)
app.config['PROFILE_PICS_FOLDER'] = os.path.join(basedir, PROFILE_PICS_FOLDER)

# Garante que a pasta de uploads exista
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)

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
    return dict(all_categories=[], notifications=[])

@app.context_processor
def inject_notifications():
    if g.user:
        db = get_db()
        notifications = db.execute('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC', (g.user['id'],)).fetchall()
        return dict(notifications=notifications)
    return dict(notifications=[])

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

def admin_required(view):
    """Decorator que garante que o usuário está logado e é um administrador."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        if g.user['role'] != 'admin':
            abort(403) # Erro 'Forbidden' (Proibido)
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

def notify_admins(db, message, link):
    """Cria uma notificação para todos os administradores."""
    admins = db.execute('SELECT id FROM users WHERE role = ?', ('admin',)).fetchall()
    for admin in admins:
        db.execute(
            "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
            (admin['id'], message, link)
        )

def check_and_notify_stock_level(db, category_name):
    """Verifica o nível de estoque de uma categoria e notifica admins se estiver baixo."""
    if not category_name:
        return

    # 1. Pega a configuração de estoque mínimo para a categoria
    setting = db.execute(
        'SELECT min_stock_level FROM category_stock_settings WHERE category_name = ?',
        (category_name,)
    ).fetchone()

    # Se não há configuração para esta categoria, não faz nada
    if not setting or setting['min_stock_level'] <= 0:
        return

    min_level = setting['min_stock_level']

    # 2. Conta quantos itens "Livres" existem para essa categoria
    current_stock = db.execute(
        "SELECT COUNT(id) FROM items WHERE category = ? AND availability_status = 'Livre'",
        (category_name,)
    ).fetchone()[0]

    # 3. Se o estoque atual está abaixo do mínimo, notifica os admins
    if current_stock < min_level:
        message = f"Estoque baixo para '{category_name}': {current_stock}/{min_level} itens livres."
        link = url_for('index', category=category_name)
        notify_admins(db, message, link)

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

@app.route('/profile_pics/<filename>')
@login_required
def profile_pic(filename):
    return send_from_directory(app.config['PROFILE_PICS_FOLDER'], filename)

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
                           monthly_labels=monthly_labels, monthly_data=monthly_data,
                           low_stock_categories=[])

@app.route('/categories', methods=('GET', 'POST'))
@admin_required
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

@app.route('/manage_users', methods=('GET', 'POST'))
@admin_required
def manage_users():
    """Página para administradores gerenciarem os papéis dos usuários."""
    db = get_db()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_role':
            user_id = request.form.get('user_id')
            new_role = request.form.get('role')

            if not user_id or new_role not in ['admin', 'user']:
                flash('Requisição inválida.', 'danger')
            elif int(user_id) == g.user['id']:
                flash('Você não pode alterar seu próprio papel.', 'warning')
            else:
                try:
                    target_user = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
                    if target_user:
                        db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
                        log_activity(db, f"Alterou o papel do usuário '{target_user['username']}' para '{new_role}'")
                        db.commit()
                        flash(f"Papel do usuário '{target_user['username']}' atualizado para '{new_role}'.", 'success')
                    else:
                        flash('Usuário não encontrado.', 'danger')
                except sqlite3.Error as e:
                    db.rollback()
                    flash(f'Erro ao atualizar o papel do usuário: {e}', 'danger')
        
        elif action == 'create_user':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role')
            error = None

            if not username or not password or not role:
                error = 'Nome de usuário, senha e perfil são obrigatórios.'
            elif password != confirm_password:
                error = 'As senhas não coincidem.'
            
            if error is None:
                try:
                    db.execute(
                        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), role)
                    )
                    log_activity(db, f"Criou novo usuário '{username}' com papel '{role}'")
                    db.commit()
                    flash(f"Usuário '{username}' criado com sucesso.", 'success')
                except db.IntegrityError:
                    error = f"Usuário '{username}' já existe."
            
            if error:
                flash(error, 'danger')
        
        return redirect(url_for('manage_users'))

    # Busca todos os usuários para exibir na página
    users = db.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    return render_template('manage_users.html', users=users)

@app.route('/user_assets')
@admin_required
def user_assets():
    """Página para administradores verem os itens associados a cada usuário."""
    db = get_db()
    
    # 1. Pega todos os usuários
    users = db.execute("SELECT id, username FROM users ORDER BY username").fetchall()
    
    # 2. Pega todos os itens que estão "Em uso"
    items_in_use = db.execute("SELECT id, name, assigned_to FROM items WHERE availability_status = 'Em uso'").fetchall()
    
    # 3. Agrupa os itens por usuário em um dicionário
    assets_by_user = {user['username']: [] for user in users}
    for item in items_in_use:
        if item['assigned_to'] in assets_by_user:
            assets_by_user[item['assigned_to']].append(item)
            
    return render_template('user_assets.html', assets_by_user=assets_by_user)

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
@admin_required
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

@app.route('/request_item/<int:item_id>', methods=('POST',))
@login_required
def request_item(item_id):
    """Registra a requisição de um item por um usuário."""
    db = get_db()
    item = get_item(item_id)

    if item['availability_status'] != 'Livre':
        flash('Este item não está disponível para requisição.', 'warning')
        return redirect(url_for('index'))
    
    notes = request.form.get('notes', '').strip()
    try:
        db.execute(
            'INSERT INTO item_requests (item_id, user_id, status, notes) VALUES (?, ?, ?, ?)',
            (item_id, g.user['id'], 'Pendente', notes)
        )
        # Notifica todos os administradores sobre a nova requisição
        notification_message = f"Nova requisição para '{item['name']}' por {g.user['username']}."
        notification_link = url_for('manage_requests')
        notify_admins(db, notification_message, notification_link)

        db.commit()
        flash(f'Sua requisição para o item "{item["name"]}" foi enviada para aprovação.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Ocorreu um erro ao processar sua requisição: {e}', 'danger')

    return redirect(url_for('index'))

@app.route('/manage_requests', methods=('GET', 'POST'))
@admin_required
def manage_requests():
    """Página para administradores gerenciarem as requisições de itens."""
    db = get_db()

    if request.method == 'POST':
        request_id = request.form.get('request_id')
        action = request.form.get('action') # 'approve', 'deny', ou 'inspect'

        req_data = db.execute('SELECT * FROM item_requests WHERE id = ?', (request_id,)).fetchone()
        if not req_data:
            abort(404)

        # Correção: Estas linhas devem estar fora do bloco 'if not req_data'
        requester_id = req_data['user_id']
        item = get_item(req_data['item_id'])

        if action == 'approve':
            requester = db.execute('SELECT username FROM users WHERE id = ?', (req_data['user_id'],)).fetchone()
            # Atualiza o status da requisição
            db.execute("UPDATE item_requests SET status = 'Aprovado' WHERE id = ?", (request_id,))
            # Atualiza o item, atribuindo-o ao usuário
            db.execute(
                "UPDATE items SET availability_status = 'Em uso', assigned_to = ? WHERE id = ?",
                (requester['username'], req_data['item_id'])
            )
            # Correção: Indentação correta para criar a notificação
            notification_message = f"Sua requisição para '{item['name']}' foi Aprovada."
            db.execute("INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)", (requester_id, notification_message, url_for('my_requests')))
            log_activity(db, f"Aprovou requisição para '{item['name']}' para o usuário '{requester['username']}'")
            flash(f"Requisição para '{item['name']}' aprovada.", 'success')
            
            # Após aprovar, verifica o nível de estoque da categoria do item
            check_and_notify_stock_level(db, item['category'])
        elif action == 'deny':
            denial_reason = request.form.get('denial_reason', '').strip()
            db.execute(
                "UPDATE item_requests SET status = 'Recusado', response_notes = ? WHERE id = ?",
                (denial_reason, request_id)
            )
            # Correção: Indentação correta para criar a notificação
            notification_message = f"Sua requisição para '{item['name']}' foi Recusada." + (f" Motivo: {denial_reason}" if denial_reason else "")
            db.execute("INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)", (requester_id, notification_message, url_for('my_requests')))
            log_activity(db, f"Recusou requisição para '{item['name']}'. Motivo: {denial_reason or 'N/A'}")
            flash("Requisição recusada.", 'info')
        elif action == 'inspect':
            if req_data['status'] != 'Devolvido':
                flash('Ação inválida. O item não foi devolvido.', 'warning')
                return redirect(url_for('manage_requests'))
            
            final_condition = request.form.get('final_condition')
            
            # Atualiza o item para 'Livre' e com a condição final
            db.execute(
                "UPDATE items SET availability_status = 'Livre', status = ? WHERE id = ?",
                (final_condition, item['id'])
            )
            log_status_change(db, item['id'], item['name'], item['status'], final_condition, notes="Item inspecionado e liberado após devolução.")
            log_activity(db, f"Inspecionou e liberou o item '{item['name']}'")
            flash(f"Item '{item['name']}' foi inspecionado e está 'Livre' novamente.", 'success')

        
        db.commit()
        return redirect(url_for('manage_requests'))

    requests_list = db.execute("""
        SELECT r.id, r.request_date, r.status, r.notes, r.return_notes, i.name as item_name, i.status as item_condition, u.username as user_name
        FROM item_requests r JOIN items i ON r.item_id = i.id JOIN users u ON r.user_id = u.id 
        ORDER BY r.request_date DESC
    """).fetchall()
    return render_template('manage_requests.html', requests=requests_list)

@app.route('/stock_levels', methods=('GET', 'POST'))
@admin_required
def manage_stock_levels():
    """Página para administradores definirem os níveis de estoque mínimo por categoria."""
    db = get_db()

    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('min_level_'):
                category_name = key.replace('min_level_', '')
                min_level = int(value) if value.isdigit() else 0
                
                # UPSERT: Insere ou atualiza a configuração
                db.execute("""
                    INSERT INTO category_stock_settings (category_name, min_stock_level)
                    VALUES (?, ?)
                    ON CONFLICT(category_name) DO UPDATE SET min_stock_level = excluded.min_stock_level
                """, (category_name, min_level))
        db.commit()
        flash('Níveis de estoque mínimo atualizados com sucesso.', 'success')
        return redirect(url_for('manage_stock_levels'))

    # Coleta dados para exibir na página
    categories_cursor = db.execute("""
        SELECT 
            i.category, 
            COUNT(i.id) as total_items,
            SUM(CASE WHEN i.availability_status = 'Livre' THEN 1 ELSE 0 END) as available_items,
            COALESCE(css.min_stock_level, 0) as min_stock_level
        FROM items i
        LEFT JOIN category_stock_settings css ON i.category = css.category_name
        WHERE i.category IS NOT NULL AND i.category != ''
        GROUP BY i.category ORDER BY i.category
    """)
    categories_data = categories_cursor.fetchall()
    return render_template('manage_stock_levels.html', categories_data=categories_data)

@app.route('/request_multiple', methods=['POST'])
@login_required
def request_multiple_items():
    """Registra a requisição de múltiplos itens por um usuário."""
    db = get_db()
    item_ids = request.form.getlist('item_ids')
    notes = request.form.get('notes', '').strip()

    if not item_ids:
        flash('Nenhum item foi selecionado para requisição.', 'warning')
        return redirect(url_for('index'))

    requested_count = 0
    errors = []
    
    for item_id in item_ids:
        item = get_item(item_id) # This already aborts if not found
        if item['availability_status'] == 'Livre':
            try:
                db.execute(
                    'INSERT INTO item_requests (item_id, user_id, status, notes) VALUES (?, ?, ?, ?)',
                    (item_id, g.user['id'], 'Pendente', notes)
                )
                # Notifica todos os administradores sobre a nova requisição
                notification_message = f"Nova requisição para '{item['name']}' por {g.user['username']}."
                notification_link = url_for('manage_requests')
                notify_admins(db, notification_message, notification_link)

                requested_count += 1
            except sqlite3.Error as e:
                errors.append(f"Erro ao requisitar '{item['name']}': {e}")
        else:
            errors.append(f"O item '{item['name']}' não está mais disponível.")

    if requested_count > 0:
        db.commit()
        flash(f'{requested_count} item(s) requisitados com sucesso para aprovação.', 'success')
    for error in errors:
        flash(error, 'danger')

    return redirect(url_for('index'))

@app.route('/my_requests')
@login_required
def my_requests():
    """Página para o usuário comum ver o status de suas requisições."""
    db = get_db()
    requests_list = db.execute("""
        SELECT r.id, r.request_date, r.status, r.notes, r.response_notes, r.return_notes, i.name as item_name, i.status as item_condition
        FROM item_requests r JOIN items i ON r.item_id = i.id
        WHERE r.user_id = ?
        ORDER BY r.request_date DESC
    """, (g.user['id'],)).fetchall()
    return render_template('my_requests.html', requests=requests_list)

@app.route('/profile', methods=('GET', 'POST'))
@login_required
def profile():
    """Página de perfil do usuário com resumo de atividades."""
    db = get_db()
    user_id = g.user['id']

    if request.method == 'POST':
        if 'profile_pic' not in request.files:
            flash('Nenhum arquivo selecionado.', 'warning')
            return redirect(request.url)
        file = request.files['profile_pic']
        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'warning')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_filename = f"{user_id}_{timestamp}_{filename}"
            
            file.save(os.path.join(app.config['PROFILE_PICS_FOLDER'], new_filename))
            
            db.execute('UPDATE users SET profile_image_file = ? WHERE id = ?', (new_filename, user_id))
            db.commit()
            flash('Foto de perfil atualizada com sucesso!', 'success')
            return redirect(url_for('profile'))

    # Estatísticas dinâmicas baseadas no perfil do usuário
    stats = {}
    if g.user['role'] == 'admin':
        stats['approved_requests'] = db.execute("SELECT COUNT(id) FROM item_requests WHERE status = 'Aprovado'").fetchone()[0]
        stats['denied_requests'] = db.execute("SELECT COUNT(id) FROM item_requests WHERE status = 'Recusado'").fetchone()[0]
        stats['total_items_added'] = db.execute('SELECT COUNT(id) FROM items').fetchone()[0]
    else:
        stats['total_requests'] = db.execute('SELECT COUNT(id) FROM item_requests WHERE user_id = ?', (user_id,)).fetchone()[0]
        stats['items_in_possession'] = db.execute('SELECT COUNT(id) FROM item_requests WHERE user_id = ? AND status = ?', (user_id, 'Aprovado')).fetchone()[0]

    # Últimas atividades do usuário
    recent_activities = db.execute(
        'SELECT action, item_name, timestamp FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
        (user_id,)
    ).fetchall()

    # --- Dados para o gráfico de atividades ---
    from collections import OrderedDict
    activity_by_day = OrderedDict()
    today = date.today()
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        activity_by_day[day.strftime("%Y-%m-%d")] = 0
    
    # Query para obter a contagem de atividades
    activity_counts_cursor = db.execute("""
        SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(id) as count 
        FROM activity_log 
        WHERE user_id = ? AND timestamp >= date('now', '-30 days')
        GROUP BY day
    """, (user_id,)).fetchall()

    for row in activity_counts_cursor:
        if row['day'] in activity_by_day:
            activity_by_day[row['day']] = row['count']

    chart_labels = list(activity_by_day.keys())
    chart_data = list(activity_by_day.values())
    
    return render_template(
        'profile.html',
        stats=stats,
        recent_activities=recent_activities,
        chart_labels=chart_labels,
        chart_data=chart_data
    )

@app.route('/return_item/<int:request_id>', methods=['POST'])
@login_required
def return_item(request_id):
    """Processa a devolução de um item por um usuário."""
    db = get_db()
    req_data = db.execute(
        'SELECT * FROM item_requests WHERE id = ? AND user_id = ?', (request_id, g.user['id'])
    ).fetchone()

    if not req_data or req_data['status'] != 'Aprovado':
        flash('Requisição não encontrada ou item não está em posse para devolução.', 'danger')
        return redirect(url_for('my_requests'))

    new_condition = request.form.get('new_condition')
    return_notes = request.form.get('return_notes', '').strip()
    item_id = req_data['item_id']
    item = get_item(item_id)

    try:
        # 1. Atualiza o status da requisição para 'Devolvido' e salva as notas
        db.execute(
            "UPDATE item_requests SET status = 'Devolvido', return_notes = ? WHERE id = ?",
            (return_notes, request_id)
        )
        # 2. Atualiza o item: status de disponibilidade, condição e remove atribuição
        # O item volta a ficar 'Livre' imediatamente.
        db.execute(
            "UPDATE items SET availability_status = 'Livre', status = ?, assigned_to = NULL WHERE id = ?",
            (new_condition, item_id)
        )
        # 3. Loga a mudança de condição e a atividade de devolução
        log_status_change(db, item_id, item['name'], item['status'], new_condition, notes=f"Devolvido por usuário. {return_notes}")
        log_activity(db, f"Devolveu o item '{item['name']}'")
        # 4. Notifica os administradores
        notify_admins(db, f"Item '{item['name']}' devolvido por {g.user['username']}. Inspeção necessária.", url_for('manage_requests'))

        db.commit()
        flash(f"Item '{item['name']}' devolvido com sucesso. Aguardando inspeção do administrador.", 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Ocorreu um erro ao devolver o item: {e}', 'danger')

    return redirect(url_for('my_requests'))

@app.route('/notifications/read/<int:notification_id>')
@login_required
def read_notification(notification_id):
    """Marca uma notificação específica como lida e redireciona para seu link."""
    db = get_db()
    notification = db.execute(
        'SELECT * FROM notifications WHERE id = ? AND user_id = ?',
        (notification_id, g.user['id'])
    ).fetchone()

    if notification:
        db.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
        db.commit()
        # Se a notificação tiver um link, redireciona para ele.
        if notification['link']:
            return redirect(notification['link'])
    
    # Se a notificação não for encontrada ou não tiver link, redireciona para a página anterior.
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    """Marca todas as notificações do usuário como lidas."""
    db = get_db()
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', (g.user['id'],))
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))


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

            # Verifica se a disponibilidade mudou de 'Livre' para outro estado
            if item['availability_status'] == 'Livre' and availability_status != 'Livre':
                check_and_notify_stock_level(db, category)

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
        
        # Após deletar, verifica o nível de estoque da categoria do item
        check_and_notify_stock_level(get_db(), item['category'])
    except sqlite3.Error as e:
        flash(f'Erro ao excluir o item: {e}', 'danger')
    flash(f'Item "{item["name"]}" foi excluído com sucesso.', 'info')
    return redirect(url_for('index'))

@app.route('/logs')
@admin_required
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

@app.route('/change_password', methods=('GET', 'POST'))
@login_required
def change_password():
    """Permite que o usuário logado altere sua própria senha."""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        error = None

        # Verifica a senha atual
        if not check_password_hash(g.user['password'], current_password):
            error = 'A senha atual está incorreta.'
        # Verifica se a nova senha não está vazia
        elif not new_password:
            error = 'A nova senha não pode estar em branco.'
        # Verifica se as novas senhas coincidem
        elif new_password != confirm_password:
            error = 'A nova senha e a confirmação não coincidem.'

        if error is None:
            db = get_db()
            db.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (generate_password_hash(new_password), g.user['id'])
            )
            db.commit()
            flash('Sua senha foi alterada com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        
        flash(error, 'danger')

    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)