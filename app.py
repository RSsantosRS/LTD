from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt

app = Flask(__name__)  # Rota para o site
app.secret_key = 'rafaelds'  # Chave de teste

# Banco de dados existente
DATABASE = 'ltd.db'

#cria conexão com o bd
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Para acessar os dados como dicionários
    return conn

#novo usuario com hash na senha
def criar_usuario(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())#transforma em bytes, gera um salt e depois salva como hash no bd
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, hashed_password))
        #alterar TODOS usuarios para o nome correto da tabela no bd
        conn.commit()
    except sqlite3.IntegrityError:
        return False  # Usuário já existe
    finally:
        conn.close()
    return True

# Função para verificar credenciais
def verificar_credenciais(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM usuarios WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verificar_credenciais(username, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha incorretos!')

    return render_template('login.html')

@app.route('/home')
def home():
    if 'username' in session:
        return f'Seja Bem-vindo!!, {session["username"]}!'
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
     #init_db()  
    #usuario teste
    criar_usuario('rafael', '123')  
    app.run(debug=True)