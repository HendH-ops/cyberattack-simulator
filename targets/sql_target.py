from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    
    # Create products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER)''')
    
    # Insert sample data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 'user1@example.com')")
    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Product 1', 10.99, 100)")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Product 2', 20.99, 50)")
    
    conn.commit()
    conn.close()

# Vulnerable template
VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Test Target</title>
</head>
<body>
    <h1>SQL Injection Test Target</h1>
    
    <h2>Login Form</h2>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    
    <h2>Product Search</h2>
    <form method="GET" action="/search">
        <input type="text" name="query" placeholder="Search products...">
        <button type="submit">Search</button>
    </form>
    
    {% if results %}
    <h3>Search Results:</h3>
    <ul>
        {% for result in results %}
        <li>{{ result }}</li>
        {% endfor %}
    </ul>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(VULNERABLE_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Vulnerable SQL query
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    
    if user:
        return f"Welcome, {user[1]}!"
    else:
        return "Invalid credentials"

@app.route('/search')
def search():
    query = request.args.get('query', '')
    
    # Vulnerable SQL query
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    c.execute(sql_query)
    results = c.fetchall()
    conn.close()
    
    formatted_results = [f"Product: {row[1]}, Price: ${row[2]}, Stock: {row[3]}" for row in results]
    return render_template_string(VULNERABLE_TEMPLATE, results=formatted_results)

@app.route('/api/products')
def api_products():
    product_id = request.args.get('id', '')
    
    # Vulnerable SQL query
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    query = f"SELECT * FROM products WHERE id = {product_id}"
    c.execute(query)
    product = c.fetchone()
    conn.close()
    
    if product:
        return jsonify({
            'id': product[0],
            'name': product[1],
            'price': product[2],
            'stock': product[3]
        })
    else:
        return jsonify({'error': 'Product not found'}), 404

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=True) 