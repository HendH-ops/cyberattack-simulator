from flask import Flask, request, render_template_string, jsonify
import os

app = Flask(__name__)

# Store comments in memory (for demonstration)
comments = []

# Vulnerable template with intentional XSS vulnerabilities
VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Test Target</title>
    <style>
        .vulnerable { color: red; }
        .comment { margin: 10px; padding: 10px; border: 1px solid #ccc; }
    </style>
</head>
<body>
    <h1>XSS Test Target</h1>
    
    <h2>Reflected XSS</h2>
    <form method="GET">
        <input type="text" name="search" placeholder="Search...">
        <button type="submit">Search</button>
    </form>
    <!-- Intentionally vulnerable: No HTML escaping -->
    <p>Search results for: {{ search_query }}</p>
    
    <h2>Stored XSS</h2>
    <form method="POST">
        <textarea name="comment" placeholder="Leave a comment..."></textarea>
        <button type="submit">Submit</button>
    </form>
    <div id="comments">
        <!-- Intentionally vulnerable: No HTML escaping -->
        {% for comment in comments %}
        <div class="comment">{{ comment }}</div>
        {% endfor %}
    </div>
    
    <h2>DOM XSS</h2>
    <p>Current URL: <span id="url-display"></span></p>
    <script>
        // Intentionally vulnerable: Directly using location.hash without sanitization
        document.getElementById('url-display').innerHTML = window.location.hash;
    </script>

    <h2>API Endpoint</h2>
    <form method="GET" action="/api/search">
        <input type="text" name="q" placeholder="Search API...">
        <button type="submit">Search API</button>
    </form>
    <div id="api-results"></div>
    <script>
        // Intentionally vulnerable: Directly using user input in innerHTML
        document.querySelector('form[action="/api/search"]').onsubmit = function(e) {
            e.preventDefault();
            const query = this.querySelector('input[name="q"]').value;
            fetch(`/api/search?q=${query}`)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('api-results').innerHTML = data.results;
                });
        };
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    search_query = request.args.get('search', '')
    return render_template_string(VULNERABLE_TEMPLATE, 
                                search_query=search_query,
                                comments=comments)

@app.route('/', methods=['POST'])
def add_comment():
    comment = request.form.get('comment', '')
    if comment:
        comments.append(comment)
    return index()

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')
    # Intentionally vulnerable: No sanitization of user input
    return jsonify({
        'query': query,
        'results': f"<div>Search results for: {query}</div>"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True) 