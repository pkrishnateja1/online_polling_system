from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this for production
bcrypt = Bcrypt(app)

# Database initialization
def init_db():
    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Polls table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS polls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        emoji TEXT,
        created_by INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closes_at TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    )
    ''')
    
    # Options table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        option_text TEXT NOT NULL,
        emoji TEXT,
        FOREIGN KEY (poll_id) REFERENCES polls (id)
    )
    ''')
    
    # Votes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        option_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES polls (id),
        FOREIGN KEY (option_id) REFERENCES options (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(poll_id, user_id)
    )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Database helper function
def get_db():
    conn = sqlite3.connect('election.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's polls
    cursor.execute('''
    SELECT polls.*, COUNT(votes.id) as vote_count 
    FROM polls 
    LEFT JOIN votes ON votes.poll_id = polls.id 
    WHERE polls.created_by = ? 
    GROUP BY polls.id 
    ORDER BY polls.created_at DESC
    ''', (session['user_id'],))
    user_polls = cursor.fetchall()
    
    # Get all active polls
    cursor.execute('''
    SELECT polls.*, users.username as creator, COUNT(votes.id) as vote_count 
    FROM polls 
    JOIN users ON users.id = polls.created_by 
    LEFT JOIN votes ON votes.poll_id = polls.id 
    WHERE polls.closes_at > datetime('now') OR polls.closes_at IS NULL
    GROUP BY polls.id 
    ORDER BY polls.created_at DESC
    ''')
    active_polls = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         user_polls=user_polls, 
                         active_polls=active_polls,
                         username=session.get('username'))

@app.route('/create_poll', methods=['GET', 'POST'])
def create_poll():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        emoji = request.form.get('emoji', '🗳️')
        
        # Get options and their emojis
        options = []
        option_emojis = []
        
        # Collect all non-empty options
        for key, value in request.form.items():
            if key.startswith('option_text_') and value.strip():
                options.append(value.strip())
                # Get corresponding emoji
                opt_num = key.split('_')[-1]
                option_emojis.append(request.form.get(f'option_emoji_{opt_num}', '🔘'))
        
        if not title:
            flash('Poll title is required', 'danger')
            return redirect(url_for('create_poll'))
        
        if len(options) < 2:
            flash('At least 2 options are required', 'danger')
            return redirect(url_for('create_poll'))
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Insert poll
            cursor.execute('''
            INSERT INTO polls (title, description, emoji, created_by) 
            VALUES (?, ?, ?, ?)
            ''', (title, description, emoji, session['user_id']))
            poll_id = cursor.lastrowid
            
            # Insert options
            for i, option in enumerate(options):
                cursor.execute('''
                INSERT INTO options (poll_id, option_text, emoji) 
                VALUES (?, ?, ?)
                ''', (poll_id, option, option_emojis[i]))
            
            conn.commit()
            flash('Poll created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.rollback()
            flash(f'Error creating poll: {str(e)}', 'danger')
        finally:
            conn.close()
    
    emojis = ['👍', '❤️', '😂', '😮', '😢', '🎉', '🔥', '🌟', '🏆', '💡']
    return render_template('create_poll.html', emojis=emojis)

@app.route('/poll/<int:poll_id>')
def view_poll(poll_id):
    if 'user_id' not in session:
        return redirect(url_for('login', next=url_for('view_poll', poll_id=poll_id)))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get poll details
    cursor.execute('''
    SELECT polls.*, users.username as creator 
    FROM polls 
    JOIN users ON users.id = polls.created_by 
    WHERE polls.id = ?
    ''', (poll_id,))
    poll = cursor.fetchone()
    
    if not poll:
        flash('Poll not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get options
    cursor.execute('''
    SELECT options.*, COUNT(votes.id) as vote_count 
    FROM options 
    LEFT JOIN votes ON votes.option_id = options.id 
    WHERE options.poll_id = ? 
    GROUP BY options.id 
    ORDER BY options.id
    ''', (poll_id,))
    options = cursor.fetchall()
    
    # Check if user already voted
    cursor.execute('''
    SELECT id FROM votes 
    WHERE poll_id = ? AND user_id = ?
    ''', (poll_id, session['user_id']))
    has_voted = cursor.fetchone() is not None
    
    conn.close()
    
    return render_template('poll.html', 
                         poll=poll, 
                         options=options, 
                         has_voted=has_voted)

@app.route('/vote/<int:poll_id>', methods=['POST'])
def vote(poll_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    option_id = request.form.get('option_id')
    if not option_id:
        flash('Please select an option', 'danger')
        return redirect(url_for('view_poll', poll_id=poll_id))
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user already voted
        cursor.execute('''
        SELECT id FROM votes 
        WHERE poll_id = ? AND user_id = ?
        ''', (poll_id, session['user_id']))
        if cursor.fetchone():
            flash('You have already voted in this poll', 'warning')
            return redirect(url_for('view_poll', poll_id=poll_id))
        
        # Record vote
        cursor.execute('''
        INSERT INTO votes (poll_id, option_id, user_id) 
        VALUES (?, ?, ?)
        ''', (poll_id, option_id, session['user_id']))
        
        conn.commit()
        flash('Your vote has been recorded!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error recording vote: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('view_poll', poll_id=poll_id))

@app.route('/results/<int:poll_id>')
def poll_results(poll_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get poll details
    cursor.execute('''
    SELECT polls.*, users.username as creator 
    FROM polls 
    JOIN users ON users.id = polls.created_by 
    WHERE polls.id = ?
    ''', (poll_id,))
    poll = cursor.fetchone()
    
    if not poll:
        flash('Poll not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get options with vote counts
    cursor.execute('''
    SELECT options.*, COUNT(votes.id) as vote_count 
    FROM options 
    LEFT JOIN votes ON votes.option_id = options.id 
    WHERE options.poll_id = ? 
    GROUP BY options.id 
    ORDER BY vote_count DESC
    ''', (poll_id,))
    options = cursor.fetchall()
    
    # Calculate total votes
    total_votes = sum(option['vote_count'] for option in options) if options else 0
    
    # Determine winner(s)
    winners = []
    if options and total_votes > 0:
        max_votes = options[0]['vote_count']
        winners = [option for option in options if option['vote_count'] == max_votes]
    
    conn.close()
    
    return render_template('results.html', 
                         poll=poll, 
                         options=options, 
                         total_votes=total_votes,
                         winners=winners,
                         username=session.get('username'))
# Add these new routes to your existing app.py

@app.route('/share_poll/<int:poll_id>')
def share_poll(poll_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get poll details
    cursor.execute('''
    SELECT polls.*, users.username as creator 
    FROM polls 
    JOIN users ON users.id = polls.created_by 
    WHERE polls.id = ?
    ''', (poll_id,))
    poll = cursor.fetchone()
    
    if not poll:
        flash('Poll not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Generate shareable link
    share_url = url_for('view_poll', poll_id=poll_id, _external=True)
    
    conn.close()
    
    return render_template('share_poll.html', 
                        poll=poll, 
                        share_url=share_url)

@app.route('/my_poll_results/<int:poll_id>')
def my_poll_results(poll_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get poll details and verify owner
    cursor.execute('''
    SELECT polls.*, users.username as creator 
    FROM polls 
    JOIN users ON users.id = polls.created_by 
    WHERE polls.id = ? AND polls.created_by = ?
    ''', (poll_id, session['user_id']))
    poll = cursor.fetchone()
    
    if not poll:
        flash('Poll not found or you are not the owner', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get options with vote counts
    cursor.execute('''
    SELECT options.*, COUNT(votes.id) as vote_count 
    FROM options 
    LEFT JOIN votes ON votes.option_id = options.id 
    WHERE options.poll_id = ? 
    GROUP BY options.id 
    ORDER BY vote_count DESC
    ''', (poll_id,))
    options = cursor.fetchall()
    
    # Calculate total votes
    total_votes = sum(option['vote_count'] for option in options) if options else 0
    
    # Determine winner(s)
    winners = []
    if options and total_votes > 0:
        max_votes = options[0]['vote_count']
        winners = [option for option in options if option['vote_count'] == max_votes]
    
    conn.close()
    
    return render_template('my_poll_results.html', 
                         poll=poll, 
                         options=options, 
                         total_votes=total_votes,
                         winners=winners)
# Add this new route to your existing app.py
@app.route('/delete_poll/<int:poll_id>', methods=['POST'])
def delete_poll(poll_id):
    if 'user_id' not in session:
        flash('You need to login first', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Verify the poll exists and belongs to the current user
        cursor.execute('''
        SELECT id FROM polls 
        WHERE id = ? AND created_by = ?
        ''', (poll_id, session['user_id']))
        poll = cursor.fetchone()
        
        if not poll:
            flash('Poll not found or you are not the owner', 'danger')
            return redirect(url_for('dashboard'))
        
        # Delete all votes for this poll first (to maintain referential integrity)
        cursor.execute('DELETE FROM votes WHERE poll_id = ?', (poll_id,))
        
        # Delete all options for this poll
        cursor.execute('DELETE FROM options WHERE poll_id = ?', (poll_id,))
        
        # Finally delete the poll itself
        cursor.execute('DELETE FROM polls WHERE id = ?', (poll_id,))
        
        conn.commit()
        flash('Poll deleted successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting poll: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)