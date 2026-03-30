import os
import json
import sqlite3
import hashlib
from flask import Flask, request, jsonify, session, send_from_directory

# --- Configuration ---
# Set the root directory to the folder containing this script
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
# CRITICAL: You must change this key to a long, random string for security
app.secret_key = 'your_super_secret_key_that_should_be_long_and_random' 
DATABASE = os.path.join(ROOT_DIR, 'finplan_users.db')
# --- End Configuration ---

# --- Database Initialization ---
def init_db():
    """Initializes the SQLite database and creates the users table."""
    with app.app_context():
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # 1. Create Users Table (Stores login info and the data JSON for each user)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                user_data TEXT 
            )
        ''')
        
        # 2. Add an index for faster lookups
        cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_username ON users (username)')
        
        conn.commit()
        conn.close()

def get_db():
    """Returns a connection to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

# --- Utility Functions ---

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_data(user_id):
    """Retrieves all data for a given user ID, or returns a default empty structure."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Attempt to fetch the user_data column
    cursor.execute('SELECT user_data FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    # Define a guaranteed safe fallback structure
    SAFE_DEFAULT_DATA = { "recurringSchedules": [], "oneTimeTransactions": [], "debtPlans": [], "settings": {} }

    if row and row['user_data']:
        try:
            # IMPORTANT: Safely deserialize the JSON string
            data = json.loads(row['user_data'])
            app.logger.info(f"Successfully loaded data for user ID: {user_id}")
            return data
        except json.JSONDecodeError as e:
            # CRITICAL: Log the error if the saved data is corrupted
            app.logger.error(f"ERROR LOADING USER DATA: JSON decode failure for user ID {user_id}: {e}", exc_info=True)
            # If data is corrupted, return the safe default structure.
            return SAFE_DEFAULT_DATA
    
    # Default structure for new users or users with no saved data
    app.logger.info(f"No existing data found for user ID: {user_id}. Returning default structure.")
    return SAFE_DEFAULT_DATA

def save_user_data(user_id, data):
    """Saves the entire data structure for a given user ID."""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # IMPORTANT: Safely serialize the data structure to a JSON string
        json_data = json.dumps(data)
        
        # Update the user's data
        cursor.execute('UPDATE users SET user_data = ? WHERE id = ?', (json_data, user_id))
        conn.commit()
        app.logger.info(f"Successfully saved data for user ID: {user_id}")
    except Exception as e:
        # CRITICAL: Log the error if saving fails
        app.logger.error(f"ERROR SAVING USER DATA: Database/Serialization failure for user ID {user_id}: {e}", exc_info=True)
        conn.rollback() # Ensure no partial write happens
    finally:
        conn.close()


# --- API Endpoints ---

@app.route('/')
def index():
    """Serves the main HTML file."""
    # NOTE: FINAPP3.html must be in the same directory as app.py
    return send_from_directory(ROOT_DIR, 'FINAPP3.html')


@app.route('/api/auth/register', methods=['POST'])
def register():
    """Handles new user registration."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    hashed_password = hash_password(password)
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Create user with an empty data set
        cursor.execute('INSERT INTO users (username, password_hash, user_data) VALUES (?, ?, ?)',
                       (username, hashed_password, '{}'))
        conn.commit()
        
        # Log the user in immediately after registration
        user_id = cursor.lastrowid
        session['user_id'] = user_id
        session['username'] = username
        app.logger.info(f"New user registered and logged in: {username} (ID: {user_id})")
        
        return jsonify({'success': True, 'message': 'Registration successful', 'username': username}), 200
    
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already taken'}), 409
    
    except Exception as e:
        app.logger.error(f"Database error during registration: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An internal error occurred'}), 500
    finally:
        conn.close()


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Handles user login."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    hashed_password = hash_password(password)
    conn = get_db()
    cursor = conn.cursor()
    
    # Retrieve user by username
    cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user['password_hash'] == hashed_password:
        # Success: Set session data
        session['user_id'] = user['id']
        session['username'] = username
        app.logger.info(f"User successfully logged in: {username}")
        return jsonify({'success': True, 'message': 'Login successful', 'username': username}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401


@app.route('/api/auth/status')
def auth_status():
    """Checks the authentication status."""
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'username': session['username'], 'user_id': session['user_id']}), 200
    return jsonify({'logged_in': False}), 200


@app.route('/api/auth/logout')
def logout():
    """Logs out the user by clearing the session."""
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200


@app.route('/api/load-data')
def load_data():
    """Loads user-specific financial data."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    SAFE_DEFAULT_DATA = { "recurringSchedules": [], "oneTimeTransactions": [], "debtPlans": [], "settings": {} }
    
    # CRITICAL: This try-except block is designed to catch *any* failure during database read
    # and guarantee the frontend gets a valid 200 OK response with the minimum data structure.
    try:
        data = get_user_data(user_id)
        return jsonify(data), 200
    except Exception as e:
        app.logger.error(f"FATAL ERROR IN LOAD DATA ROUTE (DB Connection/Outer Logic) for user {user_id}: {e}", exc_info=True)
        # On a fatal server error, return the safe default structure with a 200 status 
        # to ensure the frontend continues and the app appears.
        return jsonify(SAFE_DEFAULT_DATA), 200


@app.route('/api/save-data', methods=['POST'])
def save_data():
    """Saves user-specific financial data."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    # CRITICAL: This try-except block logs the error if the database or JSON saving fails.
    try:
        save_user_data(user_id, data)
        return jsonify({'success': True, 'message': 'Data saved successfully'}), 200
    except Exception as e:
        app.logger.error(f"FATAL ERROR IN SAVE DATA ROUTE for user {user_id}: {e}", exc_info=True)
        # Return an error response so the frontend knows the save failed
        return jsonify({'error': 'Failed to save data due to an internal server error.'}), 500


if __name__ == '__main__':
    # Initialize the database when the script is run directly
    init_db()
    # Set debug=True for development to auto-reload
    app.run(debug=True)
