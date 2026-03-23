import sqlite3

def get_connection():
    conn = sqlite3.connect('../database/ekms.db')
    # suport pentru chei externe in SQLitwe
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Creare tabele."""
    conn = get_connection()
   
    sql_script = """
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name VARCHAR(255) NOT NULL,
        hash_password VARCHAR(255) NOT NULL 
    );
    CREATE TABLE IF NOT EXISTS Algorithm (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alg_name VARCHAR(255) NOT NULL, 
        alg_type VARCHAR(255), 
        key_bit_length INTEGER, 
        block_bit_dimension INTEGER 
    );
    CREATE TABLE IF NOT EXISTS Keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_user INTEGER REFERENCES Users(id),
        id_algorithm INTEGER REFERENCES Algorithm(id),
        key_value BLOB NOT NULL,
        creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS Framework (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        framework_name VARCHAR(255) NOT NULL, 
        framework_version VARCHAR(255)
    );
    CREATE TABLE IF NOT EXISTS File (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_key INTEGER UNIQUE REFERENCES Keys(id),
        id_user INTEGER REFERENCES Users(id),
        id_framework INTEGER REFERENCES Framework(id), 
        file_name VARCHAR(255) NOT NULL,
        file_type VARCHAR(255),
        dimension INTEGER,
        file_path VARCHAR(255), 
        encrypt_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        en_status VARCHAR(50), 
        original_hash BLOB, 
        encrypted_hash BLOB,
        integrity_payload BLOB,
        init_vector BLOB 
    );
    CREATE TABLE IF NOT EXISTS Performance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_file INTEGER REFERENCES File(id), 
        id_algorithm INTEGER REFERENCES Algorithm(id),
        id_framework INTEGER REFERENCES Framework(id),
        operation_type VARCHAR(50), 
        time_exec_ms REAL, 
        memory_peak_kb INTEGER
    );
    """
    conn.executescript(sql_script)
    conn.close()

# opratii CRUD

def create_user(username, hashed_pw):
    """CREATE: adaugarea unui utilizator."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "INSERT INTO Users (user_name, hash_password) VALUES (?,?)"
    cursor.execute(query, (username, hashed_pw))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def register_encrypted_file(file_data):
    """CREATE: salveaza metadatele fisierului si cheia asociata."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        
        cursor.execute("INSERT INTO Keys (id_user, id_algorithm, key_value) VALUES (?,?,?)", (file_data['user_id'], file_data['algo_id'], file_data['key_bytes']))
        key_id = cursor.lastrowid

        query_file = """
        INSERT INTO File (id_key, id_user, id_framework, file_name, file_type, dimension, 
                          file_path, en_status, original_hash, encrypted_hash, integrity_payload, init_vector)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """
        params = (key_id, file_data['user_id'], file_data['framework_id'], file_data['name'], 
                  file_data['type'], file_data['size'], file_data['path'], 'Encrypted',
                  file_data['orig_hash'], file_data['enc_hash'], file_data['payload'], file_data['iv'])
        
        cursor.execute(query_file, params)
        file_id = cursor.lastrowid
        conn.commit()
        return file_id
    except sqlite3.Error as e:
        print(f"Eroare DB: {e}")
        conn.rollback()
    finally:
        conn.close()

def add_algorithm(name, alg_type, key_len, block_dim=None):
    """CREATE: adaugare algoritm."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Algorithm WHERE alg_name = ?", (name,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return row[0]   #returnare id existent
    
    query = "INSERT INTO Algorithm (alg_name, alg_type, key_bit_length, block_bit_dimension) VALUES (?,?,?,?)"
    try:
        cursor.execute(query, (name, alg_type, key_len, block_dim))
        algo_id = cursor.lastrowid
        conn.commit()
        return algo_id
    except sqlite3.Error as e:
        print(f"Eroare la adaugarea algoritmului: {e}")
        return None
    finally:
        conn.close()

def register_framework(name, version):
    """CREATE: Inregistrare framework. """
    conn = get_connection()
    cursor = conn.cursor()
    query = "INSERT INTO Framework (framework_name, framework_version) VALUES (?,?)"
    try:
        cursor.execute(query, (name, version))
        fw_id = cursor.lastrowid
        conn.commit()
        return fw_id
    except sqlite3.Error as e:
        print(f"Eroare la inregistrarea framework-ului: {e}")
        return None
    finally:
        conn.close()

def get_file_metadata(file_id):
    """READ: extrage metadate necesare pentru decriptare."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row # permit accesul prin numele coloanei
    cursor = conn.cursor()
    query = """
    SELECT F.*, K.key_value 
    FROM File F 
    JOIN Keys K ON F.id_key = K.id 
    WHERE F.id =?
    """
    cursor.execute(query, (file_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_all_user_files(user_id):
    """READ: Retunreaza toate fisierele unui user"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_name, en_status, encrypt_date FROM File WHERE id_user = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_file_status(file_id, new_status):
    """UPDATE: actualizez starea fisierului."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE File SET en_status =? WHERE id =?", (new_status, file_id))
    conn.commit()
    conn.close()

def delete_file_and_key(file_id):
    """DELETE: Stergere fisier si cheia asociata acestuia"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM Performance WHERE id_file = ?", (file_id,))
        cursor.execute("SELECT id_key FROM File WHERE id = ?", (file_id,))
        res = cursor.fetchone()
        if res:
            key_id = res[0]
            cursor.execute("DELETE FROM File WHERE id = ?", (file_id,))
            cursor.execute("DELETE FROM Keys WHERE id = ?", (key_id,))
            conn.commit()
            return True
    except sqlite3.Error as e:
        print(f"Eroare la stergere: {e}")
        conn.rollback()
    finally:
        conn.close()
    return False


def log_test_performance(perf_data):
    """CREATE: test."""
    conn = get_connection()
    cursor = conn.cursor()
    query = """
    INSERT INTO Performance (id_file, id_algorithm, id_framework, operation_type, time_exec_ms, memory_peak_kb)
    VALUES (?,?,?,?,?,?)
    """
    cursor.execute(query, (perf_data['f_id'], perf_data['a_id'], perf_data['fw_id'], 
                           perf_data['op'], perf_data['time'], perf_data['mem']))
    conn.commit()
    conn.close()