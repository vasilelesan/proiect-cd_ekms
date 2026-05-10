import sqlite3

import os
import sqlite3

def get_connection():
    # 1. exatregere cale pentu fisierul curent (db_manager.py)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Construim calea către baza de date plecând de la folderul 'db'
    # Dacă structura ta este: src/db/db_manager.py și src/database/ekms.db
    # Atunci mergem un nivel sus (..) și apoi în database
    #db_path = os.path.abspath(os.path.join(current_dir, "..", ".." "database", "ekms.db"))
    # go up to 'src'
    src_dir = os.path.dirname(current_dir)
    
    # go up to project root
    root_dir = os.path.dirname(src_dir)
    
    # build path to database folder
    db_path = os.path.join(root_dir, "database", "ekms.db")
    
    # 3. initializare director database
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # 4. conectare la baza de date
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error as e:
        print(f"Eroare la conectarea DB la calea {db_path}: {e}")
        raise e

def add_column_if_not_exists(conn, table_name, column_name, column_definition):
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]

    if column_name not in columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )

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
        public_key BLOB,
        private_key BLOB NOT NULL,
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
    # create default user if table is empty
    add_column_if_not_exists(conn, "File", "original_dimension", "INTEGER")
    add_column_if_not_exists(conn, "File", "encrypted_dimension", "INTEGER")
    add_column_if_not_exists(conn, "File", "decrypted_dimension", "INTEGER")

    add_column_if_not_exists(conn, "Performance", "input_bytes", "INTEGER")
    add_column_if_not_exists(conn, "Performance", "output_bytes", "INTEGER")
    add_column_if_not_exists(conn, "Performance", "time_per_byte", "REAL")
    add_column_if_not_exists(conn, "Performance", "memory_per_byte", "REAL")

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO Users (id, user_name, hash_password) VALUES (1, 'admin', 'dummy_hash')")
        conn.commit()
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
        cursor.execute(
            """
            INSERT INTO Keys 
            (id_user, id_algorithm, public_key, private_key) 
            VALUES (?, ?, ?, ?)
            """,
            (
                file_data["user_id"],
                file_data["algo_id"],
                file_data["public_key_bytes"],
                file_data["private_key_bytes"]
            )
        )

        key_id = cursor.lastrowid

        query_file = """
        INSERT INTO File (
            id_key,
            id_user,
            id_framework,
            file_name,
            file_type,
            dimension,
            original_dimension,
            encrypted_dimension,
            decrypted_dimension,
            file_path,
            en_status,
            original_hash,
            encrypted_hash,
            integrity_payload,
            init_vector
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        params = (
            key_id,
            file_data["user_id"],
            file_data["framework_id"],
            file_data["name"],
            file_data["type"],
            file_data["size"],
            file_data.get("original_dimension"),
            file_data.get("encrypted_dimension"),
            file_data.get("decrypted_dimension"),
            file_data["path"],
            "Encrypted",
            file_data["orig_hash"],
            file_data["enc_hash"],
            file_data["payload"],
            file_data["iv"]
        )

        cursor.execute(query_file, params)

        file_id = cursor.lastrowid
        conn.commit()
        return file_id

    except sqlite3.Error as e:
        print(f"Eroare DB: {e}")
        conn.rollback()
        return None

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
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = """
    SELECT F.*, K.public_key, K.private_key, K.id_algorithm, A.alg_name
    FROM File F 
    JOIN Keys K ON F.id_key = K.id 
    JOIN Algorithm A ON K.id_algorithm = A.id
    WHERE F.id =?
    """
    cursor.execute(query, (file_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_encrypted_files():
    """READ: returneaza doar fisierele care sunt criptate pentru a popula dropdown-ul."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_name FROM File WHERE en_status = 'Encrypted'")
    rows = cursor.fetchall()
    conn.close()
    return rows

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

def get_performance_report():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
    SELECT 
        F.id AS file_id,
        F.file_name,
        F.en_status,
        F.dimension,
        F.original_dimension,
        F.encrypted_dimension,
        F.decrypted_dimension,

        A.alg_name,

        FW.framework_name AS fw_name,

        P.operation_type,
        P.time_exec_ms AS time,
        P.memory_peak_kb AS mem,
        P.input_bytes,
        P.output_bytes,
        P.time_per_byte,
        P.memory_per_byte,

        K.private_key

    FROM Performance P
    JOIN File F ON P.id_file = F.id
    JOIN Algorithm A ON P.id_algorithm = A.id
    JOIN Framework FW ON P.id_framework = FW.id
    JOIN Keys K ON F.id_key = K.id
    ORDER BY P.id DESC
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_decrypted_file_size(file_id, decrypted_dimension):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE File
        SET decrypted_dimension = ?, en_status = ?
        WHERE id = ?
        """,
        (decrypted_dimension, "Decrypted", file_id)
    )

    conn.commit()
    conn.close()

def log_test_performance(perf_data):
    """CREATE: salvare performanta criptare/decriptare."""
    conn = get_connection()
    cursor = conn.cursor()

    input_bytes = perf_data.get("input_bytes", 0) or 0
    output_bytes = perf_data.get("output_bytes", 0) or 0

    reference_bytes = max(input_bytes, 1)

    time_per_byte = perf_data["time"] / reference_bytes
    memory_per_byte = perf_data["mem"] / reference_bytes

    query = """
    INSERT INTO Performance (
        id_file,
        id_algorithm,
        id_framework,
        operation_type,
        time_exec_ms,
        memory_peak_kb,
        input_bytes,
        output_bytes,
        time_per_byte,
        memory_per_byte
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    cursor.execute(
        query,
        (
            perf_data["f_id"],
            perf_data["a_id"],
            perf_data["fw_id"],
            perf_data["op"],
            perf_data["time"],
            perf_data["mem"],
            input_bytes,
            output_bytes,
            time_per_byte,
            memory_per_byte
        )
    )

    conn.commit()
    conn.close()

def get_all_keys():
    """Returnarea tuturor cheilor de criptare salvate in DB."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # fetch id and private_key
    cursor.execute("SELECT id, private_key, public_key FROM Keys")
    rows = cursor.fetchall()
    conn.close()
    return rows