-- tabel pentru gestionarea utilizatorilor
CREATE TABLE Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name VARCHAR(255) NOT NULL,
    hash_password VARCHAR(255) NOT NULL 
);

-- tabel pentru catalogarea algoritmilor disponibili
CREATE TABLE Algorithm (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alg_name VARCHAR(255) NOT NULL, 
    alg_type VARCHAR(255), 
    key_bit_length INTEGER, 
    block_bit_dimension INTEGER 
);

-- tabel pentru stocarea cheilor de criptare
CREATE TABLE Keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER REFERENCES Users(id),
    id_algorithm INTEGER REFERENCES Algorithm(id),
    key_value BLOB NOT NULL,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- tabel pentru metadatele fisierelor criptate
CREATE TABLE File (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_key INTEGER REFERENCES Keys(id) UNIQUE,
    id_user INTEGER REFERENCES Users(id),
    id_framework INTEGER REFERENCES Framework(id), 
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(255),
    dimension INTEGER, -- dimensiunea in octeti
    file_path VARCHAR(255), 
    encrypt_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    en_status VARCHAR(50), -- 'Encrypted' sau 'Decrypted' 
    original_hash BLOB, -- SHA-256 al fisierului original pentru verificarea integritatii 
    encrypted_hash BLOB, -- SHA-256 al fisierului criptat
    integrity_payload BLOB,
    init_vector BLOB 
);

-- tabel pentru framework-urile utilizate
CREATE TABLE Framework (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_name VARCHAR(255) NOT NULL, 
    framework_version VARCHAR(255)
);

-- tabel pentru stocarea metodică a testelor de performanta
CREATE TABLE Performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_file INTEGER REFERENCES File(id), 
    id_algorithm INTEGER REFERENCES Algorithm(id),
    id_framework INTEGER REFERENCES Framework(id),
    operation_type VARCHAR(50), -- 'Encryption' sau 'Decryption' 
    time_exec_ms REAL, -- timp de executie in milisecunde 
    memory_peak_kb INTEGER -- consumul maxim de memorie
);