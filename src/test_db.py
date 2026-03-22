import db_manager as db

# initializare tabele
#db.init_db()

algo_id = db.add_algorithm("AES-256-GCM", "Symmetric", 256, 128)
fw_id = db.register_framework("OpenSSL", "3.0.7")
# adaugare utilizator
uid = db.create_user("vasile_admin", "parola_hashuita")
print(f"Utilizator creat cu ID: {uid}")

test_file = {
    'user_id': uid,
    'algo_id': algo_id,      
    'framework_id': fw_id,   
    'key_bytes': b'\xaf\xfe...', 
    'name': 'secret.docx',
    'type': 'docx',
    'size': 50240,
    'path': 'D:/proiect/secret.enc',
    'orig_hash': b'...',
    'enc_hash': b'...',
    'payload': b'...',
    'iv': b'\x00\x01\x02\x03'
}

fid = db.register_encrypted_file(test_file)
print(f"Fisier inregistrat cu ID: {fid}")

# citire date
file_info = db.get_file_metadata(fid)
if file_info:
    print(f"Verificare: Fisierul {file_info['file_name']} are statusul {file_info['en_status']}")
    print(f"Cheia recuperata din BLOB: {file_info['key_value'].hex()}")

db.log_test_performance({
    'f_id': fid, 'a_id': 1, 'fw_id': 1, 
    'op': 'Encryption', 'time': 45.2, 'mem': 1200
})
print("Performanta inregistrata cu succes.")