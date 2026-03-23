import db_manager as db

# initializare tabele
db.init_db()

algo_id = db.add_algorithm("AES-256-GCM", "Symmetric", 256, 128)
fw_id = db.register_framework("OpenSSL", "3.0.7")
# adaugare utilizator
uid = db.create_user("vasile_admin", "parola_hashuita")
print(f"Utilizator creat cu ID: {uid}\n")

test_file = {
    'user_id': uid,
    'algo_id': algo_id,      
    'framework_id': fw_id,
    'public_key_bytes': None,
    'private_key_bytes': b'\xaf\xfe...', 
    'name': 'secret.docx',
    'type': 'docx',
    'size': 50240,
    'path': 'D:/proiect/secret.enc',
    'orig_hash': b'...',
    'enc_hash': b'...',
    'payload': b'...',
    'iv': b'\x00\x01\x02\x03'
}

test_file2 = {
    'user_id': uid,
    'algo_id': algo_id,      
    'framework_id': fw_id,
    'public_key_bytes': None,   
    'private_key_bytes': b'\xaf\xfe...', 
    'name': 'secretx.docx',
    'type': 'docx',
    'size': 60000,
    'path': 'D:/proiect/secretx.enc',
    'orig_hash': b'...',
    'enc_hash': b'...',
    'payload': b'...',
    'iv': b'\x00\x01\x02\x03'
}
fid = db.register_encrypted_file(test_file)
print(f"Fisier inregistrat cu ID: {fid}\n")
fid2 = db.register_encrypted_file(test_file2)
print(f"Fisier inregistrat cu ID: {fid2}\n")

# afisarea tuturor fisierelor unui utilizator
print("\nLista fisierelor utilizatorului")
user_files = db.get_all_user_files(uid)
for f in user_files:
    print(f"ID: {f['id']} | Nume: {f['file_name']} | Status: {f['en_status']}")

#update status fisier
db.update_file_status(fid, "Decrypted")
print(f"\n[UPDATE] Statusul fisierului {fid} a fost actualizat.")

# citire date
file_info = db.get_file_metadata(fid)
if file_info:
    print(f"Verificare: Fisierul {file_info['file_name']} are statusul {file_info['en_status']}")
    print(f"Public Key (BLOB): {file_info['public_key']}")
    print(f"Private/Symmetric Key (BLOB): {file_info['private_key'].hex()}")

db.log_test_performance({
    'f_id': fid, 'a_id': algo_id, 'fw_id': fw_id, 
    'op': 'Encryption', 'time': 45.2, 'mem': 1200
})


print("Performanta inregistrata cu succes.")

db.delete_file_and_key(fid)
print(f"Fisierul {fid} a fost sters din baza de date.")

print("\nLista fisierelor utilizatorului dupa stergere")
user_files = db.get_all_user_files(uid)
for f in user_files:
    print(f"ID: {f['id']} | Nume: {f['file_name']} | Status: {f['en_status']}")

print("\n--- Toate testele DB au fost finalizate cu succes ---")
