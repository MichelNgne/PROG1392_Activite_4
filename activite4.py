# Activité #4 - Protection des secrets (.env), obfuscation et protection des branches
"""
Auteurs
Ange Nikuze
Ange Michel
Gildas Ciani
Richard Silue
Date: 2025-06-06

"""

#lire le fichier .env

from dotenv import load_dotenv
import os

#importation de sqlite3
import sqlite3
import tkinter as tk
from tkinter import messagebox
import hashlib


load_dotenv()



nom = os.getenv("NOM")
motdepasse = os.getenv("MOTDEPASSE")
db = os.getenv("DB")
port = os.getenv("PORT")
host = os.getenv("HOST")

#print(f"Nom: {nom}, Mot de passe: {motdepasse}, DB: {db}, Port: {port}, Host: {host}")

# UI - Login 
def save_user(username, password):
        # SQL (SAVE AU DB)
        # global c, conn
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT
        )
    ''')
        
        password = hashlib.sha256(password.encode()).hexdigest()
        
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        
        print("SAVE")


def validate_user(username, password): 
        # VERIFIER AVEC SQL (OUBLIER PAS LE HASH)
        conn = sqlite3.connect(db)
        c = conn.cursor()
        password = hashlib.sha256(password.encode()).hexdigest()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        result = c.fetchone()
        return result is not None
    
#Login dans l'interface
def login():
    if validate_user(username_entry.get(), password_entry.get()):
        messagebox.showinfo("Login", "CONENXION REUSSIE")
    else:
        messagebox.showinfo("Login", "ECHEC DE CONENXION")
        
def open_register():
    print("NOUVELLE FENETRE POUR NOUVEL UTILISATEUR")

    register_window = tk.Toplevel(window)
    register_window.title("Nouvel Utilisateur")
    register_window.geometry("300x200")
    tk.Label(register_window, text="Nom User").pack()
    new_username_entry = tk.Entry(register_window)  
    new_username_entry.pack()
    
    tk.Label(register_window, text="Mot de passe").pack()
    new_password_entry = tk.Entry(register_window, show="*") 
    new_password_entry.pack()
    tk.Button(register_window, text="Enregistrer", command=lambda: save_user(new_username_entry.get(), new_password_entry.get())).pack(pady=5)
    

    

window = tk.Tk()
window.title("Authentification")
window.geometry("300x200")

tk.Label(window, text="Username").pack()
username_entry = tk.Entry(window)
username_entry.pack()

tk.Label(window, text="Password").pack()
password_entry = tk.Entry(window, show="*")
password_entry.pack()

tk.Button(window, text="Login", command=login).pack(pady=5)
tk.Button(window, text="Register", command=open_register).pack()

window.mainloop()