#!/usr/bin/env python3
"""
Password Manager with warm brown gui
Requires: pip install cryptography
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from pathlib import Path
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x700")
        
        # Colors inspired by Claude's design
        self.bg_gradient = "#f5f0e8"
        self.card_bg = "#ffffff"
        self.primary = "#a77b5c"
        self.primary_hover = "#8d6549"
        self.text_dark = "#6b5544"
        self.text_gray = "#666666"
        self.border = "#d4c5b3"
        
        self.root.configure(bg=self.bg_gradient)
        
        self.data_file = Path.home() / ".password_manager_data.json"
        self.cipher = None
        self.passwords = []
        self.is_unlocked = False
        
        self.create_login_screen()
    
    def derive_key(self, password, salt):
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def create_login_screen(self):
        """Create the master password login screen"""
        self.login_frame = tk.Frame(self.root, bg=self.bg_gradient)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Lock icon container
        icon_frame = tk.Frame(self.login_frame, bg="#fef3c7", width=80, height=80)
        icon_frame.pack(pady=(0, 20))
        icon_frame.pack_propagate(False)
        
        lock_label = tk.Label(icon_frame, text="LOCK", font=("Arial", 20, "bold"), bg="#fef3c7")
        lock_label.place(relx=0.5, rely=0.5, anchor="center")
        
        # Card container
        card = tk.Frame(self.login_frame, bg=self.card_bg, padx=40, pady=30)
        card.pack()
        
        # Add subtle shadow effect
        card.configure(highlightbackground=self.border, highlightthickness=1)
        
        title = tk.Label(card, text="Password Manager", font=("Arial", 24, "bold"),
                        bg=self.card_bg, fg=self.text_dark)
        title.pack(pady=(0, 5))
        
        subtitle = tk.Label(card, text="Enter master password", font=("Arial", 11),
                           bg=self.card_bg, fg=self.text_gray)
        subtitle.pack(pady=(0, 20))
        
        self.master_password_entry = tk.Entry(card, show="*", font=("Arial", 12),
                                              width=30, relief="solid", bd=2)
        self.master_password_entry.configure(highlightbackground=self.border,
                                            highlightcolor=self.primary,
                                            highlightthickness=2)
        self.master_password_entry.pack(pady=(0, 20), ipady=8)
        self.master_password_entry.bind("<Return>", lambda e: self.unlock())
        
        unlock_btn = tk.Button(card, text="Unlock", command=self.unlock,
                              bg=self.primary, fg="white", font=("Arial", 12, "bold"),
                              relief="flat", cursor="hand2", width=30, height=2)
        unlock_btn.pack()
        
        # Hover effects
        unlock_btn.bind("<Enter>", lambda e: unlock_btn.config(bg=self.primary_hover))
        unlock_btn.bind("<Leave>", lambda e: unlock_btn.config(bg=self.primary))
        
        self.master_password_entry.focus()
    
    def unlock(self):
        """Unlock the password manager"""
        master_pw = self.master_password_entry.get()
        
        if len(master_pw) < 4:
            messagebox.showerror("Error", "Master password must be at least 4 characters")
            return
        
        # Load or create data file
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                data = json.load(f)
                salt = base64.b64decode(data['salt'])
        else:
            salt = os.urandom(16)
            data = {'salt': base64.b64encode(salt).decode(), 'passwords': []}
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
        
        key = self.derive_key(master_pw, salt)
        self.cipher = Fernet(key)
        self.is_unlocked = True
        
        # Load passwords
        try:
            self.passwords = []
            for entry in data.get('passwords', []):
                decrypted = {
                    'site': self.cipher.decrypt(entry['site'].encode()).decode(),
                    'username': self.cipher.decrypt(entry['username'].encode()).decode(),
                    'password': self.cipher.decrypt(entry['password'].encode()).decode(),
                }
                self.passwords.append(decrypted)
        except:
            messagebox.showerror("Error", "Invalid master password")
            return
        
        self.login_frame.destroy()
        self.create_main_screen()
    
    def save_passwords(self):
        """Save encrypted passwords to file"""
        with open(self.data_file, 'r') as f:
            data = json.load(f)
        
        encrypted_passwords = []
        for entry in self.passwords:
            encrypted_passwords.append({
                'site': self.cipher.encrypt(entry['site'].encode()).decode(),
                'username': self.cipher.encrypt(entry['username'].encode()).decode(),
                'password': self.cipher.encrypt(entry['password'].encode()).decode(),
            })
        
        data['passwords'] = encrypted_passwords
        
        with open(self.data_file, 'w') as f:
            json.dump(data, f)
    
    def create_main_screen(self):
        """Create the main password manager interface"""
        # Header
        header = tk.Frame(self.root, bg=self.card_bg, pady=20, padx=30)
        header.pack(fill="x", padx=40, pady=(40, 20))
        
        title = tk.Label(header, text="Password Manager", font=("Arial", 28, "bold"),
                        bg=self.card_bg, fg=self.text_dark)
        title.pack(side="left")
        
        add_btn = tk.Button(header, text="+ Add Password", command=self.show_add_dialog,
                           bg=self.primary, fg="white", font=("Arial", 11, "bold"),
                           relief="flat", cursor="hand2", padx=20, pady=8)
        add_btn.pack(side="right")
        add_btn.bind("<Enter>", lambda e: add_btn.config(bg=self.primary_hover))
        add_btn.bind("<Leave>", lambda e: add_btn.config(bg=self.primary))
        
        # Search
        search_frame = tk.Frame(self.root, bg=self.card_bg, pady=15, padx=30)
        search_frame.pack(fill="x", padx=40, pady=(0, 20))
        
        search_label = tk.Label(search_frame, text="Search:", font=("Arial", 11), bg=self.card_bg)
        search_label.pack(side="left", padx=(0, 10))
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_passwords())
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               font=("Arial", 12), relief="solid", bd=2)
        search_entry.configure(highlightbackground=self.border,
                              highlightcolor=self.primary, highlightthickness=2)
        search_entry.pack(fill="x", ipady=6)
        
        # Scrollable password list
        canvas_frame = tk.Frame(self.root, bg=self.bg_gradient)
        canvas_frame.pack(fill="both", expand=True, padx=40, pady=(0, 40))
        
        self.canvas = tk.Canvas(canvas_frame, bg=self.bg_gradient, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.bg_gradient)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Enable mouse wheel scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
        
        self.display_passwords()
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def display_passwords(self):
        """Display all password entries"""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        if not self.passwords:
            empty_frame = tk.Frame(self.scrollable_frame, bg=self.card_bg, pady=60)
            empty_frame.pack(fill="x", pady=20)
            
            tk.Label(empty_frame, text="LOCK", font=("Arial", 36, "bold"),
                    bg=self.card_bg, fg=self.text_gray).pack()
            tk.Label(empty_frame, text="No passwords stored yet",
                    font=("Arial", 16), bg=self.card_bg, fg=self.text_gray).pack(pady=(10, 5))
            tk.Label(empty_frame, text="Click 'Add Password' to get started",
                    font=("Arial", 11), bg=self.card_bg, fg=self.text_gray).pack()
            return
        
        for i, entry in enumerate(self.passwords):
            self.create_password_card(entry, i)
    
    def create_password_card(self, entry, index):
        """Create a card for a single password entry"""
        card = tk.Frame(self.scrollable_frame, bg=self.card_bg, pady=20, padx=25)
        card.pack(fill="x", pady=(0, 15))
        
        # Site name
        site_label = tk.Label(card, text=entry['site'], font=("Arial", 18, "bold"),
                             bg=self.card_bg, fg=self.text_dark, anchor="w")
        site_label.pack(fill="x")
        
        # Username row
        username_frame = tk.Frame(card, bg=self.card_bg)
        username_frame.pack(fill="x", pady=(10, 5))
        
        tk.Label(username_frame, text="Username:", font=("Arial", 10),
                bg=self.card_bg, fg=self.text_gray).pack(side="left")
        tk.Label(username_frame, text=entry['username'], font=("Arial", 11),
                bg=self.card_bg, fg="#000000").pack(side="left", padx=(5, 10))
        
        copy_user_btn = tk.Button(username_frame, text="Copy", command=lambda: self.copy_to_clipboard(entry['username']),
                                 relief="flat", cursor="hand2", bg=self.card_bg, font=("Arial", 10))
        copy_user_btn.pack(side="left")
        
        # Password row
        password_frame = tk.Frame(card, bg=self.card_bg)
        password_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(password_frame, text="Password:", font=("Arial", 10),
                bg=self.card_bg, fg=self.text_gray).pack(side="left")
        
        password_text = tk.StringVar(value="********")
        password_label = tk.Label(password_frame, textvariable=password_text,
                                 font=("Courier", 11), bg=self.card_bg, fg="#000000")
        password_label.pack(side="left", padx=(5, 10))
        
        show_btn = tk.Button(password_frame, text="Show", 
                            command=lambda: self.toggle_password(password_text, entry['password'], show_btn),
                            relief="flat", cursor="hand2", bg=self.card_bg, font=("Arial", 10))
        show_btn.pack(side="left", padx=(0, 5))
        
        copy_pass_btn = tk.Button(password_frame, text="Copy",
                                 command=lambda: self.copy_to_clipboard(entry['password']),
                                 relief="flat", cursor="hand2", bg=self.card_bg, font=("Arial", 10))
        copy_pass_btn.pack(side="left")
        
        # Delete button
        delete_btn = tk.Button(password_frame, text="Delete", command=lambda: self.delete_password(index),
                              relief="flat", cursor="hand2", bg=self.card_bg,
                              fg="#dc2626", font=("Arial", 10, "bold"))
        delete_btn.pack(side="right")
    
    def toggle_password(self, password_var, actual_password, button):
        """Toggle password visibility"""
        if password_var.get() == "********":
            password_var.set(actual_password)
            button.config(text="Hide")
        else:
            password_var.set("********")
            button.config(text="Show")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!")
    
    def filter_passwords(self):
        """Filter passwords based on search term"""
        search_term = self.search_var.get().lower()
        
        if not search_term:
            # Reload all passwords
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            self.passwords = []
            for entry in data.get('passwords', []):
                decrypted = {
                    'site': self.cipher.decrypt(entry['site'].encode()).decode(),
                    'username': self.cipher.decrypt(entry['username'].encode()).decode(),
                    'password': self.cipher.decrypt(entry['password'].encode()).decode(),
                }
                self.passwords.append(decrypted)
        else:
            # Filter current passwords
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            all_passwords = []
            for entry in data.get('passwords', []):
                decrypted = {
                    'site': self.cipher.decrypt(entry['site'].encode()).decode(),
                    'username': self.cipher.decrypt(entry['username'].encode()).decode(),
                    'password': self.cipher.decrypt(entry['password'].encode()).decode(),
                }
                all_passwords.append(decrypted)
            
            self.passwords = [p for p in all_passwords if 
                             search_term in p['site'].lower() or 
                             search_term in p['username'].lower()]
        
        self.display_passwords()
    
    def show_add_dialog(self):
        """Show dialog to add new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("450x350")
        dialog.configure(bg=self.card_bg)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Add New Password", font=("Arial", 18, "bold"),
                bg=self.card_bg, fg=self.text_dark).pack(pady=(20, 30))
        
        # Site
        tk.Label(dialog, text="Website/App name:", font=("Arial", 10),
                bg=self.card_bg, fg=self.text_gray, anchor="w").pack(fill="x", padx=30)
        site_entry = tk.Entry(dialog, font=("Arial", 12), relief="solid", bd=2)
        site_entry.configure(highlightbackground=self.border, highlightcolor=self.primary,
                           highlightthickness=2)
        site_entry.pack(fill="x", padx=30, pady=(5, 15), ipady=6)
        
        # Username
        tk.Label(dialog, text="Username/Email:", font=("Arial", 10),
                bg=self.card_bg, fg=self.text_gray, anchor="w").pack(fill="x", padx=30)
        username_entry = tk.Entry(dialog, font=("Arial", 12), relief="solid", bd=2)
        username_entry.configure(highlightbackground=self.border, highlightcolor=self.primary,
                               highlightthickness=2)
        username_entry.pack(fill="x", padx=30, pady=(5, 15), ipady=6)
        
        # Password
        tk.Label(dialog, text="Password:", font=("Arial", 10),
                bg=self.card_bg, fg=self.text_gray, anchor="w").pack(fill="x", padx=30)
        password_entry = tk.Entry(dialog, font=("Arial", 12), relief="solid", bd=2)
        password_entry.configure(highlightbackground=self.border, highlightcolor=self.primary,
                               highlightthickness=2)
        password_entry.pack(fill="x", padx=30, pady=(5, 20), ipady=6)
        
        def save_entry():
            site = site_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if not site or not username or not password:
                messagebox.showerror("Error", "All fields are required")
                return
            
            self.passwords.append({
                'site': site,
                'username': username,
                'password': password
            })
            self.save_passwords()
            self.display_passwords()
            dialog.destroy()
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=self.card_bg)
        btn_frame.pack(fill="x", padx=30)
        
        save_btn = tk.Button(btn_frame, text="Save", command=save_entry,
                           bg=self.primary, fg="white", font=("Arial", 11, "bold"),
                           relief="flat", cursor="hand2", width=15, height=2)
        save_btn.pack(side="left", expand=True, padx=(0, 5))
        save_btn.bind("<Enter>", lambda e: save_btn.config(bg=self.primary_hover))
        save_btn.bind("<Leave>", lambda e: save_btn.config(bg=self.primary))
        
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                              bg=self.card_bg, fg=self.text_dark, font=("Arial", 11),
                              relief="solid", bd=2, cursor="hand2", width=15, height=2)
        cancel_btn.configure(highlightbackground=self.border, highlightthickness=2)
        cancel_btn.pack(side="left", expand=True, padx=(5, 0))
        
        site_entry.focus()
    
    def delete_password(self, index):
        """Delete a password entry"""
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            self.passwords.pop(index)
            self.save_passwords()
            self.display_passwords()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
