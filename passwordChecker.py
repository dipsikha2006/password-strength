import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
from datetime import datetime

class PasswordStrengthGUI:
    def _init_(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("600x700")
        self.root.configure(bg='#f0f0f0')
        
        self.common_passwords = self.load_common_passwords()
        self.setup_ui()
    
    def load_common_passwords(self):
        """Load a list of common passwords to check against"""
        common_passwords = [
            "password", "123456", "12345678", "1234", "qwerty", "12345", 
            "dragon", "baseball", "football", "letmein", "monkey", "abc123",
            "mustang", "michael", "shadow", "master", "jennifer", "111111",
            "2000", "jordan", "superman", "harley", "1234567", "freedom"
        ]
        return common_passwords
    
    def setup_ui(self):
        # Title
        title_label = tk.Label(self.root, text="Password Strength Analyzer", 
                              font=('Arial', 18, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=10)
        
        # Password entry frame
        entry_frame = tk.Frame(self.root, bg='#f0f0f0')
        entry_frame.pack(pady=10, fill='x', padx=20)
        
        tk.Label(entry_frame, text="Enter Password:", 
                font=('Arial', 12), bg='#f0f0f0').pack(anchor='w')
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(entry_frame, textvariable=self.password_var, 
                                      show="*", font=('Arial', 12), width=40)
        self.password_entry.pack(pady=5, fill='x')
        self.password_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Show password checkbox
        self.show_var = tk.IntVar()
        show_check = tk.Checkbutton(entry_frame, text="Show password", 
                                   variable=self.show_var, command=self.toggle_password_visibility,
                                   bg='#f0f0f0')
        show_check.pack(anchor='w', pady=5)
        
        # Strength meter frame
        meter_frame = tk.Frame(self.root, bg='#f0f0f0')
        meter_frame.pack(pady=10, fill='x', padx=20)
        
        tk.Label(meter_frame, text="Password Strength:", 
                font=('Arial', 12), bg='#f0f0f0').pack(anchor='w')
        
        self.strength_var = tk.StringVar(value="Not assessed")
        strength_label = tk.Label(meter_frame, textvariable=self.strength_var, 
                                 font=('Arial', 14, 'bold'), bg='#f0f0f0')
        strength_label.pack(anchor='w', pady=5)
        
        # Progress bar for strength
        self.progress = ttk.Progressbar(meter_frame, orient='horizontal', 
                                       length=400, mode='determinate')
        self.progress.pack(fill='x', pady=5)
        
        # Details frame
        details_frame = tk.LabelFrame(self.root, text="Password Analysis", 
                                     font=('Arial', 12, 'bold'), bg='#f0f0f0')
        details_frame.pack(pady=10, fill='both', expand=True, padx=20)
        
        # Text area for results
        self.results_text = scrolledtext.ScrolledText(details_frame, height=15, 
                                                     font=('Arial', 10), wrap=tk.WORD)
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.results_text.config(state=tk.DISABLED)
        
        # Buttons frame
        button_frame = tk.Frame(self.root, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Check Strength", command=self.check_strength,
                 font=('Arial', 12), bg='#4CAF50', fg='white', padx=20).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Clear", command=self.clear_all,
                 font=('Arial', 12), bg='#f44336', fg='white', padx=20).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Save Results", command=self.save_results,
                 font=('Arial', 12), bg='#2196F3', fg='white', padx=20).pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, 
                             relief=tk.SUNKEN, anchor=tk.W, bg='#e0e0e0')
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def toggle_password_visibility(self):
        if self.show_var.get() == 1:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def on_password_change(self, event=None):
        # Real-time strength checking as user types
        password = self.password_var.get()
        if password:
            self.check_strength(real_time=True)
    
    def check_strength(self, real_time=False):
        password = self.password_var.get()
        
        if not password:
            if not real_time:
                messagebox.showwarning("Input Error", "Please enter a password to check.")
            return
        
        results = self.analyze_password(password)
        self.display_results(results, real_time)
    
    def analyze_password(self, password):
        """Analyze password and return strength metrics"""
        score = 0
        feedback = []
        checks = {}
        
        # Length check
        checks['length'] = len(password) >= 8
        if len(password) >= 12:
            score += 3
            checks['length_strong'] = True
        elif len(password) >= 8:
            score += 2
            checks['length_strong'] = False
            feedback.append("Consider using at least 12 characters")
        else:
            checks['length_strong'] = False
            feedback.append("Password is too short (min 8 characters)")
        
        # Character variety checks
        checks['uppercase'] = bool(re.search(r'[A-Z]', password))
        checks['lowercase'] = bool(re.search(r'[a-z]', password))
        checks['numbers'] = bool(re.search(r'[0-9]', password))
        checks['special'] = bool(re.search(r'[^A-Za-z0-9]', password))
        
        if checks['uppercase'] and checks['lowercase']:
            score += 2
        else:
            feedback.append("Use both uppercase and lowercase letters")
        
        if checks['numbers']:
            score += 2
        else:
            feedback.append("Include numbers in your password")
        
        if checks['special']:
            score += 2
        else:
            feedback.append("Add special characters (e.g., !@#$%)")
        
        # Common password check
        checks['common'] = password.lower() in self.common_passwords
        if checks['common']:
            score -= 5
            feedback.append("This is a very common password")
        
        # Sequential characters check
        checks['sequential'] = bool(re.search(r'(.)\1{2,}', password) or 
                                  re.search(r'(abc|123|xyz)', password.lower()))
        if checks['sequential']:
            score -= 2
            feedback.append("Avoid sequential or repeated characters")
        
        # Determine strength level
        if score >= 8:
            strength = "Very Strong"
            color = "green"
        elif score >= 6:
            strength = "Strong"
            color = "blue"
        elif score >= 4:
            strength = "Moderate"
            color = "orange"
        elif score >= 2:
            strength = "Weak"
            color = "red"
        else:
            strength = "Very Weak"
            color = "darkred"
        
        # Estimate crack time
        crack_time = self.estimate_crack_time(password)
        
        return {
            'password': password,
            'score': score,
            'strength': strength,
            'color': color,
            'feedback': feedback,
            'checks': checks,
            'crack_time': crack_time,
            'length': len(password)
        }
    
    def estimate_crack_time(self, password):
        """Estimate how long it would take to crack the password"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            charset_size += 32
        
        if charset_size == 0 or len(password) == 0:
            return "instantly"
        
        combinations = charset_size ** len(password)
        seconds = combinations / 1e9  # 1 billion guesses per second
        
        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds/86400)} days"
        elif seconds < 3153600000:
            return f"{int(seconds/31536000)} years"
        else:
            return "centuries"
    
    def display_results(self, results, real_time=False):
        # Update progress bar and strength label
        max_score = 9  # Our maximum score
        progress_value = (results['score'] / max_score) * 100
        self.progress['value'] = progress_value
        
        # Set progress bar color based on strength
        if results['score'] >= 8:
            self.progress.configure(style="Green.Horizontal.TProgressbar")
        elif results['score'] >= 6:
            self.progress.configure(style="Blue.Horizontal.TProgressbar")
        elif results['score'] >= 4:
            self.progress.configure(style="Orange.Horizontal.TProgressbar")
        else:
            self.progress.configure(style="Red.Horizontal.TProgressbar")
        
        self.strength_var.set(f"{results['strength']} ({results['score']}/9)")
        
        if not real_time:
            # Update results text area
            self.results_text.config(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
            
            result_text = f"PASSWORD ANALYSIS RESULTS\n"
            result_text += "=" * 30 + "\n\n"
            result_text += f"Password: {'*' * len(results['password'])}\n"
            result_text += f"Length: {results['length']} characters\n"
            result_text += f"Strength: {results['strength']}\n"
            result_text += f"Score: {results['score']}/9\n"
            result_text += f"Estimated time to crack: {results['crack_time']}\n\n"
            
            result_text += "CHECKS PASSED:\n"
            result_text += f"✓ Length ≥ 8 chars: {'Yes' if results['checks']['length'] else 'No'}\n"
            result_text += f"✓ Upper & lower case: {'Yes' if results['checks']['uppercase'] and results['checks']['lowercase'] else 'No'}\n"
            result_text += f"✓ Contains numbers: {'Yes' if results['checks']['numbers'] else 'No'}\n"
            result_text += f"✓ Contains special chars: {'Yes' if results['checks']['special'] else 'No'}\n"
            result_text += f"✓ Not a common password: {'Yes' if not results['checks']['common'] else 'No'}\n"
            result_text += f"✓ No sequential patterns: {'Yes' if not results['checks']['sequential'] else 'No'}\n\n"
            
            if results['feedback']:
                result_text += "RECOMMENDATIONS:\n"
                for item in results['feedback']:
                    result_text += f"• {item}\n"
            else:
                result_text += "✓ Excellent password! No recommendations needed.\n"
            
            self.results_text.insert(tk.END, result_text)
            self.results_text.config(state=tk.DISABLED)
            
            self.status_var.set("Analysis complete")
    
    def clear_all(self):
        self.password_var.set("")
        self.strength_var.set("Not assessed")
        self.progress['value'] = 0
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.show_var.set(0)
        self.toggle_password_visibility()
        self.status_var.set("Cleared")
    
    def save_results(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Save Error", "No password analyzed to save.")
            return
        
        filename = f"password_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                # Get the current results text
                self.results_text.config(state=tk.NORMAL)
                content = self.results_text.get(1.0, tk.END)
                self.results_text.config(state=tk.DISABLED)
                
                f.write(content)
            
            self.status_var.set(f"Results saved to {filename}")
            messagebox.showinfo("Save Successful", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save file: {e}")

# Create styled progress bars
def configure_styles():
    style = ttk.Style()
    style.configure("Green.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#4CAF50')
    style.configure("Blue.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#2196F3')
    style.configure("Orange.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#FF9800')
    style.configure("Red.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#F44336')

def main():
    root = tk.Tk()
    configure_styles()
    app = PasswordStrengthGUI(root)
    root.mainloop()

if _name_ == "_main_":
    # Uncomment the version you want to run:
    
    # For command line version:
    # main()  # This runs the CLI version
    
    # For GUI version:
    gui_root = tk.Tk()
    configure_styles()
    app = PasswordStrengthGUI(gui_root)
    gui_root.mainloop()