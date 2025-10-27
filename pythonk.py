import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import random
from Crypto.Util import number

class DSA_Core:
    """
    Lớp triển khai logic toán học cốt lõi của Thuật toán Chữ ký số (DSA).
    Hiển thị các giá trị trung gian để minh họa quy trình.
    """
    # Valid (L, N) pairs according to FIPS 186-4
    VALID_LN_PAIRS = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    def generate_params(self, L, N):
        """Tạo các tham số miền DSA (p, q, g)."""
        if (L, N) not in self.VALID_LN_PAIRS:
            raise ValueError(f"Cặp (L={L}, N={N}) không hợp lệ. Các cặp hợp lệ: {self.VALID_LN_PAIRS}")
        
        # Generate q (N-bit prime)
        q = number.getPrime(N)
        
        # Generate p (L-bit prime such that (p-1) is divisible by q)
        while True:
            k = number.getRandomNBitInteger(L - N)
            p = k * q + 1
            if p.bit_length() == L and number.isPrime(p):
                break
        
        # Generate g
        while True:
            h = random.randint(2, p - 2)
            exponent = (p - 1) // q
            g = pow(h, exponent, p)
            if g > 1:
                break
        
        return p, q, g

    def generate_keys(self, p, q, g):
        """Tạo cặp khóa bí mật/công khai (x, y)."""
        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        return x, y

    def sign_message(self, p, q, g, x, message):
        """Ký một thông điệp và trả về chữ ký cùng các giá trị trung gian."""
        h_obj = hashlib.sha256()
        h_obj.update(message.encode('utf-8'))
        H = int(h_obj.hexdigest(), 16)

        while True:
            k = random.randint(1, q - 1)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            try:
                k_inv = pow(k, -1, q)
                s = (k_inv * (H + x * r)) % q
                if s != 0:
                    break
            except ValueError:
                continue

        return r, s, H, k

    def verify_signature(self, p, q, g, y, message, r, s):
        """Xác minh chữ ký và trả về kết quả cùng các giá trị trung gian."""
        if not (0 < r < q and 0 < s < q):
            return False, 0, 0, 0, 0

        h_obj = hashlib.sha256()
        h_obj.update(message.encode('utf-8'))
        H = int(h_obj.hexdigest(), 16)

        try:
            w = pow(s, -1, q)
        except ValueError:
            return False, 0, 0, 0, 0

        u1 = (H * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        is_valid = (v == r)
        
        return is_valid, w, u1, u2, v

class DSA_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Minh họa Thuật toán Chữ ký số (DSA)")
        self.dsa_core = DSA_Core()
        
        # Configure style
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("TLabel", padding=5)
        style.configure("TEntry", padding=5)

        self.p = None
        self.q = None
        self.g = None
        self.x = None
        self.y = None
        self.create_widgets()

    def create_widgets(self):
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        # Configure canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Main frame inside scrollable frame
        main_frame = ttk.Frame(self.scrollable_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # --- Parameter Section ---
        params_frame = ttk.LabelFrame(main_frame, text="1. Tham số Toàn cục", padding="10")
        params_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(params_frame, text="Cặp (L, N):").grid(row=0, column=0, sticky=tk.W)
        self.ln_var = tk.StringVar(value="2048, 256")
        ln_options = [f"{L}, {N}" for L, N in self.dsa_core.VALID_LN_PAIRS]
        self.ln_combo = ttk.Combobox(params_frame, textvariable=self.ln_var, values=ln_options, width=15, state="readonly")
        self.ln_combo.grid(row=0, column=1, sticky=tk.W)

        self.params_button = ttk.Button(params_frame, text="Tạo Tham số", command=self.generate_params)
        self.params_button.grid(row=0, column=2, padx=20)

        self.p_text = self.create_display_field(params_frame, "p:", 1)
        self.q_text = self.create_display_field(params_frame, "q:", 2)
        self.g_text = self.create_display_field(params_frame, "g:", 3)

        # --- Key Section ---
        keys_frame = ttk.LabelFrame(main_frame, text="2. Cặp khóa", padding="10")
        keys_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.keys_button = ttk.Button(keys_frame, text="Tạo Cặp Khóa", command=self.generate_keys, state="disabled")
        self.keys_button.grid(row=0, column=0, columnspan=2, pady=5)
        self.x_text = self.create_display_field(keys_frame, "Khóa Bí mật (x):", 1)
        self.y_text = self.create_display_field(keys_frame, "Khóa Công khai (y):", 2)

        # --- Signing Section ---
        sign_frame = ttk.LabelFrame(main_frame, text="3. Ký văn bản", padding="10")
        sign_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        ttk.Label(sign_frame, text="Văn bản gốc (M):").grid(row=0, column=0, columnspan=2, sticky=tk.W)
        self.msg_sign_text = scrolledtext.ScrolledText(sign_frame, height=4, width=50)
        self.msg_sign_text.grid(row=1, column=0, columnspan=2, pady=5)
        self.msg_sign_text.insert(tk.END, "Đây là một thông điệp kiểm tra.")

        self.sign_button = ttk.Button(sign_frame, text="Ký văn bản", command=self.sign_message, state="disabled")
        self.sign_button.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.H_text = self.create_display_field(sign_frame, "H(M):", 3)
        self.k_text = self.create_display_field(sign_frame, "k (nonce):", 4)
        self.r_text = self.create_display_field(sign_frame, "r:", 5)
        self.s_text = self.create_display_field(sign_frame, "s:", 6)

        # --- Verification Section ---
        verify_frame = ttk.LabelFrame(main_frame, text="4. Xác minh Chữ ký", padding="10")
        verify_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(verify_frame, text="Văn bản cần xác minh (M'):").grid(row=0, column=0, columnspan=2, sticky=tk.W)
        self.msg_verify_text = scrolledtext.ScrolledText(verify_frame, height=4, width=80)
        self.msg_verify_text.grid(row=1, column=0, columnspan=2, pady=5)

        ttk.Label(verify_frame, text="r':").grid(row=2, column=0, sticky=tk.W)
        self.r_verify_entry = ttk.Entry(verify_frame, width=80)
        self.r_verify_entry.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        ttk.Label(verify_frame, text="s':").grid(row=4, column=0, sticky=tk.W)
        self.s_verify_entry = ttk.Entry(verify_frame, width=80)
        self.s_verify_entry.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.verify_button = ttk.Button(verify_frame, text="Xác minh Chữ ký", command=self.verify_signature, state="disabled")
        self.verify_button.grid(row=6, column=0, pady=10)
        
        self.status_label = ttk.Label(verify_frame, text="Trạng thái: CHƯA XÁC MINH", font=("Helvetica", 12, "bold"))
        self.status_label.grid(row=6, column=1, sticky=tk.W, padx=20)

        self.w_text = self.create_display_field(verify_frame, "w:", 7)
        self.u1_text = self.create_display_field(verify_frame, "u1:", 8)
        self.u2_text = self.create_display_field(verify_frame, "u2:", 9)
        self.v_text = self.create_display_field(verify_frame, "v:", 10)

        # Enable mouse wheel scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)  # Windows
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)  # Linux
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)  # Linux

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        if event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")

    def create_display_field(self, parent, label_text, row):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky=tk.W, pady=2)
        text_widget = scrolledtext.ScrolledText(parent, height=2, width=80, wrap=tk.WORD)
        text_widget.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=2)
        text_widget.configure(state='disabled')
        return text_widget

    def update_text_field(self, widget, content):
        widget.configure(state='normal')
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, str(content))
        widget.configure(state='disabled')

    def generate_params(self):
        try:
            L, N = map(int, self.ln_var.get().split(", "))
            self.status_label.config(text="Trạng thái: Đang tạo tham số...", foreground="blue")
            self.root.update()
            self.p, self.q, self.g = self.dsa_core.generate_params(L, N)
            self.update_text_field(self.p_text, self.p)
            self.update_text_field(self.q_text, self.q)
            self.update_text_field(self.g_text, self.g)
            self.status_label.config(text="Trạng thái: Đã tạo tham số", foreground="black")
            self.keys_button.config(state="normal")
        except Exception as e:
            self.status_label.config(text="Trạng thái: Lỗi", foreground="red")
            messagebox.showerror("Lỗi", f"Không thể tạo tham số: {e}")

    def generate_keys(self):
        if not hasattr(self, 'p') or self.p is None:
            messagebox.showwarning("Cảnh báo", "Vui lòng tạo tham số trước.")
            return
        try:
            self.x, self.y = self.dsa_core.generate_keys(self.p, self.q, self.g)
            self.update_text_field(self.x_text, self.x)
            self.update_text_field(self.y_text, self.y)
            self.sign_button.config(state="normal")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo khóa: {e}")

    def sign_message(self):
        if not hasattr(self, 'x') or self.x is None:
            messagebox.showwarning("Cảnh báo", "Vui lòng tạo cặp khóa trước.")
            return
        
        message = self.msg_sign_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Cảnh báo", "Văn bản không được để trống.")
            return

        try:
            r, s, H, k = self.dsa_core.sign_message(self.p, self.q, self.g, self.x, message)
            self.update_text_field(self.H_text, H)
            self.update_text_field(self.k_text, k)
            self.update_text_field(self.r_text, r)
            self.update_text_field(self.s_text, s)

            self.msg_verify_text.delete('1.0', tk.END)
            self.msg_verify_text.insert(tk.END, message)
            self.r_verify_entry.delete(0, tk.END)
            self.r_verify_entry.insert(0, str(r))
            self.s_verify_entry.delete(0, tk.END)
            self.s_verify_entry.insert(0, str(s))
            self.verify_button.config(state="normal")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể ký văn bản: {e}")

    def verify_signature(self):
        if not hasattr(self, 'y') or self.y is None:
            messagebox.showwarning("Cảnh báo", "Vui lòng tạo cặp khóa và ký trước.")
            return

        message = self.msg_verify_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Cảnh báo", "Văn bản xác minh không được để trống.")
            return

        try:
            r = int(self.r_verify_entry.get())
            s = int(self.s_verify_entry.get())
        except ValueError:
            messagebox.showerror("Lỗi", "r' và s' phải là các số nguyên.")
            return

        try:
            is_valid, w, u1, u2, v = self.dsa_core.verify_signature(self.p, self.q, self.g, self.y, message, r, s)
            self.update_text_field(self.w_text, w)
            self.update_text_field(self.u1_text, u1)
            self.update_text_field(self.u2_text, u2)
            self.update_text_field(self.v_text, v)

            if is_valid:
                self.status_label.config(text="Trạng thái: Chữ ký HỢP LỆ (v=r')", foreground="green")
            else:
                self.status_label.config(text="Trạng thái: Chữ ký KHÔNG HỢP LỆ (v!=r')", foreground="red")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể xác minh chữ ký: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("900x700")  # Set initial window size
    app = DSA_GUI(root)
    root.mainloop()
