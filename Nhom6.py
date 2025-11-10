import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import hashlib
import random
from Crypto.Util import number
from pathlib import Path

class DSA_Core:
    VALID_LN_PAIRS = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    def generate_params(self, L, N):
        if (L, N) not in self.VALID_LN_PAIRS:
            raise ValueError(f"Cặp (L={L}, N={N}) không hợp lệ.")
        q = number.getPrime(N)
        while True:
            k = number.getRandomNBitInteger(L - N)
            p = k * q + 1
            if p.bit_length() == L and number.isPrime(p):
                break
        while True:
            h = random.randint(2, p - 2)
            g = pow(h, (p - 1) // q, p)
            if g > 1:
                break
        return p, q, g
    def generate_keys(self, p, q, g):
        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        return x, y
    def sign_bytes(self, p, q, g, x, data_bytes):
        H = int(hashlib.sha256(data_bytes).hexdigest(), 16)
        while True:
            k = random.randint(1, q - 1)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            k_inv = pow(k, -1, q)
            s = (k_inv * (H + x * r)) % q
            if s != 0:
                break
        return r, s, H, k
    def verify_bytes(self, p, q, g, y, data_bytes, r, s):
        log = []
        if not (0 < r < q and 0 < s < q):
            log.append("Kiểm tra phạm vi r, s → thất bại")
            return False, 0, 0, 0, 0, log
        H = int(hashlib.sha256(data_bytes).hexdigest(), 16)
        log.append(f"H(file) = {H}")
        try:
            w = pow(s, -1, q)
            log.append(f"w = s⁻¹ mod q = {w}")
        except ValueError:
            log.append("Không thể tính w")
            return False, 0, 0, 0, 0, log
        u1 = (H * w) % q
        u2 = (r * w) % q
        log.append(f"u1 = H·w mod q = {u1}")
        log.append(f"u2 = r·w mod q = {u2}")
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        log.append(f"v = (g^{u1} · y^{u2} mod p) mod q = {v}")
        is_valid = (v == r)
        log.append(f"Kiểm tra v == r → {'HỢP LỆ' if is_valid else 'KHÔNG HỢP LỆ'}")
        return is_valid, w, u1, u2, v, log

class DSA_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Nhóm 6")
        self.root.geometry("1720x900")
        self.root.configure(bg="#f8f9fa")
        self.dsa = DSA_Core()
        self.p = self.q = self.g = self.x = self.y = None
        self.file_path = None
        self.file_bytes = None
        self.verify_file_path = None
        self.verify_file_bytes = None
        self.last_H = self.last_w = self.last_u1 = self.last_u2 = self.last_v = None
        self.last_r = self.last_s = None
        self.setup_style()
        self.build_ui()
    def setup_style(self):
        s = ttk.Style()
        s.theme_use('clam')
        primary = "#f97316"; bg = "#ffffff"; txt = "#1f2937"
        s.configure(".", font=("Segoe UI", 10), background="#f8f9fa", foreground=txt)
        s.configure("TLabelframe", background=bg, foreground=primary, font=("Segoe UI", 11, "bold"))
        s.configure("TLabelframe.Label", background=bg, foreground=primary, font=("Segoe UI", 11, "bold"))
        s.map("Accent.TButton", background=[('active', primary), ('pressed', '#e55a00')], foreground=[('active', 'white')])
        s.configure("Accent.TButton", background=primary, foreground="white", borderwidth=0, padding=(16, 10), font=("Segoe UI", 10, "bold"))
        s.configure("TEntry", fieldbackground="#f1f5f9", insertcolor=primary)
        s.configure("TCombobox", fieldbackground="#f1f5f9", arrowsize=12)
        self.root.option_add("*Text.Background", "#ffffff")
        self.root.option_add("*Text.Foreground", txt)
        s.configure("Treeview", background="#fdfdfd", fieldbackground="#fdfdfd", rowheight=28)
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), foreground=primary)
        s.map("Treeview", background=[("selected", primary)])
    def build_ui(self):
        canvas = tk.Canvas(self.root, bg="#f8f9fa", highlightthickness=0)
        self.canvas = canvas
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True, padx=15, pady=15)
        scrollbar.pack(side="right", fill="y", padx=(0,15), pady=15)
        main = ttk.Frame(scroll_frame, padding="18 15")
        main.pack(fill=tk.BOTH, expand=True)
        row0 = ttk.Frame(main); row0.pack(fill=tk.X, pady=(0, 18))
        self.build_section(row0, "1. Tham số Toàn cục", self.build_params, side=tk.LEFT)
        self.build_section(row0, "2. Cặp Khóa", self.build_keys, side=tk.RIGHT)
        row1 = ttk.Frame(main); row1.pack(fill=tk.X, pady=(0, 18))
        self.build_section(row1, "3. Ký Văn Bản / File", self.build_sign, side=tk.LEFT)
        self.build_section(row1, "4. Xác Minh", self.build_verify, side=tk.RIGHT)
        row2 = ttk.Frame(main); row2.pack(fill=tk.X, pady=(0, 18))
        self.build_section(row2, "5. Console Log", self.build_console, side=tk.LEFT)
        self.build_section(row2, "6. Kết quả Xác minh", self.build_result, side=tk.RIGHT)
        self.build_summary_table(main)
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Button-4>", self._on_wheel)
        self.canvas.bind_all("<Button-5>", self._on_wheel)
    def _on_wheel(self, ev):
        dir = -1 if (ev.num == 4 or ev.delta > 0) else 1
        self.canvas.yview_scroll(dir, "units")
    def build_section(self, parent, title, builder, side):
        frame = ttk.Labelframe(parent, text=title, padding="16 14")
        frame.pack(side=side, fill=tk.BOTH, expand=True, padx=(0,12) if side == tk.LEFT else (12,0))
        builder(frame)
    def build_params(self, parent):
        top = ttk.Frame(parent); top.pack(fill=tk.X, pady=(0,10))
        ttk.Label(top, text="Cặp (L,N):").pack(side=tk.LEFT)
        self.ln_var = tk.StringVar(value="2048, 256")
        opts = [f"{L}, {N}" for L,N in self.dsa.VALID_LN_PAIRS]
        cb = ttk.Combobox(top, textvariable=self.ln_var, values=opts, width=18, state="readonly")
        cb.pack(side=tk.LEFT, padx=6)
        self.btn_params = ttk.Button(top, text="Tạo Tham số", style="Accent.TButton", command=self.generate_params)
        self.btn_params.pack(side=tk.LEFT)
        self.p_txt = self.labeled_field(parent, "p:", 0)
        self.q_txt = self.labeled_field(parent, "q:", 1)
        self.g_txt = self.labeled_field(parent, "g:", 2)
    def build_keys(self, parent):
        self.btn_keys = ttk.Button(parent, text="Tạo Cặp Khóa", style="Accent.TButton", command=self.generate_keys, state="disabled")
        self.btn_keys.pack(pady=(0,12))
        self.x_txt = self.labeled_field(parent, "x (bí mật):", 0)
        self.y_txt = self.labeled_field(parent, "y (công khai):", 1)
    def build_sign(self, parent):
        btn_row = ttk.Frame(parent); btn_row.pack(fill=tk.X, pady=(0,6))
        self.btn_choose = ttk.Button(btn_row, text="Chọn Tệp...", command=self.choose_file)
        self.btn_choose.pack(side=tk.LEFT)
        self.file_label = ttk.Label(btn_row, text="Chưa chọn tệp", anchor="w")
        self.file_label.pack(side=tk.LEFT, padx=8)
        ttk.Label(parent, text="Văn bản (M) hoặc đường dẫn file:").pack(anchor="w", pady=(6,4))
        self.msg_sign = scrolledtext.ScrolledText(parent, height=3, font=("Consolas", 10))
        self.msg_sign.pack(fill=tk.X, pady=(0,8))
        self.msg_sign.insert(tk.END, "Đây là một thông điệp kiểm tra.")
        self.btn_sign = ttk.Button(parent, text="Ký (file hoặc nội dung)", style="Accent.TButton", command=self.sign_message, state="disabled")
        self.btn_sign.pack(pady=(0,12))
        self.H_txt = self.labeled_field(parent, "H:", 0)
        self.k_txt = self.labeled_field(parent, "k:", 1)
        self.r_txt = self.labeled_field(parent, "r:", 2)
        self.s_txt = self.labeled_field(parent, "s:", 3)
    def build_verify(self, parent):
        btn_row = ttk.Frame(parent); btn_row.pack(fill=tk.X, pady=(0,6))
        self.btn_choose_verify = ttk.Button(btn_row, text="Chọn Tệp Xác Minh...", command=self.choose_verify_file)
        self.btn_choose_verify.pack(side=tk.LEFT)
        self.verify_file_label = ttk.Label(btn_row, text="Chưa chọn tệp xác minh", anchor="w")
        self.verify_file_label.pack(side=tk.LEFT, padx=8)
        ttk.Label(parent, text="Văn bản / File để xác minh (M')").pack(anchor="w", pady=(6,4))
        self.msg_verify = scrolledtext.ScrolledText(parent, height=3, font=("Consolas", 10))
        self.msg_verify.pack(fill=tk.X, pady=(0,8))
        grid = ttk.Frame(parent); grid.pack(fill=tk.X, pady=(0,8))
        ttk.Label(grid, text="r':", width=6).grid(row=0, column=0, sticky="w", padx=(0,5))
        self.r_entry = ttk.Entry(grid, font=("Consolas", 10)); self.r_entry.grid(row=0, column=1, sticky="ew")
        grid.columnconfigure(1, weight=1)
        ttk.Label(grid, text="s':", width=6).grid(row=1, column=0, sticky="w", padx=(0,5), pady=(6,0))
        self.s_entry = ttk.Entry(grid, font=("Consolas", 10)); self.s_entry.grid(row=1, column=1, sticky="ew", pady=(6,0))
        self.btn_verify = ttk.Button(parent, text="Xác Minh (dùng file đã chọn nếu có)", style="Accent.TButton", command=self.verify_signature, state="disabled")
        self.btn_verify.pack(pady=(6,12))
        self.w_txt = self.labeled_field(parent, "w:", 0)
        self.u1_txt = self.labeled_field(parent, "u1:", 1)
        self.u2_txt = self.labeled_field(parent, "u2:", 2)
        self.v_txt = self.labeled_field(parent, "v:", 3)
    def build_console(self, parent):
        self.console = scrolledtext.ScrolledText(parent, height=12, font=("Consolas", 9), bg="#1e1e1e", fg="#00FF00", insertbackground="#00FF00")
        self.console.pack(fill=tk.BOTH, expand=True); self.console.configure(state="disabled")
    def build_result(self, parent):
        self.result_label = ttk.Label(parent, text="CHƯA XÁC MINH", font=("Segoe UI", 16, "bold"), foreground="#6b7280", anchor="center")
        self.result_label.pack(fill=tk.BOTH, expand=True, pady=20)
    def build_summary_table(self, parent):
        frame = ttk.Labelframe(parent, text="7. Các Giá Trị", padding="12 10")
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        columns = ("var", "desc", "value")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        self.tree.heading("var", text="Biến"); self.tree.heading("desc", text="Mô Tả"); self.tree.heading("value", text="Giá Trị")
        self.tree.column("var", width=80, anchor="center"); self.tree.column("desc", width=420, anchor="w"); self.tree.column("value", width=180, anchor="center")
        self.tree_data = [
            ("", "Tham Số Hệ Thống", ""),
            ("p", "Số nguyên tố modulo", "—"),
            ("q", "Ước số nguyên tố của (p−1)", "—"),
            ("g", "Phần tử sinh", "—"),
            ("", "Cặp Khóa", ""),
            ("x", "Khóa bí mật (riêng tư)", "—"),
            ("y", "Khóa công khai (y = g^x mod p)", "—"),
            ("", "Thành Phần Chữ Ký", ""),
            ("r'", "Thành phần chữ ký r  = (g^k mod p) mod q", "—"),
            ("s'", "Thành phần chữ ký s = (k^-1 * (H + x*r)) mod q", "—"),
            ("", "Quá Trình Xác Minh", ""),
            ("H", "Giá trị băm (SHA-256 trên bytes)", "—"),
            ("w", "w = s^-1 mod q", "—"),
            ("u1", "u1 = H * w mod q", "—"),
            ("u2", "u2 = r' * w mod q", "—"),
            ("v", "v = (g^u1 * y^u2 mod p) mod q", "—"),
            ("", "Kết Quả Xác Minh", ""),
            ("Kết quả xác minh", "v ≡ r' (mod q)", "—"),
        ]
        for var, desc, val in self.tree_data:
            if var == "": self.tree.insert("", "end", values=(var, desc, val), tags=("header",))
            else: self.tree.insert("", "end", values=(var, desc, val))
        self.tree.tag_configure("header", background="#f3f4f6", font=("Segoe UI", 10, "bold"))
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set); self.tree.pack(side="left", fill=tk.BOTH, expand=True); vsb.pack(side="right", fill="y")
    def labeled_field(self, parent, label, row):
        f = ttk.Frame(parent); f.pack(fill=tk.X, pady=3)
        ttk.Label(f, text=label, width=26, anchor="w", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        txt = scrolledtext.ScrolledText(f, height=2, font=("Consolas", 9), relief="flat", bg="#f8f9fa")
        txt.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8,0)); txt.configure(state="disabled")
        return txt
    def _update(self, widget, value):
        widget.configure(state="normal"); widget.delete("1.0", tk.END); widget.insert(tk.END, str(value)); widget.configure(state="disabled")
    def _log(self, text):
        self.console.configure(state="normal"); self.console.insert(tk.END, text + "\n"); self.console.see(tk.END); self.console.configure(state="disabled")
    def _clear_log(self):
        self.console.configure(state="normal"); self.console.delete("1.0", tk.END); self.console.configure(state="disabled")
    def update_summary_table(self):
        values = {
            "p": self.p, "q": self.q, "g": self.g, "x": self.x, "y": self.y,
            "r'": self.last_r, "s'": self.last_s, "H": self.last_H,
            "w": self.last_w, "u1": self.last_u1, "u2": self.last_u2, "v": self.last_v,
            "Kết quả xác minh": "HỢP LỆ" if self.result_label["text"] == "HỢP LỆ" else "KHÔNG HỢP LỆ" if self.result_label["text"] == "KHÔNG HỢP LỆ" else "—"
        }
        for i, (var, _, _) in enumerate(self.tree_data):
            if var in values:
                self.tree.item(self.tree.get_children()[i], values=(var, self.tree_data[i][1], values[var]))
    def choose_file(self):
        path = filedialog.askopenfilename(title="Chọn tệp", filetypes=[("All files","*.*")])
        if not path:
            return
        self.file_path = Path(path)
        try:
            with open(self.file_path, "rb") as f:
                self.file_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể mở file: {e}")
            self.file_path = None
            self.file_bytes = None
            self.file_label.config(text="Chưa chọn tệp")
            return
        self.file_label.config(text=str(self.file_path.name))
        self.msg_sign.delete("1.0", tk.END)
        self.msg_sign.insert(tk.END, f"[FILE] {self.file_path.name}")
        if self.x is not None:
            self.btn_sign.config(state="normal")
        self._log(f"Đã chọn file: {self.file_path}")
    def choose_verify_file(self):
        path = filedialog.askopenfilename(title="Chọn tệp xác minh", filetypes=[("All files","*.*")])
        if not path:
            return
        self.verify_file_path = Path(path)
        try:
            with open(self.verify_file_path, "rb") as f:
                self.verify_file_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể mở file xác minh: {e}")
            self.verify_file_path = None
            self.verify_file_bytes = None
            self.verify_file_label.config(text="Chưa chọn tệp xác minh")
            return
        self.verify_file_label.config(text=str(self.verify_file_path.name))
        self.msg_verify.delete("1.0", tk.END)
        self.msg_verify.insert(tk.END, f"[VERIFY FILE] {self.verify_file_path.name}")
        if self.y is not None:
            self.btn_verify.config(state="normal")
        self._log(f"Đã chọn file xác minh: {self.verify_file_path}")
    def generate_params(self):
        try:
            L, N = map(int, self.ln_var.get().split(", "))
            self.result_label.config(text="Đang tạo...", foreground="#f59e0b")
            self.root.update_idletasks()
            self.p, self.q, self.g = self.dsa.generate_params(L, N)
            self._update(self.p_txt, self.p); self._update(self.q_txt, self.q); self._update(self.g_txt, self.g)
            self.result_label.config(text="Tham số OK", foreground="#10b981")
            self.btn_keys.config(state="normal"); self.update_summary_table()
        except Exception as e:
            messagebox.showerror("Lỗi", str(e)); self.result_label.config(text="Lỗi", foreground="#ef4444")
    def generate_keys(self):
        if not self.p: return messagebox.showwarning("Cảnh báo", "Tạo tham số trước.")
        self.x, self.y = self.dsa.generate_keys(self.p, self.q, self.g)
        self._update(self.x_txt, self.x); self._update(self.y_txt, self.y)
        self.btn_sign.config(state="normal"); self.btn_verify.config(state="normal"); self.update_summary_table()
    def sign_message(self):
        if not self.x: return messagebox.showwarning("Cảnh báo", "Tạo khóa trước.")
        if self.file_bytes is not None:
            data = self.file_bytes
            source = f"FILE: {self.file_path.name}"
        else:
            txt = self.msg_sign.get("1.0", tk.END).strip()
            if not txt:
                return messagebox.showwarning("Cảnh báo", "Văn bản rỗng.")
            data = txt.encode()
            source = ""
        r, s, H, k = self.dsa.sign_bytes(self.p, self.q, self.g, self.x, data)
        self._update(self.H_txt, H); self._update(self.k_txt, k); self._update(self.r_txt, r); self._update(self.s_txt, s)
        self.last_r, self.last_s = r, s
        self.msg_verify.delete("1.0", tk.END); self.msg_verify.insert(tk.END, f"{source}")
        self.r_entry.delete(0, tk.END); self.r_entry.insert(0, str(r))
        self.s_entry.delete(0, tk.END); self.s_entry.insert(0, str(s))
        self.btn_verify.config(state="normal")
        self.result_label.config(text="ĐÃ KÝ", foreground="#f59e0b")
        self._log(f"Đã ký {source} → r={r} s={s}")
    def verify_signature(self):
        if not self.y: return messagebox.showwarning("Cảnh báo", "Cần khóa + chữ ký.")
        try:
            r = int(self.r_entry.get()); s = int(self.s_entry.get())
        except ValueError:
            return messagebox.showerror("Lỗi", "r', s' phải là số nguyên.")
        if self.verify_file_bytes is not None:
            data = self.verify_file_bytes
            source = f"VERIFY FILE: {self.verify_file_path.name}"
        elif self.file_bytes is not None and self.msg_verify.get("1.0", tk.END).strip().startswith("[SAME SOURCE]"):
            data = self.file_bytes
            source = f"FILE: {self.file_path.name}"
        else:
            txt = self.msg_verify.get("1.0", tk.END).strip()
            if not txt:
                return messagebox.showwarning("Cảnh báo", "Vui lòng nhập nội dung hoặc chọn file để xác minh.")
            data = txt.encode()
            source = ""
        self._clear_log(); self._log("BẮT ĐẦU XÁC MINH".center(50, "="))
        is_valid, w, u1, u2, v, log_lines = self.dsa.verify_bytes(self.p, self.q, self.g, self.y, data, r, s)
        self._update(self.w_txt, w); self._update(self.u1_txt, u1); self._update(self.u2_txt, u2); self._update(self.v_txt, v)
        self.last_H, self.last_w, self.last_u1, self.last_u2, self.last_v = (int(hashlib.sha256(data).hexdigest(), 16), w, u1, u2, v)
        for line in log_lines: self._log(line)
        if is_valid:
            self.result_label.config(text="HỢP LỆ", foreground="#10b981", font=("Segoe UI", 16, "bold"))
        else:
            self.result_label.config(text="KHÔNG HỢP LỆ", foreground="#ef4444", font=("Segoe UI", 16, "bold"))
        title = "Kết quả Xác minh"; status = "HỢP LỆ" if is_valid else "KHÔNG HỢP LỆ"
        msg_popup = f"KẾT QUẢ: {status}\n\nNguồn: {source}\nr' = {r}\nv = {v}\n\nChi tiết xem trong Console."
        if is_valid: messagebox.showinfo(title, msg_popup)
        else: messagebox.showwarning(title, msg_popup)
        self._log("KẾT THÚC XÁC MINH".center(50, "=")); self.update_summary_table()

if __name__ == "__main__":
    root = tk.Tk()
    app = DSA_GUI(root)
    root.mainloop()
