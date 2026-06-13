import socket
import threading
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
import io
import os
import datetime
import logging

from cryptography.fernet import Fernet

import crypto
import storage
import network
from network import (
    TAG_HISTORY_TEXT, TAG_HISTORY_IMAGE, TAG_IMAGE,
    TAG_TYPING, TAG_USERS, TAG_AUTH_OK, TAG_AUTH_FAIL,
    send_encrypted, recv_encrypted, recv_encrypted_bytes,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

FOREST_DEEP  = "#0D530E"
FOREST_MID   = "#306D29"
PARCHMENT    = "#FBF5DD"
WHEAT        = "#E7E1B1"
WHITE        = "#FFFFFF"
TEXT_DARK    = "#1a2e1a"
TEXT_MID     = "#3d5c3d"
TEXT_LIGHT   = "#7a9a7a"

STATUS_OK     = FOREST_MID
STATUS_WARN   = "#8a6a10"
STATUS_ERROR  = "#8B1A1A"

TEAL  = FOREST_MID
ROSE  = FOREST_DEEP
MINT  = WHEAT
SAND  = "#c8c49a"
BLUSH = PARCHMENT
CREAM = PARCHMENT

# emoji
EMOJI_MAP = {
    ":)":     "😊",
    ":D":     "😄",
    ":(":     "😢",
    "<3":     "❤️",
    ":fire:": "🔥",
    ":star:": "⭐",
    ":ok:":   "👍",
    ":wave:": "👋",
    ":eyes:": "👀",
    ":100:":  "💯",
}

EMOJI_PALETTE = [
    "😊","😄","😂","😢","😡","😍","🤔","😎",
    "👍","👎","👋","🙏","🤝","💪","🎉","🔥",
    "❤️","⭐","💯","✅","❌","🚀","🌿","💬",
]

my_username    = ""
cipher: Fernet | None = None
client_sock: socket.socket | None = None
online_users: list[str] = []
_typing_after_id = None
_connected       = False

_dm_history: dict[str, list] = {}
_dm_windows: dict[str, tk.Toplevel] = {}   # open DM panels


# Key exchange

def do_key_exchange(sock: socket.socket) -> Fernet:
    pem = crypto.recv_frame(sock)
    server_pub = crypto.load_public_key(pem)
    fernet_key, ciphertext = crypto.generate_and_encrypt_session_key(server_pub)
    from crypto import frame
    sock.sendall(frame(ciphertext))
    return Fernet(fernet_key)

# Auth window

def show_auth_window(sock: socket.socket, session_cipher: Fernet) -> str:
    result = {"username": ""}

    auth_win = tk.Tk()
    auth_win.title("Lazy Chat — Sign In")
    auth_win.geometry("380x460")
    auth_win.configure(bg=PARCHMENT)
    auth_win.resizable(False, False)

    header = tk.Frame(auth_win, bg=FOREST_DEEP, height=90)
    header.pack(fill=tk.X)
    header.pack_propagate(False)
    tk.Label(header, text="💬 lazy chat", font=("Helvetica", 22, "bold"),
             bg=FOREST_DEEP, fg=WHITE).pack(expand=True)

    banner_var = tk.StringVar(value="")
    banner = tk.Label(auth_win, textvariable=banner_var,
                      font=("Helvetica", 9), bg=PARCHMENT, fg=STATUS_ERROR,
                      anchor="center", pady=4)
    banner.pack(fill=tk.X, padx=0)

    def set_banner(msg: str, color: str = STATUS_ERROR):
        banner_var.set(msg)
        banner.config(fg=color)

    form = tk.Frame(auth_win, bg=PARCHMENT, padx=40)
    form.pack(fill=tk.BOTH, expand=True, pady=8)

    def make_field(parent, label_text, hide=False):
        tk.Label(parent, text=label_text, font=("Helvetica", 10),
                 bg=PARCHMENT, fg=TEXT_MID, anchor="w").pack(fill=tk.X, pady=(10, 2))
        border = tk.Frame(parent, bg=SAND)
        border.pack(fill=tk.X, ipady=1)
        inner = tk.Frame(border, bg=WHITE)
        inner.pack(fill=tk.X, padx=1, pady=1)
        entry = tk.Entry(inner, font=("Helvetica", 11), bg=WHITE, fg=TEXT_DARK,
                         bd=0, insertbackground=FOREST_MID,
                         show="•" if hide else "")
        entry.pack(fill=tk.X, ipady=7, padx=8)
        return entry

    user_entry = make_field(form, "Username")
    pass_entry = make_field(form, "Password", hide=True)

    def submit_auth(action: str):
        uname = user_entry.get().strip()
        pword = pass_entry.get()
        if not uname or not pword:
            set_banner("All fields are required.")
            return
        if ":" in uname or ":" in pword:
            set_banner("Colons (:) are not allowed.")
            return
        set_banner("Connecting…", STATUS_WARN)
        auth_win.update_idletasks()
        try:
            send_encrypted(sock, session_cipher, f"{action}:{uname}:{pword}")
            response = recv_encrypted(sock, session_cipher)
            if response == TAG_AUTH_OK:
                result["username"] = uname
                auth_win.destroy()
            elif response.startswith(TAG_AUTH_FAIL):
                set_banner(response[len(TAG_AUTH_FAIL):])
        except (ConnectionError, OSError):
            set_banner("Could not reach server. Please try again.")
        except Exception as e:
            logger.exception("Auth error: %s", e)
            set_banner("An unexpected error occurred.")

    btn_frame = tk.Frame(form, bg=PARCHMENT)
    btn_frame.pack(fill=tk.X, pady=20)

    for text, color, hover, action, side in [
        ("Sign In",  FOREST_DEEP, "#0a3d0b", "LOGIN",    tk.LEFT),
        ("Register", FOREST_MID,  "#245220", "REGISTER", tk.RIGHT),
    ]:
        tk.Button(btn_frame, text=text, font=("Helvetica", 10, "bold"),
                  bg=color, fg=WHITE, activebackground=hover, activeforeground=WHITE,
                  bd=0, cursor="hand2", relief=tk.FLAT,
                  command=lambda a=action: submit_auth(a)
                  ).pack(side=side, fill=tk.X, expand=True, ipady=10,
                         padx=(0, 5) if side == tk.LEFT else (5, 0))

    user_entry.bind("<Return>", lambda e: submit_auth("LOGIN"))
    pass_entry.bind("<Return>", lambda e: submit_auth("LOGIN"))
    auth_win.mainloop()
    return result["username"]

# Connect + handshake

def _try_connect():

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((network.HOST, network.PORT))
        s.settimeout(None)
        c = do_key_exchange(s)
        return s, c
    except (OSError, Exception) as e:
        logger.warning("Connection attempt failed: %s", e)
        return None, None

_splash = tk.Tk()
_splash.withdraw()

client_sock, cipher = _try_connect()

if client_sock is None:

    err_win = tk.Tk()
    err_win.title("Lazy Chat")
    err_win.geometry("360x200")
    err_win.configure(bg=PARCHMENT)
    err_win.resizable(False, False)
    tk.Frame(err_win, bg=FOREST_DEEP, height=60).pack(fill=tk.X)
    tk.Label(err_win, text="💬 lazy chat", font=("Helvetica", 16, "bold"),
             bg=PARCHMENT, fg=FOREST_DEEP).pack(pady=(16, 4))
    tk.Label(err_win, text="Could not connect to the server.\nPlease check the server is running and try again.",
             font=("Helvetica", 10), bg=PARCHMENT, fg=STATUS_ERROR,
             justify="center").pack(pady=8)
    tk.Button(err_win, text="Quit", bg=FOREST_DEEP, fg=WHITE,
              activebackground=FOREST_MID, activeforeground=WHITE,
              bd=0, relief=tk.FLAT, cursor="hand2",
              font=("Helvetica", 10, "bold"),
              command=err_win.destroy).pack(ipadx=20, ipady=8)
    err_win.mainloop()
    raise SystemExit(1)

_splash.destroy()

my_username = show_auth_window(client_sock, cipher)
if not my_username:
    raise SystemExit(0)

# Main window

root = tk.Tk()
root.title("lazy chat")
root.geometry("920x620")
root.configure(bg=PARCHMENT)
root.minsize(700, 480)

header_bar = tk.Frame(root, bg=FOREST_DEEP, height=54)
header_bar.pack(fill=tk.X, side=tk.TOP)
header_bar.pack_propagate(False)
tk.Label(header_bar, text="💬 lazy chat", font=("Helvetica", 16, "bold"),
         bg=FOREST_DEEP, fg=WHITE).pack(side=tk.LEFT, padx=20)
tk.Label(header_bar, text=f"● {my_username}", font=("Helvetica", 10),
         bg=FOREST_DEEP, fg=WHEAT).pack(side=tk.RIGHT, padx=20)

_conn_var = tk.StringVar(value="")
_conn_banner = tk.Label(root, textvariable=_conn_var,
                        font=("Helvetica", 9, "italic"),
                        bg=STATUS_OK, fg=WHITE,
                        anchor="center", pady=3)

def _show_conn_banner(msg: str, color: str):
    _conn_var.set(msg)
    _conn_banner.config(bg=color)
    _conn_banner.pack(fill=tk.X, side=tk.TOP, before=root.pack_slaves()[1]
                      if len(root.pack_slaves()) > 1 else None)

def _hide_conn_banner():
    _conn_var.set("")
    _conn_banner.pack_forget()

_connected = True

body = tk.Frame(root, bg=PARCHMENT)
body.pack(fill=tk.BOTH, expand=True)

sidebar = tk.Frame(body, bg=WHEAT, width=170)
sidebar.pack(side=tk.RIGHT, fill=tk.Y)
sidebar.pack_propagate(False)
tk.Label(sidebar, text="Online", font=("Helvetica", 10, "bold"),
         bg=WHEAT, fg=FOREST_DEEP, pady=12).pack(fill=tk.X, padx=14)
tk.Frame(sidebar, bg=SAND, height=1).pack(fill=tk.X, padx=10)
users_list = tk.Listbox(sidebar, bg=WHEAT, fg=TEXT_DARK, font=("Helvetica", 10),
                        bd=0, highlightthickness=0, selectbackground=WHEAT,
                        selectforeground=FOREST_DEEP, activestyle="none", relief=tk.FLAT)
users_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)


def refresh_users_list():
    users_list.delete(0, tk.END)
    for u in online_users:
        prefix = "● " if u == my_username else "○ "
        users_list.insert(tk.END, f"  {prefix}{u}")


chat_outer = tk.Frame(body, bg=PARCHMENT)
chat_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

chat_frame = tk.Frame(chat_outer, bg=PARCHMENT)
chat_frame.pack(fill=tk.BOTH, expand=True, padx=(16, 0), pady=(12, 0))

chat_area = tk.Text(chat_frame, wrap=tk.WORD, state=tk.DISABLED,
                    bg=PARCHMENT, fg=TEXT_DARK, font=("Helvetica", 10),
                    bd=0, padx=16, pady=14, spacing3=4,
                    relief=tk.FLAT, highlightthickness=0)
chat_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(chat_frame, command=chat_area.yview,
                         bg=SAND, troughcolor=PARCHMENT, bd=0, width=8)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_area.config(yscrollcommand=scrollbar.set)

chat_area.tag_config("join",      foreground=FOREST_MID, font=("Helvetica", 9, "italic"))
chat_area.tag_config("leave",     foreground="#8B3A3A", font=("Helvetica", 9, "italic"))
chat_area.tag_config("typing",    foreground=TEXT_LIGHT, font=("Helvetica", 9, "italic"))
chat_area.tag_config("timestamp", foreground=TEXT_LIGHT, font=("Helvetica", 9))
chat_area.tag_config("username",  foreground=FOREST_DEEP, font=("Helvetica", 10, "bold"))
chat_area.tag_config("private",   foreground="#7a5c20", font=("Helvetica", 10, "italic"))
chat_area.tag_config("divider",   foreground=SAND, font=("Helvetica", 8))
chat_area.tag_config("emoji",     font=("Segoe UI Emoji", 11))
chat_area.tag_config("disconn",   foreground=STATUS_ERROR, font=("Helvetica", 9, "italic"))

chat_area.config(state=tk.NORMAL)
chat_area.delete("1.0", tk.END)
chat_area.config(state=tk.DISABLED)

typing_var = tk.StringVar(value="")
typing_label = tk.Label(chat_outer, textvariable=typing_var, bg=PARCHMENT,
                        fg=TEXT_LIGHT, font=("Helvetica", 9, "italic"),
                        anchor="w", padx=16)
typing_label.pack(fill=tk.X)

# Input bar
input_outer = tk.Frame(chat_outer, bg=PARCHMENT, pady=12)
input_outer.pack(fill=tk.X, padx=16)

_emoji_picker_open = False

def _toggle_emoji_picker():
    global _emoji_picker_open
    if _emoji_picker_open:
        return
    _emoji_picker_open = True
    picker = tk.Toplevel(root)
    picker.title("")
    picker.configure(bg=WHEAT)
    picker.resizable(False, False)
    picker.attributes("-topmost", True)

    btn_x = emoji_btn.winfo_rootx()
    btn_y = emoji_btn.winfo_rooty()
    picker.geometry(f"+{btn_x}+{btn_y - 160}")

    cols = 8
    for idx, em in enumerate(EMOJI_PALETTE):
        r, c = divmod(idx, cols)
        b = tk.Button(picker, text=em, font=("Segoe UI Emoji", 13),
                      bg=WHEAT, activebackground=PARCHMENT,
                      bd=0, relief=tk.FLAT, cursor="hand2", width=2,
                      command=lambda e=em: _insert_emoji(e, picker))
        b.grid(row=r, column=c, padx=2, pady=2)

    def _on_close():
        global _emoji_picker_open
        _emoji_picker_open = False
        picker.destroy()

    picker.protocol("WM_DELETE_WINDOW", _on_close)
    picker.bind("<FocusOut>", lambda e: _on_close() if picker.winfo_exists() else None)

def _insert_emoji(em: str, picker: tk.Toplevel):
    global _emoji_picker_open
    msg_entry.insert(tk.END, em)
    msg_entry.focus_set()
    _emoji_picker_open = False
    picker.destroy()

emoji_btn = tk.Button(input_outer, text="😊", font=("Segoe UI Emoji", 13),
                      bg=WHEAT, activebackground=PARCHMENT,
                      bd=0, relief=tk.FLAT, cursor="hand2",
                      command=_toggle_emoji_picker)
emoji_btn.pack(side=tk.LEFT, padx=(0, 6))

input_pill = tk.Frame(input_outer, bg=WHITE, highlightbackground=SAND,
                      highlightthickness=1)
input_pill.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 8))

msg_entry = tk.Entry(input_pill, font=("Helvetica", 11), bg=WHITE, fg=TEXT_DARK,
                     bd=0, insertbackground=FOREST_MID, relief=tk.FLAT)
msg_entry.pack(fill=tk.X, expand=True, ipady=10, padx=12)

_action_buttons: list[tk.Button] = []

for btn_text, color, hover, cmd in [
    ("Send",  FOREST_DEEP, "#0a3d0b", lambda: send_message()),
    ("Image", FOREST_MID,  "#245220", lambda: send_image()),
]:
    b = tk.Button(input_outer, text=btn_text, font=("Helvetica", 9, "bold"),
                  bg=color, fg=WHITE, activebackground=hover, activeforeground=WHITE,
                  bd=0, cursor="hand2", relief=tk.FLAT, width=7,
                  command=cmd)
    b.pack(side=tk.LEFT, ipady=10, padx=(0, 4))
    _action_buttons.append(b)

send_btn, image_btn = _action_buttons


# Connection state helpers

def _set_connected(state: bool, banner_msg: str = ""):
    global _connected
    _connected = state
    if state:
        msg_entry.config(state=tk.NORMAL, bg=WHITE,
                         disabledbackground=WHITE)
        send_btn.config(state=tk.NORMAL, bg=FOREST_DEEP, cursor="hand2")
        image_btn.config(state=tk.NORMAL, bg=FOREST_MID, cursor="hand2")
        emoji_btn.config(state=tk.NORMAL)
        _hide_conn_banner()
    else:
        msg_entry.config(state=tk.DISABLED, disabledbackground="#ddd8b8")
        send_btn.config(state=tk.DISABLED, bg="#9aaf9a", cursor="")
        image_btn.config(state=tk.DISABLED, bg="#9aaf9a", cursor="")
        emoji_btn.config(state=tk.DISABLED)
        _show_conn_banner(banner_msg or "Disconnected", STATUS_ERROR)

_image_cache: list = []


def _render_body(text: str):
    words = text.split(" ")
    for i, word in enumerate(words):
        cleaned = word.strip()
        suffix = "" if i == len(words) - 1 else " "
        if cleaned in EMOJI_MAP:
            chat_area.insert(tk.END, EMOJI_MAP[cleaned] + suffix, "emoji")
        else:
            chat_area.insert(tk.END, word + suffix)


def append_to_chat(message_str: str, system_tag: str | None = None):
    chat_area.config(state=tk.NORMAL)
    now = datetime.datetime.now().strftime("%H:%M")
    chat_area.insert(tk.END, f"[{now}]  ", "timestamp")
    if system_tag:
        chat_area.insert(tk.END, f"{message_str}\n", system_tag)
    elif ":" in message_str:
        sender, body_text = message_str.split(":", 1)
        tag = "private" if "(private)" in sender else "username"
        chat_area.insert(tk.END, f"{sender}", tag)
        chat_area.insert(tk.END, "  ")
        _render_body(body_text)
        chat_area.insert(tk.END, "\n")
    else:
        chat_area.insert(tk.END, f"{message_str}\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.see(tk.END)


def append_history_message(timestamp: str, sender: str, content: str):
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, f"[{timestamp}]  ", "timestamp")
    chat_area.insert(tk.END, f"{sender}", "username")
    chat_area.insert(tk.END, "  ")
    _render_body(content)
    chat_area.insert(tk.END, "\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.see(tk.END)


def append_image_to_chat(sender_name: str, pil_image: Image.Image,
                         timestamp: str | None = None):
    chat_area.config(state=tk.NORMAL)
    ts = f"[{timestamp}]" if timestamp else datetime.datetime.now().strftime("[%H:%M]")
    chat_area.insert(tk.END, f"{ts}  ", "timestamp")
    chat_area.insert(tk.END, f"{sender_name} sent an image:\n", "username")
    pil_image.thumbnail((220, 220))
    img_obj = ImageTk.PhotoImage(pil_image)
    _image_cache.append(img_obj)
    chat_area.image_create(tk.END, image=img_obj)
    chat_area.insert(tk.END, "\n\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.see(tk.END)


def insert_history_divider():
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, "─" * 40 + "  earlier  " + "─" * 40 + "\n", "divider")
    chat_area.config(state=tk.DISABLED)

# Send functions

def send_message():
    if not _connected:
        return
    raw = msg_entry.get().strip()
    if not raw:
        return
    try:
        send_encrypted(client_sock, cipher, f"{my_username}: {raw}")
        msg_entry.delete(0, tk.END)
        global _typing_after_id
        if _typing_after_id:
            root.after_cancel(_typing_after_id)
            _typing_after_id = None
    except OSError as e:
        logger.error("Send error: %s", e)


def send_image():
    if not _connected:
        return
    file_path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png *.jpg *.jpeg *.gif")])
    if not file_path:
        return
    try:
        with open(file_path, "rb") as f:
            img_bytes = f.read()
        if not storage.is_valid_image(img_bytes):
            _banner_error("Only PNG, JPEG, and GIF images are supported.")
            return
        header = f"{TAG_IMAGE}{len(img_bytes)}|{my_username}"
        send_encrypted(client_sock, cipher, header)
        send_encrypted(client_sock, cipher, img_bytes)
    except OSError as e:
        _banner_error(f"Failed to send image: {e}")


def _banner_error(msg: str):
    _show_conn_banner(msg, STATUS_ERROR)
    root.after(4000, _hide_conn_banner)

# Typing indicator

def _on_keypress(event):
    global _typing_after_id
    if event.keysym in ("Return", "Shift_L", "Shift_R") or not _connected:
        return
    try:
        send_encrypted(client_sock, cipher, f"{TAG_TYPING}{my_username}")
    except OSError:
        pass
    if _typing_after_id:
        root.after_cancel(_typing_after_id)
    _typing_after_id = root.after(2000, lambda: typing_var.set(""))


msg_entry.bind("<Return>", lambda e: send_message())
msg_entry.bind("<KeyPress>", _on_keypress)

# Private DM panel

def _dm_record(recipient: str, direction: str, text: str):
    ts = datetime.datetime.now().strftime("%H:%M")
    _dm_history.setdefault(recipient, []).append((direction, text, ts))
    if recipient in _dm_windows and _dm_windows[recipient].winfo_exists():
        _dm_refresh(recipient)


def _dm_refresh(recipient: str):
    win = _dm_windows.get(recipient)
    if not win or not win.winfo_exists():
        return
    ta = win._dm_text
    ta.config(state=tk.NORMAL)
    ta.delete("1.0", tk.END)
    for direction, text, ts in _dm_history.get(recipient, []):
        label = "You" if direction == "sent" else recipient
        align_tag = "sent_tag" if direction == "sent" else "recv_tag"
        ta.insert(tk.END, f"[{ts}] {label}: ", align_tag)
        ta.insert(tk.END, f"{text}\n")
    ta.config(state=tk.DISABLED)
    ta.see(tk.END)


def open_private_dialog(recipient: str):
    if recipient in _dm_windows and _dm_windows[recipient].winfo_exists():
        _dm_windows[recipient].lift()
        _dm_windows[recipient].focus_force()
        return

    dlg = tk.Toplevel(root)
    dlg.title(f"🔒 DM — {recipient}")
    dlg.geometry("400x340")
    dlg.configure(bg=PARCHMENT)
    dlg.resizable(True, True)
    dlg.minsize(320, 240)

    dh = tk.Frame(dlg, bg=FOREST_DEEP, height=40)
    dh.pack(fill=tk.X)
    dh.pack_propagate(False)
    tk.Label(dh, text=f"🔒 Private chat with {recipient}",
             font=("Helvetica", 10, "bold"), bg=FOREST_DEEP, fg=WHITE).pack(
             side=tk.LEFT, padx=12, expand=True, anchor="w")

    thread_frame = tk.Frame(dlg, bg=PARCHMENT)
    thread_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(6, 0))

    dm_ta = tk.Text(thread_frame, wrap=tk.WORD, state=tk.DISABLED,
                    bg=WHEAT, fg=TEXT_DARK, font=("Helvetica", 10),
                    bd=0, padx=10, pady=8, relief=tk.FLAT, highlightthickness=0)
    dm_ta.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    dm_sb = tk.Scrollbar(thread_frame, command=dm_ta.yview,
                         bg=SAND, troughcolor=WHEAT, bd=0, width=7)
    dm_sb.pack(side=tk.RIGHT, fill=tk.Y)
    dm_ta.config(yscrollcommand=dm_sb.set)
    dm_ta.tag_config("sent_tag", foreground=FOREST_DEEP, font=("Helvetica", 9, "bold"))
    dm_ta.tag_config("recv_tag", foreground="#7a5c20", font=("Helvetica", 9, "bold"))

    dlg._dm_text = dm_ta

    status_var = tk.StringVar(value="")
    tk.Label(dlg, textvariable=status_var, bg=PARCHMENT,
             fg=FOREST_MID, font=("Helvetica", 8, "italic"),
             anchor="w").pack(fill=tk.X, padx=12)

    inp_row = tk.Frame(dlg, bg=PARCHMENT, pady=8)
    inp_row.pack(fill=tk.X, padx=8)

    pm_pill = tk.Frame(inp_row, bg=WHITE, highlightbackground=SAND,
                       highlightthickness=1)
    pm_pill.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    pm_entry = tk.Entry(pm_pill, font=("Helvetica", 11), bg=WHITE, fg=TEXT_DARK,
                        bd=0, insertbackground=FOREST_MID)
    pm_entry.pack(fill=tk.X, ipady=7, padx=8)
    pm_entry.focus_set()

    def do_send():
        text = pm_entry.get().strip()
        if not text:
            return
        if not _connected:
            status_var.set("⚠ Disconnected — cannot send.")
            return
        try:
            msg = f"{my_username}: /msg {recipient} {text}"
            send_encrypted(client_sock, cipher, msg)
            pm_entry.delete(0, tk.END)
            _dm_record(recipient, "sent", text)
            status_var.set(f"✓ Sent at {datetime.datetime.now().strftime('%H:%M')}")
            dlg.after(3000, lambda: status_var.set(""))
        except OSError as e:
            status_var.set(f"✗ Send failed: {e}")

    tk.Button(inp_row, text="Send", bg=FOREST_DEEP, fg=WHITE,
              activebackground=FOREST_MID, activeforeground=WHITE,
              bd=0, cursor="hand2", relief=tk.FLAT,
              font=("Helvetica", 10, "bold"), command=do_send
              ).pack(side=tk.LEFT, ipady=8, ipadx=12)

    pm_entry.bind("<Return>", lambda e: do_send())

    _dm_windows[recipient] = dlg
    _dm_refresh(recipient)

    def _on_dm_close():
        _dm_windows.pop(recipient, None)
        dlg.destroy()
    dlg.protocol("WM_DELETE_WINDOW", _on_dm_close)


# Right-click context menu

def show_context_menu(event):
    selection = users_list.curselection()
    if not selection:
        return
    raw = users_list.get(selection[0]).strip().lstrip("●○ ")
    if raw == my_username:
        return
    menu = tk.Menu(root, tearoff=0, bg=PARCHMENT, fg=TEXT_DARK,
                   activebackground=WHEAT, activeforeground=FOREST_DEEP,
                   font=("Helvetica", 10))
    menu.add_command(
        label=f"  💬 DM {raw}  ",
        command=lambda: open_private_dialog(raw),
    )
    menu.tk_popup(event.x_root, event.y_root)


users_list.bind("<Button-3>", show_context_menu)
users_list.bind("<Double-Button-1>", lambda e: show_context_menu(e))


# Receive thread

def receive_messages():
    history_buffer: list = []
    receiving_history = True

    while True:
        try:
            message = recv_encrypted(client_sock, cipher)

            if message.startswith(TAG_HISTORY_TEXT):
                _, timestamp, sender, content = message.split("|", 3)
                history_buffer.append(("text", timestamp, sender, content))
                continue

            if message.startswith(TAG_HISTORY_IMAGE):
                _, size_str, sender, timestamp = message.split("|")
                img_bytes = recv_encrypted_bytes(client_sock, cipher)
                try:
                    pil_img = Image.open(io.BytesIO(img_bytes))
                    history_buffer.append(("image", timestamp, sender, pil_img))
                except Exception as e:
                    logger.warning("Could not decode history image: %s", e)
                continue

            if receiving_history:
                receiving_history = False
                if history_buffer:
                    root.after(0, insert_history_divider)
                    for entry in history_buffer:
                        if entry[0] == "text":
                            root.after(0, append_history_message, entry[1], entry[2], entry[3])
                        elif entry[0] == "image":
                            root.after(0, append_image_to_chat, entry[2], entry[3], entry[1])
                    root.after(0, insert_history_divider)
                history_buffer.clear()

            if message.startswith(TAG_USERS):
                user_csv = message[len(TAG_USERS):]
                online_users.clear()
                online_users.extend(u for u in user_csv.split(",") if u)
                root.after(0, refresh_users_list)
                continue

            if message.startswith(TAG_TYPING):
                typer = message[len(TAG_TYPING):]
                root.after(0, typing_var.set, f"{typer} is typing…")
                root.after(2500, lambda: typing_var.set(""))
                continue

            if message.startswith(TAG_IMAGE):
                parts = message.split("|")
                sender = parts[2] if len(parts) >= 3 else "?"
                img_bytes = recv_encrypted_bytes(client_sock, cipher)
                try:
                    pil_img = Image.open(io.BytesIO(img_bytes))
                    root.after(0, append_image_to_chat, sender, pil_img)
                    if sender != my_username:
                        _notify("New Image", f"{sender} sent an image")
                except Exception as e:
                    logger.warning("Could not decode live image: %s", e)
                continue

            if "(private)" in message and ":" in message:
                sender_part, body = message.split(":", 1)
                sender_name = sender_part.replace("(private)", "").strip()
                _dm_record(sender_name, "received", body.strip())
                root.after(0, append_to_chat, message, "private")
                _notify(f"DM from {sender_name}", body.strip()[:60])
                continue

            if "joined the chat!" in message:
                root.after(0, append_to_chat, message, "join")
                _notify("User Joined", message)
            elif "left the chat!" in message:
                root.after(0, append_to_chat, message, "leave")
                _notify("User Left", message)
            else:
                root.after(0, append_to_chat, message)
                if not message.startswith(f"{my_username}:"):
                    _notify("New Message", message[:60])

        except ConnectionError as e:
            logger.info("Disconnected: %s", e)
            break
        except Exception as e:
            logger.exception("Receive error: %s", e)
            break

    root.after(0, _set_connected, False, "⚠ Disconnected — retrying in 5 s…")
    root.after(0, append_to_chat, "— You have been disconnected from the server —", "disconn")
    _schedule_reconnect()


def _schedule_reconnect(attempt: int = 1):
    def _attempt():
        global client_sock, cipher, _connected
        logger.info("Reconnect attempt #%d…", attempt)
        new_sock, new_cipher = _try_connect()
        if new_sock is None:
            root.after(0, _show_conn_banner,
                       f"⚠ Disconnected — retrying… (attempt {attempt + 1})", STATUS_ERROR)
            root.after(5000, _schedule_reconnect, attempt + 1)
            return
        root.after(0, _show_conn_banner,
                   "Server is back online. Please restart the client to reconnect.",
                   STATUS_WARN)
        new_sock.close()

    threading.Thread(target=_attempt, daemon=True).start()


def _ensure_notify_icon() -> str:
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_lazychat_icon.ico")
    if os.path.exists(icon_path):
        return icon_path
    try:
        from PIL import ImageDraw, ImageFont

        def _make_frame(size: int) -> Image.Image:
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            draw.ellipse([0, 0, size - 1, size - 1], fill="#306D29")
            try:
                font = ImageFont.truetype("seguiemj.ttf", int(size * 0.56))
            except Exception:
                font = ImageFont.load_default()
            draw.text(
                (size // 2, size // 2), "💬",
                font=font, anchor="mm", embedded_color=True,
            )
            return img.convert("RGBA")

        base = _make_frame(256)
        base.save(
            icon_path,
            format="ICO",
            sizes=[(256, 256), (64, 64), (32, 32), (16, 16)],
        )
        logger.info("Notification icon created at %s", icon_path)
    except Exception as e:
        logger.debug("Could not generate notify icon: %s", e)
        return ""
    return icon_path


def _notify(title: str, msg: str):
    try:
        from plyer import notification
        icon = _ensure_notify_icon()
        notification.notify(
            app_name="Lazy Chat",
            title=title,
            message=msg,
            app_icon=icon or None,
            timeout=5,
        )
    except Exception as e:
        logger.debug("Notification error: %s", e)


online_users.append(my_username)
refresh_users_list()

threading.Thread(target=receive_messages, daemon=True).start()
root.mainloop()