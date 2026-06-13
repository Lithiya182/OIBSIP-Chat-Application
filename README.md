# 💬 Lazy Chat

A secure, end-to-end encrypted LAN chat application built with Python and Tkinter.

---

## Features

- **RSA + Fernet key exchange** — no symmetric key stored in source code
- **bcrypt password hashing** — salted, work-factor 12
- **Encrypted image sharing** — all bytes wrapped in Fernet, validated by magic-byte check
- **Chat history replay** — SQLite-backed, streamed to new clients on join
- **Online users sidebar** — live list updated on every join/leave
- **Typing indicator** — debounced, 2-second timeout
- **Private messaging** — right-click any user in the sidebar
- **Desktop notifications** — join, leave, new message, new image
- **Unicode emoji** — no external image files required

---

## Project Structure

```
lazy_chat/
├── server.py          # Chat server
├── chat_gui.py        # Client GUI
├── crypto.py          # RSA key exchange + Fernet framing
├── storage.py         # SQLite storage + bcrypt + image validation
├── network.py         # Shared protocol constants + send/recv helpers
├── requirements.txt
└── README.md
```

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
python server.py
```

The server creates `lazy_chat.db` and an `images/` folder automatically on first run.

### 3. Start a client

```bash
python chat_gui.py
```

Run this on as many machines (or terminals) as you like.  
On first launch, register a new account. On subsequent launches, log in.

---

## Emoji codes

| Code     | Emoji |
|----------|-------|
| `:)`     | 😊   |
| `:D`     | 😄   |
| `:(`     | 😢   |
| `<3`     | ❤️   |
| `:fire:` | 🔥   |
| `:star:` | ⭐   |
| `:ok:`   | 👍   |
| `:wave:` | 👋   |
| `:eyes:` | 👀   |
| `:100:`  | 💯   |

---

## Security notes

- The RSA key pair is generated fresh every time the server starts.
- Session keys are never written to disk.
- `users.json` and `chat_history.json` are no longer used — delete them if present.
- Image payloads are validated against PNG/JPEG/GIF magic bytes before relay or storage.

---

## Requirements

- Python 3.11+
- Windows / macOS / Linux
