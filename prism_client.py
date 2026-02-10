#!/usr/bin/env python3
"""
Prism GUI Client
================
A graphical desktop client for the Prism E2E Encrypted Chat protocol.
Implements the full Prism Protocol (PP) over TCP with AES-256 encryption.

Requirements:
    - Python 3.8+
    - pycryptodome (pip install pycryptodome)
    - tkinter (usually included with Python)

Usage:
    python prism_client.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, font as tkfont
import socket
import struct
import threading
import os
import sys
import time
from datetime import datetime

# AES encryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ─── Protocol Constants ──────────────────────────────────────────────────────

PRISM_PORT = 14296
CLIENT_VERSION = "1.0.0\x00\x00\x00"  # 8 bytes, padded

# Packet types
PKT_INITIAL          = 0x01
PKT_WELCOME          = 0x02
PKT_SERVER_DISCONNECT = 0x03
PKT_CLIENT_CONNECT   = 0x05
PKT_CLIENT_DISCONNECT = 0x06
PKT_GENERAL_MESSAGE  = 0x14  # 20

MAX_USERNAME_LEN = 20


# ─── Encryption ──────────────────────────────────────────────────────────────

class PrismCrypto:
    """AES-256-CFB encryption compatible with Go's crypto/aes + cipher.CFB."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes for AES-256")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with AES-256-CFB. Prepends random 16-byte IV to ciphertext."""
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv, segment_size=128)
        ciphertext = cipher.encrypt(plaintext)
        return iv + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt AES-256-CFB. Expects 16-byte IV prepended to ciphertext."""
        if len(data) < AES.block_size:
            raise ValueError("Ciphertext too short")
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher.decrypt(ciphertext)


# ─── Protocol Implementation ─────────────────────────────────────────────────

class PrismProtocol:
    """Encodes/decodes Prism Protocol packets."""

    @staticmethod
    def encode_size_prefix(data: bytes) -> bytes:
        """Prepend 2-byte uint16 big-endian size prefix."""
        return struct.pack("!H", len(data)) + data

    @staticmethod
    def build_initial_packet(username: str) -> bytes:
        """
        Build an Initial [1] packet.
        Byte 0:     packet type (0x01)
        Byte 1:     username length
        Byte 2-21:  username (UTF-8, padded to 20 bytes)
        Byte 22-29: client version (8 bytes)
        """
        uname_bytes = username.encode("utf-8")[:MAX_USERNAME_LEN]
        uname_padded = uname_bytes.ljust(MAX_USERNAME_LEN, b'\x00')

        version_bytes = CLIENT_VERSION.encode("utf-8")[:8].ljust(8, b'\x00')

        packet = bytes([PKT_INITIAL, len(uname_bytes)]) + uname_padded + version_bytes
        return PrismProtocol.encode_size_prefix(packet)

    @staticmethod
    def build_message_packet(username: str, message: bytes, encrypted: bool = True) -> bytes:
        """
        Build a GeneralMessage [20] packet.
        Byte 0:     packet type (0x14)
        Byte 1:     username length
        Byte 2-21:  username (UTF-8, padded to 20 bytes)
        Byte 22:    encrypted boolean
        Byte 23:    message length
        Byte 24+:   message data
        """
        uname_bytes = username.encode("utf-8")[:MAX_USERNAME_LEN]
        uname_padded = uname_bytes.ljust(MAX_USERNAME_LEN, b'\x00')

        packet = (
            bytes([PKT_GENERAL_MESSAGE, len(uname_bytes)])
            + uname_padded
            + bytes([0x01 if encrypted else 0x00])
            + bytes([len(message)])
            + message
        )
        return PrismProtocol.encode_size_prefix(packet)

    @staticmethod
    def parse_packet(data: bytes) -> dict:
        """Parse a raw packet (after size prefix has been stripped)."""
        if not data:
            return {"type": None}

        pkt_type = data[0]

        if pkt_type == PKT_WELCOME:
            return PrismProtocol._parse_welcome(data)
        elif pkt_type == PKT_SERVER_DISCONNECT:
            return PrismProtocol._parse_server_disconnect(data)
        elif pkt_type == PKT_CLIENT_CONNECT:
            return PrismProtocol._parse_client_connect(data)
        elif pkt_type == PKT_CLIENT_DISCONNECT:
            return PrismProtocol._parse_client_disconnect(data)
        elif pkt_type == PKT_GENERAL_MESSAGE:
            return PrismProtocol._parse_general_message(data)
        else:
            return {"type": pkt_type, "raw": data}

    @staticmethod
    def _parse_welcome(data: bytes) -> dict:
        """Parse Welcome [2] packet to extract connected user list."""
        result = {"type": PKT_WELCOME, "users": []}
        if len(data) < 2:
            return result

        num_users = data[1]
        offset = 2

        for _ in range(num_users):
            if offset >= len(data):
                break
            uname_len = data[offset]
            offset += 1
            if offset + uname_len > len(data):
                break
            username = data[offset:offset + uname_len].decode("utf-8", errors="replace")
            result["users"].append(username)
            offset += uname_len

        return result

    @staticmethod
    def _parse_server_disconnect(data: bytes) -> dict:
        """Parse ServerDisconnect [3] packet."""
        result = {"type": PKT_SERVER_DISCONNECT, "code": 0, "reason": "Unknown"}
        if len(data) >= 2:
            result["code"] = data[1]
        if len(data) >= 3:
            reason_len = data[2]
            if len(data) >= 3 + reason_len:
                result["reason"] = data[3:3 + reason_len].decode("utf-8", errors="replace")
        return result

    @staticmethod
    def _parse_client_connect(data: bytes) -> dict:
        """Parse ClientConnect [5] packet."""
        result = {"type": PKT_CLIENT_CONNECT, "username": ""}
        if len(data) >= 2:
            uname_len = data[1]
            uname_end = min(2 + uname_len, len(data))
            result["username"] = data[2:uname_end].decode("utf-8", errors="replace")
        return result

    @staticmethod
    def _parse_client_disconnect(data: bytes) -> dict:
        """Parse ClientDisconnect [6] packet."""
        result = {"type": PKT_CLIENT_DISCONNECT, "username": ""}
        if len(data) >= 2:
            uname_len = data[1]
            uname_end = min(2 + uname_len, len(data))
            result["username"] = data[2:uname_end].decode("utf-8", errors="replace")
        return result

    @staticmethod
    def _parse_general_message(data: bytes) -> dict:
        """Parse GeneralMessage [20] packet."""
        result = {
            "type": PKT_GENERAL_MESSAGE,
            "username": "",
            "encrypted": False,
            "message": b"",
        }
        if len(data) < 24:
            return result

        uname_len = data[1]
        result["username"] = data[2:2 + uname_len].decode("utf-8", errors="replace")
        result["encrypted"] = data[22] == 0x01

        if len(data) >= 24:
            msg_len = data[23]
            result["message"] = data[24:24 + msg_len]

        return result


# ─── Network Client ──────────────────────────────────────────────────────────

class PrismClient:
    """Manages the TCP connection and protocol communication."""

    def __init__(self, on_message, on_user_join, on_user_leave,
                 on_welcome, on_disconnect, on_error):
        self.sock = None
        self.connected = False
        self.username = ""
        self.crypto = None
        self.recv_thread = None

        # Callbacks
        self.on_message = on_message
        self.on_user_join = on_user_join
        self.on_user_leave = on_user_leave
        self.on_welcome = on_welcome
        self.on_disconnect = on_disconnect
        self.on_error = on_error

    def connect(self, host: str, port: int, username: str, key: bytes):
        """Connect to the Prism server and send the Initial packet."""
        self.username = username
        self.crypto = PrismCrypto(key)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((host, port))
            self.sock.settimeout(None)
        except Exception as e:
            self.on_error(f"Connection failed: {e}")
            return False

        # Send Initial packet
        initial_pkt = PrismProtocol.build_initial_packet(username)
        try:
            self.sock.sendall(initial_pkt)
        except Exception as e:
            self.on_error(f"Failed to send handshake: {e}")
            self.sock.close()
            return False

        self.connected = True

        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()
        return True

    def send_message(self, text: str):
        """Encrypt and send a chat message."""
        if not self.connected or not self.sock:
            return

        plaintext = text.encode("utf-8")
        ciphertext = self.crypto.encrypt(plaintext)

        pkt = PrismProtocol.build_message_packet(self.username, ciphertext, encrypted=True)
        try:
            self.sock.sendall(pkt)
        except Exception as e:
            self.on_error(f"Send failed: {e}")
            self.disconnect()

    def disconnect(self):
        """Close the connection."""
        self.connected = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _recv_loop(self):
        """Background thread: read packets from the server."""
        while self.connected:
            try:
                # Read 2-byte size prefix
                size_data = self._recv_exact(2)
                if not size_data:
                    break
                pkt_size = struct.unpack("!H", size_data)[0]

                if pkt_size == 0:
                    continue

                # Read the packet body
                pkt_data = self._recv_exact(pkt_size)
                if not pkt_data:
                    break

                self._handle_packet(pkt_data)

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                break
            except OSError:
                break
            except Exception as e:
                if self.connected:
                    self.on_error(f"Receive error: {e}")
                break

        self.connected = False
        self.on_disconnect("Connection closed")

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle_packet(self, data: bytes):
        """Dispatch a parsed packet to the appropriate callback."""
        pkt = PrismProtocol.parse_packet(data)
        pkt_type = pkt.get("type")

        if pkt_type == PKT_WELCOME:
            self.on_welcome(pkt["users"])

        elif pkt_type == PKT_SERVER_DISCONNECT:
            self.on_disconnect(f"Server disconnect [{pkt['code']}]: {pkt['reason']}")
            self.disconnect()

        elif pkt_type == PKT_CLIENT_CONNECT:
            self.on_user_join(pkt["username"])

        elif pkt_type == PKT_CLIENT_DISCONNECT:
            self.on_user_leave(pkt["username"])

        elif pkt_type == PKT_GENERAL_MESSAGE:
            username = pkt["username"]
            if pkt["encrypted"] and self.crypto:
                try:
                    plaintext = self.crypto.decrypt(pkt["message"]).decode("utf-8", errors="replace")
                except Exception:
                    plaintext = "[Could not decrypt message — wrong key?]"
            else:
                plaintext = pkt["message"].decode("utf-8", errors="replace")

            self.on_message(username, plaintext)


# ─── Color Palette ────────────────────────────────────────────────────────────

class Theme:
    """Dark theme color palette inspired by the 'Prism' name."""
    BG_DARK      = "#0d1117"
    BG_MEDIUM    = "#161b22"
    BG_LIGHT     = "#21262d"
    BG_INPUT     = "#1c2128"
    BORDER       = "#30363d"
    TEXT         = "#e6edf3"
    TEXT_DIM     = "#8b949e"
    TEXT_MUTED   = "#484f58"
    ACCENT       = "#7c6aef"   # Purple — prism/spectrum
    ACCENT_HOVER = "#9b8afb"
    SUCCESS      = "#3fb950"
    WARNING      = "#d29922"
    ERROR        = "#f85149"
    CYAN         = "#58a6ff"
    PINK         = "#f778ba"
    USER_COLORS  = ["#58a6ff", "#f778ba", "#7ee787", "#d2a8ff", "#ffa657", "#79c0ff"]


# ─── GUI Application ─────────────────────────────────────────────────────────

class PrismGUI:
    """Main application window."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Prism — E2E Encrypted Chat")
        self.root.geometry("960x640")
        self.root.minsize(720, 480)
        self.root.configure(bg=Theme.BG_DARK)

        # Try to set a window icon (won't fail if unavailable)
        try:
            self.root.iconname("Prism")
        except Exception:
            pass

        self.client = None
        self.users = []
        self.user_color_map = {}
        self.color_index = 0

        self._setup_fonts()
        self._setup_styles()
        self._build_connect_screen()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Fonts & Styles ────────────────────────────────────────────────────

    def _setup_fonts(self):
        available = tkfont.families()

        # Pick the best available monospace / UI fonts
        mono_candidates = ["JetBrains Mono", "Fira Code", "Cascadia Code",
                           "SF Mono", "Consolas", "Ubuntu Mono",
                           "Liberation Mono", "Courier New"]
        ui_candidates = ["SF Pro Display", "Segoe UI", "Helvetica Neue",
                         "Ubuntu", "Cantarell", "Noto Sans", "Arial"]

        self.font_mono = "Courier"
        for f in mono_candidates:
            if f in available:
                self.font_mono = f
                break

        self.font_ui = "Helvetica"
        for f in ui_candidates:
            if f in available:
                self.font_ui = f
                break

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("Dark.TFrame", background=Theme.BG_DARK)
        self.style.configure("Medium.TFrame", background=Theme.BG_MEDIUM)
        self.style.configure("Light.TFrame", background=Theme.BG_LIGHT)

        self.style.configure("Title.TLabel",
                             background=Theme.BG_DARK,
                             foreground=Theme.ACCENT,
                             font=(self.font_ui, 28, "bold"))

        self.style.configure("Subtitle.TLabel",
                             background=Theme.BG_DARK,
                             foreground=Theme.TEXT_DIM,
                             font=(self.font_ui, 11))

        self.style.configure("Field.TLabel",
                             background=Theme.BG_DARK,
                             foreground=Theme.TEXT,
                             font=(self.font_ui, 10))

        self.style.configure("Status.TLabel",
                             background=Theme.BG_MEDIUM,
                             foreground=Theme.TEXT_DIM,
                             font=(self.font_ui, 9))

        self.style.configure("Sidebar.TLabel",
                             background=Theme.BG_MEDIUM,
                             foreground=Theme.TEXT_DIM,
                             font=(self.font_ui, 9, "bold"))

        self.style.configure("UserCount.TLabel",
                             background=Theme.BG_MEDIUM,
                             foreground=Theme.TEXT_MUTED,
                             font=(self.font_ui, 9))

        self.style.configure("Accent.TButton",
                             background=Theme.ACCENT,
                             foreground="#ffffff",
                             font=(self.font_ui, 11, "bold"),
                             padding=(20, 10),
                             borderwidth=0)
        self.style.map("Accent.TButton",
                       background=[("active", Theme.ACCENT_HOVER)])

        self.style.configure("Flat.TButton",
                             background=Theme.BG_LIGHT,
                             foreground=Theme.TEXT_DIM,
                             font=(self.font_ui, 10),
                             padding=(12, 6),
                             borderwidth=0)
        self.style.map("Flat.TButton",
                       background=[("active", Theme.BORDER)])

    # ── Connect Screen ────────────────────────────────────────────────────

    def _build_connect_screen(self):
        """Build the connection/login screen."""
        self.connect_frame = ttk.Frame(self.root, style="Dark.TFrame")
        self.connect_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ttk.Label(self.connect_frame, text="◇ PRISM",
                  style="Title.TLabel").pack(pady=(0, 4))
        ttk.Label(self.connect_frame, text="End-to-End Encrypted Chat",
                  style="Subtitle.TLabel").pack(pady=(0, 30))

        fields_frame = ttk.Frame(self.connect_frame, style="Dark.TFrame")
        fields_frame.pack()

        # Server address
        ttk.Label(fields_frame, text="SERVER ADDRESS",
                  style="Field.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.entry_host = tk.Entry(fields_frame, width=36,
                                   bg=Theme.BG_INPUT, fg=Theme.TEXT,
                                   insertbackground=Theme.TEXT,
                                   font=(self.font_mono, 11),
                                   relief="flat", bd=8,
                                   highlightthickness=1,
                                   highlightcolor=Theme.ACCENT,
                                   highlightbackground=Theme.BORDER)
        self.entry_host.grid(row=1, column=0, pady=(0, 16))
        self.entry_host.insert(0, "127.0.0.1")

        # Port
        ttk.Label(fields_frame, text="PORT",
                  style="Field.TLabel").grid(row=0, column=1, sticky="w", pady=(0, 4), padx=(12, 0))
        self.entry_port = tk.Entry(fields_frame, width=8,
                                   bg=Theme.BG_INPUT, fg=Theme.TEXT,
                                   insertbackground=Theme.TEXT,
                                   font=(self.font_mono, 11),
                                   relief="flat", bd=8,
                                   highlightthickness=1,
                                   highlightcolor=Theme.ACCENT,
                                   highlightbackground=Theme.BORDER)
        self.entry_port.grid(row=1, column=1, pady=(0, 16), padx=(12, 0))
        self.entry_port.insert(0, str(PRISM_PORT))

        # Username
        ttk.Label(fields_frame, text="USERNAME",
                  style="Field.TLabel").grid(row=2, column=0, columnspan=2,
                                             sticky="w", pady=(0, 4))
        self.entry_user = tk.Entry(fields_frame, width=48,
                                   bg=Theme.BG_INPUT, fg=Theme.TEXT,
                                   insertbackground=Theme.TEXT,
                                   font=(self.font_mono, 11),
                                   relief="flat", bd=8,
                                   highlightthickness=1,
                                   highlightcolor=Theme.ACCENT,
                                   highlightbackground=Theme.BORDER)
        self.entry_user.grid(row=3, column=0, columnspan=2, pady=(0, 16))

        # Encryption key
        ttk.Label(fields_frame, text="32-BYTE ENCRYPTION KEY",
                  style="Field.TLabel").grid(row=4, column=0, columnspan=2,
                                             sticky="w", pady=(0, 4))
        self.entry_key = tk.Entry(fields_frame, width=48,
                                  bg=Theme.BG_INPUT, fg=Theme.TEXT,
                                  insertbackground=Theme.TEXT,
                                  font=(self.font_mono, 11),
                                  relief="flat", bd=8,
                                  show="•",
                                  highlightthickness=1,
                                  highlightcolor=Theme.ACCENT,
                                  highlightbackground=Theme.BORDER)
        self.entry_key.grid(row=5, column=0, columnspan=2, pady=(0, 8))

        # Show/hide key toggle
        self.show_key_var = tk.BooleanVar(value=False)
        self.show_key_btn = tk.Checkbutton(
            fields_frame, text="Show key", variable=self.show_key_var,
            command=self._toggle_key_visibility,
            bg=Theme.BG_DARK, fg=Theme.TEXT_DIM,
            selectcolor=Theme.BG_LIGHT,
            activebackground=Theme.BG_DARK,
            activeforeground=Theme.TEXT_DIM,
            font=(self.font_ui, 9))
        self.show_key_btn.grid(row=6, column=0, columnspan=2, sticky="w", pady=(0, 4))

        # Key info
        ttk.Label(fields_frame,
                  text="Enter exactly 32 ASCII characters, or 64 hex characters (0-9, a-f)",
                  style="Subtitle.TLabel").grid(row=7, column=0, columnspan=2,
                                                sticky="w", pady=(0, 20))

        # Connect button
        self.btn_connect = ttk.Button(self.connect_frame, text="Connect",
                                      style="Accent.TButton",
                                      command=self._do_connect)
        self.btn_connect.pack(pady=(10, 0))

        # Error label
        self.lbl_connect_error = tk.Label(self.connect_frame, text="",
                                          bg=Theme.BG_DARK, fg=Theme.ERROR,
                                          font=(self.font_ui, 10))
        self.lbl_connect_error.pack(pady=(12, 0))

        # Bind Enter key
        self.entry_key.bind("<Return>", lambda e: self._do_connect())
        self.entry_user.bind("<Return>", lambda e: self._do_connect())
        self.entry_host.bind("<Return>", lambda e: self._do_connect())

    def _toggle_key_visibility(self):
        if self.show_key_var.get():
            self.entry_key.configure(show="")
        else:
            self.entry_key.configure(show="•")

    def _do_connect(self):
        """Validate inputs and attempt connection."""
        host = self.entry_host.get().strip()
        port_str = self.entry_port.get().strip()
        username = self.entry_user.get().strip()
        key_input = self.entry_key.get().strip()

        # Validate
        if not host:
            self._show_connect_error("Server address is required")
            return
        try:
            port = int(port_str)
        except ValueError:
            self._show_connect_error("Invalid port number")
            return
        if not username:
            self._show_connect_error("Username is required")
            return
        if len(username) > MAX_USERNAME_LEN:
            self._show_connect_error(f"Username must be {MAX_USERNAME_LEN} characters or fewer")
            return

        # Parse key: accept 32 ASCII chars or 64 hex chars
        key = self._parse_key(key_input)
        if key is None:
            self._show_connect_error("Key must be 32 ASCII characters or 64 hex characters")
            return

        self.lbl_connect_error.configure(text="Connecting...", fg=Theme.TEXT_DIM)
        self.btn_connect.configure(state="disabled")
        self.root.update_idletasks()

        # Create client and connect
        self.client = PrismClient(
            on_message=self._on_message,
            on_user_join=self._on_user_join,
            on_user_leave=self._on_user_leave,
            on_welcome=self._on_welcome,
            on_disconnect=self._on_disconnect,
            on_error=self._on_error,
        )

        # Connect in a thread to avoid freezing the UI
        def connect_thread():
            success = self.client.connect(host, port, username, key)
            self.root.after(0, lambda: self._on_connect_result(success))

        threading.Thread(target=connect_thread, daemon=True).start()

    def _parse_key(self, key_input: str) -> bytes:
        """Parse encryption key from user input."""
        if len(key_input) == 32:
            return key_input.encode("utf-8")
        elif len(key_input) == 64:
            try:
                return bytes.fromhex(key_input)
            except ValueError:
                return None
        return None

    def _show_connect_error(self, msg: str):
        self.lbl_connect_error.configure(text=msg, fg=Theme.ERROR)

    def _on_connect_result(self, success: bool):
        if success:
            self.connect_frame.destroy()
            self._build_chat_screen()
        else:
            self.btn_connect.configure(state="normal")

    # ── Chat Screen ───────────────────────────────────────────────────────

    def _build_chat_screen(self):
        """Build the main chat interface."""
        # ── Top bar ──
        topbar = tk.Frame(self.root, bg=Theme.BG_MEDIUM, height=48)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        title_lbl = tk.Label(topbar, text="◇ PRISM",
                             bg=Theme.BG_MEDIUM, fg=Theme.ACCENT,
                             font=(self.font_ui, 14, "bold"))
        title_lbl.pack(side="left", padx=16)

        self.status_lbl = tk.Label(topbar, text="● Connected",
                                   bg=Theme.BG_MEDIUM, fg=Theme.SUCCESS,
                                   font=(self.font_ui, 10))
        self.status_lbl.pack(side="left", padx=(0, 16))

        # Connected as
        user_lbl = tk.Label(topbar,
                            text=f"as {self.client.username}",
                            bg=Theme.BG_MEDIUM, fg=Theme.TEXT_DIM,
                            font=(self.font_ui, 10))
        user_lbl.pack(side="left")

        # Disconnect button
        btn_disconnect = ttk.Button(topbar, text="Disconnect",
                                    style="Flat.TButton",
                                    command=self._do_disconnect)
        btn_disconnect.pack(side="right", padx=12, pady=8)

        # ── Main area (chat + sidebar) ──
        main_pane = tk.Frame(self.root, bg=Theme.BG_DARK)
        main_pane.pack(fill="both", expand=True)

        # ── Sidebar (user list) ──
        sidebar = tk.Frame(main_pane, bg=Theme.BG_MEDIUM, width=200)
        sidebar.pack(side="right", fill="y")
        sidebar.pack_propagate(False)

        sidebar_header = tk.Frame(sidebar, bg=Theme.BG_MEDIUM)
        sidebar_header.pack(fill="x", padx=12, pady=(12, 0))

        tk.Label(sidebar_header, text="ONLINE",
                 bg=Theme.BG_MEDIUM, fg=Theme.TEXT_DIM,
                 font=(self.font_ui, 9, "bold")).pack(side="left")

        self.user_count_lbl = tk.Label(sidebar_header, text="0",
                                       bg=Theme.BG_MEDIUM, fg=Theme.TEXT_MUTED,
                                       font=(self.font_ui, 9))
        self.user_count_lbl.pack(side="right")

        # Separator
        tk.Frame(sidebar, bg=Theme.BORDER, height=1).pack(fill="x", padx=12, pady=8)

        # User list (scrollable)
        self.user_list_frame = tk.Frame(sidebar, bg=Theme.BG_MEDIUM)
        self.user_list_frame.pack(fill="both", expand=True, padx=12)

        # ── Chat area ──
        chat_area = tk.Frame(main_pane, bg=Theme.BG_DARK)
        chat_area.pack(side="left", fill="both", expand=True)

        # Messages display
        self.chat_display = tk.Text(
            chat_area,
            bg=Theme.BG_DARK,
            fg=Theme.TEXT,
            font=(self.font_mono, 11),
            wrap="word",
            relief="flat",
            padx=16,
            pady=12,
            cursor="arrow",
            state="disabled",
            spacing1=2,
            spacing3=2,
            selectbackground=Theme.ACCENT,
            selectforeground="#ffffff",
            highlightthickness=0,
            borderwidth=0,
        )
        self.chat_display.pack(fill="both", expand=True)

        # Configure text tags for styling
        self.chat_display.tag_configure("system",
                                        foreground=Theme.TEXT_MUTED,
                                        font=(self.font_ui, 10, "italic"))
        self.chat_display.tag_configure("timestamp",
                                        foreground=Theme.TEXT_MUTED,
                                        font=(self.font_mono, 9))
        self.chat_display.tag_configure("error",
                                        foreground=Theme.ERROR,
                                        font=(self.font_ui, 10))
        self.chat_display.tag_configure("join",
                                        foreground=Theme.SUCCESS,
                                        font=(self.font_ui, 10))
        self.chat_display.tag_configure("leave",
                                        foreground=Theme.WARNING,
                                        font=(self.font_ui, 10))
        self.chat_display.tag_configure("message_body",
                                        foreground=Theme.TEXT,
                                        font=(self.font_mono, 11))

        # Create user-color tags
        for i, color in enumerate(Theme.USER_COLORS):
            self.chat_display.tag_configure(f"user_color_{i}",
                                            foreground=color,
                                            font=(self.font_ui, 11, "bold"))

        # Scrollbar
        scrollbar = tk.Scrollbar(self.chat_display, command=self.chat_display.yview,
                                 bg=Theme.BG_LIGHT, troughcolor=Theme.BG_DARK,
                                 activebackground=Theme.BORDER,
                                 highlightthickness=0, borderwidth=0)
        scrollbar.pack(side="right", fill="y")
        self.chat_display.configure(yscrollcommand=scrollbar.set)

        # ── Input bar ──
        input_bar = tk.Frame(chat_area, bg=Theme.BG_MEDIUM, height=56)
        input_bar.pack(fill="x", side="bottom")
        input_bar.pack_propagate(False)

        # Encryption indicator
        lock_lbl = tk.Label(input_bar, text="🔒",
                            bg=Theme.BG_MEDIUM, fg=Theme.SUCCESS,
                            font=(self.font_ui, 14))
        lock_lbl.pack(side="left", padx=(12, 4))

        # Text entry
        self.msg_entry = tk.Entry(
            input_bar,
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT,
            insertbackground=Theme.TEXT,
            font=(self.font_mono, 11),
            relief="flat",
            bd=8,
            highlightthickness=1,
            highlightcolor=Theme.ACCENT,
            highlightbackground=Theme.BORDER,
        )
        self.msg_entry.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=10)
        self.msg_entry.bind("<Return>", self._on_send)
        self.msg_entry.focus_set()

        # Send button
        self.btn_send = ttk.Button(input_bar, text="Send",
                                   style="Accent.TButton",
                                   command=lambda: self._on_send(None))
        self.btn_send.pack(side="right", padx=(0, 12), pady=10)

        # Initial system message
        self._append_system("Connected to server. Messages are end-to-end encrypted with AES-256.")

    # ── Chat Display Helpers ──────────────────────────────────────────────

    def _get_user_color_tag(self, username: str) -> str:
        """Get a consistent color tag for a username."""
        if username not in self.user_color_map:
            idx = self.color_index % len(Theme.USER_COLORS)
            self.user_color_map[username] = f"user_color_{idx}"
            self.color_index += 1
        return self.user_color_map[username]

    def _append_text(self, parts: list):
        """
        Append styled text to the chat display.
        `parts` is a list of (text, tag) tuples.
        """
        self.chat_display.configure(state="normal")
        for text, tag in parts:
            if tag:
                self.chat_display.insert("end", text, tag)
            else:
                self.chat_display.insert("end", text)
        self.chat_display.insert("end", "\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M")

    def _append_system(self, msg: str):
        self._append_text([
            (f"  {self._timestamp()}  ", "timestamp"),
            (msg, "system"),
        ])

    def _append_chat_message(self, username: str, message: str):
        color_tag = self._get_user_color_tag(username)
        self._append_text([
            (f"  {self._timestamp()}  ", "timestamp"),
            (f"{username}", color_tag),
            (f"  {message}", "message_body"),
        ])

    # ── User List ─────────────────────────────────────────────────────────

    def _refresh_user_list(self):
        """Redraw the user list sidebar."""
        for widget in self.user_list_frame.winfo_children():
            widget.destroy()

        self.user_count_lbl.configure(text=str(len(self.users)))

        for user in sorted(self.users):
            color_tag = self._get_user_color_tag(user)
            color_idx = int(color_tag.split("_")[-1])
            color = Theme.USER_COLORS[color_idx]

            row = tk.Frame(self.user_list_frame, bg=Theme.BG_MEDIUM)
            row.pack(fill="x", pady=2)

            # Colored dot
            dot = tk.Label(row, text="●", bg=Theme.BG_MEDIUM, fg=color,
                           font=(self.font_ui, 8))
            dot.pack(side="left", padx=(0, 6))

            # Username
            is_self = (user == self.client.username)
            display_name = f"{user} (you)" if is_self else user
            lbl = tk.Label(row, text=display_name,
                           bg=Theme.BG_MEDIUM, fg=Theme.TEXT if not is_self else Theme.ACCENT,
                           font=(self.font_ui, 10, "bold" if is_self else "normal"),
                           anchor="w")
            lbl.pack(side="left")

    # ── Event Handlers ────────────────────────────────────────────────────

    def _on_send(self, event):
        """Handle sending a message."""
        msg = self.msg_entry.get().strip()
        if not msg or not self.client or not self.client.connected:
            return

        self.msg_entry.delete(0, "end")
        self.client.send_message(msg)

    def _do_disconnect(self):
        """Disconnect and return to connect screen."""
        if self.client:
            self.client.disconnect()

        # Clear everything and rebuild
        for widget in self.root.winfo_children():
            widget.destroy()

        self.users = []
        self.client = None
        self._build_connect_screen()

    def _on_close(self):
        """Handle window close."""
        if self.client:
            self.client.disconnect()
        self.root.destroy()
        sys.exit(0)

    # ── Network Callbacks (called from recv thread → scheduled to UI) ─────

    def _on_message(self, username: str, text: str):
        self.root.after(0, lambda: self._append_chat_message(username, text))

    def _on_user_join(self, username: str):
        def _update():
            if username not in self.users:
                self.users.append(username)
            self._refresh_user_list()
            self._append_text([
                (f"  {self._timestamp()}  ", "timestamp"),
                (f"→ {username} joined the room", "join"),
            ])
        self.root.after(0, _update)

    def _on_user_leave(self, username: str):
        def _update():
            if username in self.users:
                self.users.remove(username)
            self._refresh_user_list()
            self._append_text([
                (f"  {self._timestamp()}  ", "timestamp"),
                (f"← {username} left the room", "leave"),
            ])
        self.root.after(0, _update)

    def _on_welcome(self, user_list: list):
        def _update():
            self.users = list(user_list)
            if self.client.username not in self.users:
                self.users.append(self.client.username)
            self._refresh_user_list()

            if user_list:
                names = ", ".join(user_list)
                self._append_system(f"Users already here: {names}")
            else:
                self._append_system("You're the first one here.")
        self.root.after(0, _update)

    def _on_disconnect(self, reason: str):
        def _update():
            try:
                self.status_lbl.configure(text="● Disconnected", fg=Theme.ERROR)
                self._append_text([
                    (f"  {self._timestamp()}  ", "timestamp"),
                    (f"Disconnected: {reason}", "error"),
                ])
                self.msg_entry.configure(state="disabled")
            except tk.TclError:
                pass  # Widget may have been destroyed
        self.root.after(0, _update)

    def _on_error(self, msg: str):
        def _update():
            try:
                self._show_connect_error(msg)
            except (tk.TclError, AttributeError):
                try:
                    self._append_text([
                        (f"  {self._timestamp()}  ", "timestamp"),
                        (f"Error: {msg}", "error"),
                    ])
                except tk.TclError:
                    pass
        self.root.after(0, _update)

    # ── Run ───────────────────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = PrismGUI()
    app.run()
