#!/usr/bin/env python3
import sys
import socket
import threading
import time
import subprocess
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import psutil
import nmap
import dpkt
from collections import defaultdict, deque
import platform
import netifaces
import json
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np
import random
import queue
import requests
import asyncio
import telegram
from telegram.ext import Application, MessageHandler, filters, CommandHandler, ContextTypes
import logging
import pickle
import hashlib
import secrets
import string
import hmac
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
from contextlib import contextmanager
import io
import traceback

# Constants
VERSION = "2.0.0"
CONFIG_FILE = "cyber_monitor_config.json"
THREAT_DB = "threat_signatures.json"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
COMMAND_HISTORY_FILE = "command_history.pkl"
MAX_LOG_LINES = 1000
UPDATE_INTERVAL = 2  # seconds
MAX_COMMAND_HISTORY = 1000

# Threat detection thresholds
DOS_THRESHOLD = 100  # packets per second
PORT_SCAN_THRESHOLD = 50  # ports per minute
SYN_FLOOD_THRESHOLD = 200  # SYN packets per minute

# Database setup
DATABASE_FILE = "cyber_monitor.db"

class DatabaseManager:
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Command history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    command TEXT NOT NULL,
                    source TEXT NOT NULL,
                    user_id TEXT
                )
            ''')
            
            # IP whitelist/blacklist table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_lists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    list_type TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            ''')
            
            # Threat events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    threat_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    severity TEXT,
                    description TEXT,
                    packet_count INTEGER
                )
            ''')
            
            # System events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    message TEXT,
                    user TEXT
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def add_command_history(self, command, source, user_id=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO command_history (command, source, user_id) VALUES (?, ?, ?)',
                (command, source, user_id)
            )
            conn.commit()
    
    def get_command_history(self, limit=100, offset=0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM command_history ORDER BY timestamp DESC LIMIT ? OFFSET ?',
                (limit, offset)
            )
            return cursor.fetchall()
    
    def add_ip_to_list(self, ip_address, list_type, description=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO ip_lists (ip_address, list_type, description) VALUES (?, ?, ?)',
                    (ip_address, list_type, description)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
    
    def remove_ip_from_list(self, ip_address, list_type=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if list_type:
                cursor.execute(
                    'DELETE FROM ip_lists WHERE ip_address = ? AND list_type = ?',
                    (ip_address, list_type)
                )
            else:
                cursor.execute(
                    'DELETE FROM ip_lists WHERE ip_address = ?',
                    (ip_address,)
                )
            conn.commit()
            return cursor.rowcount > 0
    
    def get_ip_list(self, list_type=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if list_type:
                cursor.execute(
                    'SELECT * FROM ip_lists WHERE list_type = ? ORDER BY created_at DESC',
                    (list_type,)
                )
            else:
                cursor.execute('SELECT * FROM ip_lists ORDER BY created_at DESC')
            return cursor.fetchall()
    
    def add_threat_event(self, threat_type, source_ip, destination_ip, severity, description, packet_count=0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO threat_events 
                (threat_type, source_ip, destination_ip, severity, description, packet_count) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (threat_type, source_ip, destination_ip, severity, description, packet_count)
            )
            conn.commit()
    
    def add_system_event(self, event_type, message, user=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO system_events (event_type, message, user) VALUES (?, ?, ?)',
                (event_type, message, user)
            )
            conn.commit()

class SecurityUtils:
    @staticmethod
    def generate_token(length=32):
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash a password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using Fernet symmetric encryption"""
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using Fernet symmetric encryption"""
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()
    
    @staticmethod
    def validate_ip_address(ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def is_private_ip(ip):
        """Check if IP address is in private range"""
        try:
            ip_obj = socket.inet_aton(ip)
            # Check for private IP ranges
            if ip.startswith('10.') or \
               ip.startswith('192.168.') or \
               (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
               ip == '127.0.0.1':
                return True
            return False
        except:
            return False

class TelegramBotManager:
    def __init__(self, main_app):
        self.main_app = main_app
        self.db = DatabaseManager()
        self.application = None
        self.is_running = False
        self.allowed_users = set()
        self.load_config()
    
    def load_config(self):
        try:
            with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.token = config.get('token', '')
                self.chat_id = config.get('chat_id', '')
                self.allowed_users = set(config.get('allowed_users', []))
                return True
        except (FileNotFoundError, json.JSONDecodeError):
            self.token = ''
            self.chat_id = ''
            self.allowed_users = set()
            return False
    
    def save_config(self):
        config = {
            'token': self.token,
            'chat_id': self.chat_id,
            'allowed_users': list(self.allowed_users)
        }
        with open(TELEGRAM_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    
    async def start_bot(self):
        if not self.token:
            return False, "Telegram token not configured"
        
        try:
            self.application = Application.builder().token(self.token).build()
            
            # Add handlers
            self.application.add_handler(CommandHandler("start", self.start_command))
            self.application.add_handler(CommandHandler("help", self.help_command))
            self.application.add_handler(CommandHandler("ping_ip", self.ping_ip_command))
            self.application.add_handler(CommandHandler("start_monitoring_ip", self.start_monitoring_command))
            self.application.add_handler(CommandHandler("stop", self.stop_command))
            self.application.add_handler(CommandHandler("exit", self.exit_command))
            self.application.add_handler(CommandHandler("clear", self.clear_command))
            self.application.add_handler(CommandHandler("history", self.history_command))
            self.application.add_handler(CommandHandler("add_ip", self.add_ip_command))
            self.application.add_handler(CommandHandler("remove_ip", self.remove_ip_command))
            self.application.add_handler(CommandHandler("status", self.status_command))
            self.application.add_handler(CommandHandler("stats", self.stats_command))
            self.application.add_handler(CommandHandler("threats", self.threats_command))
            
            # Message handler for non-command messages
            self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
            
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            
            self.is_running = True
            self.db.add_system_event("TELEGRAM_START", "Telegram bot started successfully")
            return True, "Telegram bot started successfully"
            
        except Exception as e:
            error_msg = f"Failed to start Telegram bot: {str(e)}"
            self.db.add_system_event("TELEGRAM_ERROR", error_msg)
            return False, error_msg
    
    async def stop_bot(self):
        if self.application:
            await self.application.updater.stop()
            await self.application.stop()
            await self.application.shutdown()
            self.is_running = False
            self.db.add_system_event("TELEGRAM_STOP", "Telegram bot stopped")
            return True, "Telegram bot stopped"
        return False, "Bot not running"
    
    async def start_command(self, update, context):
        """Send welcome message when the command /start is issued."""
        user_id = update.effective_user.id
        self.allowed_users.add(user_id)
        self.save_config()
        
        welcome_text = """
🤖 *Network Based Intrusion Detection System Bot*

Welcome to the advanced cyber security monitoring system!

*Available Commands:*
/help - Show all available commands
/ping_ip [IP] - Ping a network host
/start_monitoring_ip [IP] - Start monitoring specific IP
/stop - Stop monitoring
/status - Show current monitoring status
/stats - Show statistics
/threats - Show recent threats
/add_ip [IP] [whitelist|blacklist] - Add IP to list
/remove_ip [IP] - Remove IP from list
/history - Show command history
/clear - Clear command history
/exit - Exit the bot

*Example Usage:*
/ping_ip 8.8.8.8
/start_monitoring_ip 192.168.1.100
/add_ip 192.168.1.50 whitelist
        """
        await update.message.reply_text(welcome_text, parse_mode='Markdown')
        self.db.add_command_history("/start", "telegram", user_id)
    
    async def help_command(self, update, context):
        """Send help message when the command /help is issued."""
        help_text = """
📋 *Available Commands:*

*Monitoring Commands:*
/start_monitoring_ip [IP] - Start monitoring specific IP address
/stop - Stop all monitoring
/status - Show current monitoring status

*Network Diagnostics:*
/ping_ip [IP] - Ping a network host

*Threat Management:*
/threats - Show recent security threats
/add_ip [IP] [whitelist|blacklist] - Add IP to whitelist or blacklist
/remove_ip [IP] - Remove IP from lists

*System Commands:*
/stats - Show system statistics
/history - Show command history
/clear - Clear command history
/exit - Exit the bot
/help - Show this help message

*Examples:*
/ping_ip google.com
/start_monitoring_ip 192.168.1.100
/add_ip 10.0.0.5 blacklist
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')
        self.db.add_command_history("/help", "telegram", update.effective_user.id)
    
    async def ping_ip_command(self, update, context):
        """Ping an IP address."""
        if not context.args:
            await update.message.reply_text("Usage: /ping_ip <IP_ADDRESS_OR_HOSTNAME>")
            return
        
        target = context.args[0]
        user_id = update.effective_user.id
        
        # Execute ping command
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            count = "4"
            result = subprocess.run(
                ["ping", param, count, target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                await update.message.reply_text(f"✅ Ping results for {target}:\n```\n{result.stdout}\n```", parse_mode='Markdown')
            else:
                await update.message.reply_text(f"❌ Ping failed for {target}:\n```\n{result.stderr}\n```", parse_mode='Markdown')
                
        except subprocess.TimeoutExpired:
            await update.message.reply_text(f"⏰ Ping timeout for {target}")
        except Exception as e:
            await update.message.reply_text(f"❌ Ping error: {str(e)}")
        
        self.db.add_command_history(f"/ping_ip {target}", "telegram", user_id)
    
    async def start_monitoring_command(self, update, context):
        """Start monitoring a specific IP address."""
        if not context.args:
            await update.message.reply_text("Usage: /start_monitoring_ip <IP_ADDRESS>")
            return
        
        ip_address = context.args[0]
        user_id = update.effective_user.id
        
        if not SecurityUtils.validate_ip_address(ip_address):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        # Start monitoring through main application
        success = self.main_app.start_monitoring_from_telegram(ip_address, user_id)
        
        if success:
            await update.message.reply_text(f"✅ Started monitoring IP: {ip_address}")
        else:
            await update.message.reply_text(f"❌ Failed to start monitoring IP: {ip_address}")
        
        self.db.add_command_history(f"/start_monitoring_ip {ip_address}", "telegram", user_id)
    
    async def stop_command(self, update, context):
        """Stop monitoring."""
        user_id = update.effective_user.id
        success = self.main_app.stop_monitoring_from_telegram(user_id)
        
        if success:
            await update.message.reply_text("✅ Monitoring stopped")
        else:
            await update.message.reply_text("❌ No active monitoring to stop")
        
        self.db.add_command_history("/stop", "telegram", user_id)
    
    async def exit_command(self, update, context):
        """Exit the bot."""
        user_id = update.effective_user.id
        await update.message.reply_text("👋 Goodbye! Use /start to begin again.")
        self.allowed_users.discard(user_id)
        self.save_config()
        self.db.add_command_history("/exit", "telegram", user_id)
    
    async def clear_command(self, update, context):
        """Clear command history."""
        user_id = update.effective_user.id
        
        # Clear history from database
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM command_history WHERE user_id = ?', (user_id,))
            conn.commit()
        
        await update.message.reply_text("✅ Command history cleared")
        self.db.add_command_history("/clear", "telegram", user_id)
    
    async def history_command(self, update, context):
        """Show command history."""
        user_id = update.effective_user.id
        history = self.db.get_command_history(limit=10)
        
        if not history:
            await update.message.reply_text("No command history found")
            return
        
        history_text = "📜 *Last 10 Commands:*\n\n"
        for item in history:
            timestamp = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%H:%M:%S')
            history_text += f"*{timestamp}* ({item['source']}): `{item['command']}`\n"
        
        await update.message.reply_text(history_text, parse_mode='Markdown')
        self.db.add_command_history("/history", "telegram", user_id)
    
    async def add_ip_command(self, update, context):
        """Add IP to whitelist or blacklist."""
        if len(context.args) < 2:
            await update.message.reply_text("Usage: /add_ip <IP_ADDRESS> <whitelist|blacklist> [description]")
            return
        
        ip_address = context.args[0]
        list_type = context.args[1].lower()
        description = " ".join(context.args[2:]) if len(context.args) > 2 else "Added via Telegram"
        user_id = update.effective_user.id
        
        if not SecurityUtils.validate_ip_address(ip_address):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        if list_type not in ['whitelist', 'blacklist']:
            await update.message.reply_text("❌ List type must be 'whitelist' or 'blacklist'")
            return
        
        success = self.db.add_ip_to_list(ip_address, list_type, description)
        
        if success:
            await update.message.reply_text(f"✅ Added {ip_address} to {list_type}")
            self.main_app.print_to_terminal(f"Telegram user {user_id} added {ip_address} to {list_type}")
        else:
            await update.message.reply_text(f"❌ IP {ip_address} already exists in {list_type}")
        
        self.db.add_command_history(f"/add_ip {ip_address} {list_type}", "telegram", user_id)
    
    async def remove_ip_command(self, update, context):
        """Remove IP from lists."""
        if not context.args:
            await update.message.reply_text("Usage: /remove_ip <IP_ADDRESS>")
            return
        
        ip_address = context.args[0]
        user_id = update.effective_user.id
        
        if not SecurityUtils.validate_ip_address(ip_address):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        success = self.db.remove_ip_from_list(ip_address)
        
        if success:
            await update.message.reply_text(f"✅ Removed {ip_address} from all lists")
            self.main_app.print_to_terminal(f"Telegram user {user_id} removed {ip_address} from lists")
        else:
            await update.message.reply_text(f"❌ IP {ip_address} not found in any list")
        
        self.db.add_command_history(f"/remove_ip {ip_address}", "telegram", user_id)
    
    async def status_command(self, update, context):
        """Show current monitoring status."""
        user_id = update.effective_user.id
        status = self.main_app.get_monitoring_status_for_telegram()
        await update.message.reply_text(status, parse_mode='Markdown')
        self.db.add_command_history("/status", "telegram", user_id)
    
    async def stats_command(self, update, context):
        """Show system statistics."""
        user_id = update.effective_user.id
        stats = self.main_app.get_stats_for_telegram()
        await update.message.reply_text(stats, parse_mode='Markdown')
        self.db.add_command_history("/stats", "telegram", user_id)
    
    async def threats_command(self, update, context):
        """Show recent threats."""
        user_id = update.effective_user.id
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM threat_events 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''')
            threats = cursor.fetchall()
        
        if not threats:
            await update.message.reply_text("✅ No recent threats detected")
            return
        
        threats_text = "🚨 *Recent Threats:*\n\n"
        for threat in threats:
            timestamp = datetime.strptime(threat['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%H:%M:%S')
            threats_text += f"*{timestamp}* - {threat['threat_type']}\n"
            threats_text += f"Source: `{threat['source_ip']}` → Destination: `{threat['destination_ip']}`\n"
            threats_text += f"Severity: {threat['severity']}\n"
            threats_text += f"Description: {threat['description']}\n\n"
        
        await update.message.reply_text(threats_text, parse_mode='Markdown')
        self.db.add_command_history("/threats", "telegram", user_id)
    
    async def handle_message(self, update, context):
        """Handle non-command messages."""
        user_id = update.effective_user.id
        message_text = update.message.text
        
        # Log the message
        self.db.add_command_history(f"MSG: {message_text}", "telegram", user_id)
        
        # Echo the message or process it
        response = f"Received your message: {message_text}\nUse /help to see available commands."
        await update.message.reply_text(response)

class ThreatDetector:
    def __init__(self, db_manager):
        self.db = db_manager
        self.packet_counts = defaultdict(int)
        self.port_scan_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.udp_flood_counts = defaultdict(int)
        self.threat_log = []
        self.load_threat_signatures()
        
    def load_threat_signatures(self):
        try:
            with open(THREAT_DB, 'r') as f:
                self.threat_signatures = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.threat_signatures = {
                "dos_ips": [],
                "port_scanners": [],
                "known_malicious": []
            }
    
    def save_threat_signatures(self):
        with open(THREAT_DB, 'w') as f:
            json.dump(self.threat_signatures, f, indent=4)
    
    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check if IP is in whitelist
            if self.is_ip_whitelisted(src_ip):
                return None
            
            # Check if IP is in blacklist
            if self.is_ip_blacklisted(src_ip):
                threat_msg = self.log_threat(f"Blacklisted IP detected: {src_ip}", "High", src_ip, dst_ip, "Blacklist Violation")
                return threat_msg
            
            # Count packets per source IP
            self.packet_counts[src_ip] += 1
            
            # Check for known malicious IPs
            if src_ip in self.threat_signatures["known_malicious"]:
                threat_msg = self.log_threat(f"Known malicious IP detected: {src_ip}", "High", src_ip, dst_ip, "Known Malicious IP")
                return threat_msg
            
            # Check for DOS attacks
            if self.packet_counts[src_ip] > DOS_THRESHOLD:
                if src_ip not in self.threat_signatures["dos_ips"]:
                    self.threat_signatures["dos_ips"].append(src_ip)
                threat_msg = self.log_threat(f"Possible DOS attack from {src_ip}", "High", src_ip, dst_ip, "DOS Attack", self.packet_counts[src_ip])
                return threat_msg
            
            # TCP specific checks
            if TCP in packet:
                dst_port = packet[TCP].dport
                
                # SYN flood detection
                if packet[TCP].flags == 'S':  # SYN flag
                    self.syn_counts[src_ip] += 1
                    if self.syn_counts[src_ip] > SYN_FLOOD_THRESHOLD:
                        threat_msg = self.log_threat(f"Possible SYN flood from {src_ip}", "High", src_ip, dst_ip, "SYN Flood", self.syn_counts[src_ip])
                        return threat_msg
                
                # Port scan detection
                self.port_scan_counts[(src_ip, dst_port)] += 1
                if self.port_scan_counts[(src_ip, dst_port)] > PORT_SCAN_THRESHOLD:
                    if src_ip not in self.threat_signatures["port_scanners"]:
                        self.threat_signatures["port_scanners"].append(src_ip)
                    threat_msg = self.log_threat(f"Possible port scan from {src_ip} to port {dst_port}", "Medium", src_ip, dst_ip, "Port Scan", self.port_scan_counts[(src_ip, dst_port)])
                    return threat_msg
            
            # ICMP specific checks
            elif ICMP in packet:
                self.icmp_counts[src_ip] += 1
                if self.icmp_counts[src_ip] > DOS_THRESHOLD/2:
                    threat_msg = self.log_threat(f"Possible ICMP flood (Ping of Death) from {src_ip}", "Medium", src_ip, dst_ip, "ICMP Flood", self.icmp_counts[src_ip])
                    return threat_msg
            
            # UDP specific checks
            elif UDP in packet:
                self.udp_flood_counts[src_ip] += 1
                if self.udp_flood_counts[src_ip] > DOS_THRESHOLD:
                    threat_msg = self.log_threat(f"Possible UDP flood from {src_ip}", "High", src_ip, dst_ip, "UDP Flood", self.udp_flood_counts[src_ip])
                    return threat_msg
        
        return None
    
    def is_ip_whitelisted(self, ip):
        ip_list = self.db.get_ip_list('whitelist')
        return any(item['ip_address'] == ip for item in ip_list)
    
    def is_ip_blacklisted(self, ip):
        ip_list = self.db.get_ip_list('blacklist')
        return any(item['ip_address'] == ip for item in ip_list)
    
    def log_threat(self, message, severity, src_ip, dst_ip, threat_type, packet_count=0):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity}] {message}"
        self.threat_log.append(log_entry)
        
        # Add to database
        self.db.add_threat_event(threat_type, src_ip, dst_ip, severity, message, packet_count)
        
        if len(self.threat_log) > MAX_LOG_LINES:
            self.threat_log.pop(0)
        self.save_threat_signatures()
        return log_entry

class NetworkMonitor:
    def __init__(self, detector):
        self.detector = detector
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "threats_detected": 0,
            "ports_scanned": 0,
            "dos_attempts": 0,
            "syn_floods": 0,
            "udp_floods": 0
        }
        self.interface = None
        self.target_ip = None
    
    def start_monitoring(self, interface=None, ip_address=None):
        if self.is_monitoring:
            return False
        
        self.interface = interface
        self.target_ip = ip_address
        self.is_monitoring = True
        
        # Reset stats
        self.stats = {key: 0 for key in self.stats.keys()}
        
        # Start packet processing thread
        self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.process_thread.start()
        
        # Start sniffer in a separate thread
        self.sniffer_thread = threading.Thread(
            target=self.start_sniffing,
            daemon=True
        )
        self.sniffer_thread.start()
        return True
    
    def start_sniffing(self):
        try:
            filter_str = f"host {self.target_ip}" if self.target_ip else ""
            sniff(
                prn=lambda x: self.packet_queue.put(x),
                filter=filter_str,
                iface=self.interface,
                store=False
            )
        except Exception as e:
            print(f"Sniffing error: {e}")
    
    def process_packets(self):
        while self.is_monitoring:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyze_packet(packet)
            except queue.Empty:
                continue
    
    def analyze_packet(self, packet):
        self.stats["total_packets"] += 1
        
        if IP in packet:
            if TCP in packet:
                self.stats["tcp_packets"] += 1
            elif UDP in packet:
                self.stats["udp_packets"] += 1
            elif ICMP in packet:
                self.stats["icmp_packets"] += 1
            
            # Detect threats
            threat_detected = self.detector.analyze_packet(packet)
            if threat_detected:
                self.stats["threats_detected"] += 1
                
                # Update specific threat counters
                if "DOS" in threat_detected:
                    self.stats["dos_attempts"] += 1
                elif "SYN" in threat_detected:
                    self.stats["syn_floods"] += 1
                elif "UDP" in threat_detected:
                    self.stats["udp_floods"] += 1
                elif "port scan" in threat_detected.lower():
                    self.stats["ports_scanned"] += 1
    
    def stop_monitoring(self):
        self.is_monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=1)
        return True
    
    def get_stats(self):
        return self.stats.copy()
    
    def get_monitoring_info(self):
        return {
            "is_monitoring": self.is_monitoring,
            "target_ip": self.target_ip,
            "interface": self.interface
        }

class ModernTheme:
    @staticmethod
    def setup_modern_theme():
        style = ttk.Style()
        
        # Modern dark theme colors
        dark_bg = '#1e1e1e'
        dark_fg = '#ffffff'
        dark_accent = '#007acc'
        dark_hover = '#2d2d30'
        dark_border = '#3e3e42'
        
        # Modern light theme colors  
        light_bg = '#ffffff'
        light_fg = '#323130'
        light_accent = '#0078d4'
        light_hover = '#f3f2f1'
        light_border = '#d1d1d1'
        
        # Configure styles for dark theme
        style.theme_create('modern_dark', settings={
            'TFrame': {
                'configure': {'background': dark_bg}
            },
            'TLabel': {
                'configure': {
                    'background': dark_bg,
                    'foreground': dark_fg,
                    'font': ('Segoe UI', 10)
                }
            },
            'TButton': {
                'configure': {
                    'background': dark_accent,
                    'foreground': dark_fg,
                    'borderwidth': 0,
                    'focuscolor': 'none',
                    'font': ('Segoe UI', 10, 'bold')
                },
                'map': {
                    'background': [
                        ('pressed', dark_accent),
                        ('active', dark_hover)
                    ],
                    'foreground': [('pressed', dark_fg), ('active', dark_fg)]
                }
            },
            'TEntry': {
                'configure': {
                    'fieldbackground': dark_bg,
                    'foreground': dark_fg,
                    'borderwidth': 1,
                    'insertcolor': dark_fg
                }
            },
            'TCombobox': {
                'configure': {
                    'fieldbackground': dark_bg,
                    'foreground': dark_fg,
                    'background': dark_bg
                }
            },
            'TNotebook': {
                'configure': {
                    'background': dark_bg,
                    'tabmargins': [2, 5, 2, 0]
                }
            },
            'TNotebook.Tab': {
                'configure': {
                    'background': dark_hover,
                    'foreground': dark_fg,
                    'padding': [10, 5]
                },
                'map': {
                    'background': [('selected', dark_accent)],
                    'expand': [('selected', [1, 1, 1, 0])]
                }
            },
            'TLabelframe': {
                'configure': {
                    'background': dark_bg,
                    'foreground': dark_fg,
                    'borderwidth': 1,
                    'relief': 'groove'
                }
            },
            'TLabelframe.Label': {
                'configure': {
                    'background': dark_bg,
                    'foreground': dark_accent,
                    'font': ('Segoe UI', 10, 'bold')
                }
            },
            'Horizontal.TProgressbar': {
                'configure': {
                    'background': dark_accent,
                    'troughcolor': dark_border
                }
            }
        })
        
        # Configure styles for light theme
        style.theme_create('modern_light', settings={
            'TFrame': {
                'configure': {'background': light_bg}
            },
            'TLabel': {
                'configure': {
                    'background': light_bg,
                    'foreground': light_fg,
                    'font': ('Segoe UI', 10)
                }
            },
            'TButton': {
                'configure': {
                    'background': light_accent,
                    'foreground': 'white',
                    'borderwidth': 0,
                    'focuscolor': 'none',
                    'font': ('Segoe UI', 10, 'bold')
                },
                'map': {
                    'background': [
                        ('pressed', light_accent),
                        ('active', '#106ebe')
                    ]
                }
            },
            'TEntry': {
                'configure': {
                    'fieldbackground': light_bg,
                    'foreground': light_fg,
                    'borderwidth': 1,
                    'insertcolor': light_fg
                }
            },
            'TCombobox': {
                'configure': {
                    'fieldbackground': light_bg,
                    'foreground': light_fg,
                    'background': light_bg
                }
            },
            'TNotebook': {
                'configure': {
                    'background': light_bg,
                    'tabmargins': [2, 5, 2, 0]
                }
            },
            'TNotebook.Tab': {
                'configure': {
                    'background': light_hover,
                    'foreground': light_fg,
                    'padding': [10, 5]
                },
                'map': {
                    'background': [('selected', light_accent)],
                    'foreground': [('selected', 'white')],
                    'expand': [('selected', [1, 1, 1, 0])]
                }
            },
            'TLabelframe': {
                'configure': {
                    'background': light_bg,
                    'foreground': light_fg,
                    'borderwidth': 1,
                    'relief': 'groove'
                }
            },
            'TLabelframe.Label': {
                'configure': {
                    'background': light_bg,
                    'foreground': light_accent,
                    'font': ('Segoe UI', 10, 'bold')
                }
            },
            'Horizontal.TProgressbar': {
                'configure': {
                    'background': light_accent,
                    'troughcolor': light_border
                }
            }
        })

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Advanced Network Based Intrusion Detection System v{VERSION}")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Initialize database
        self.db = DatabaseManager()
        
        # Configuration
        self.config = self.load_config()
        self.dark_mode = self.config.get("dark_mode", True)
        self.recent_ips = self.config.get("recent_ips", [])
        self.command_history = deque(maxlen=MAX_COMMAND_HISTORY)
        self.load_command_history()
        
        # Setup modern theme
        ModernTheme.setup_modern_theme()
        
        # Threat detector and monitor
        self.detector = ThreatDetector(self.db)
        self.monitor = NetworkMonitor(self.detector)
        
        # Telegram bot manager
        self.telegram_bot = TelegramBotManager(self)
        
        # Setup GUI
        self.setup_menu()
        self.setup_main_frame()
        self.setup_dashboard()
        self.setup_terminal()
        self.setup_status_bar()
        
        # Apply theme
        self.apply_theme()
        
        # Start stats update loop
        self.update_stats()
        
        # Initialize Telegram bot if configured
        self.initialize_telegram_bot()
    
    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                "dark_mode": self.dark_mode,
                "recent_ips": self.recent_ips
            }, f, indent=4)
    
    def load_command_history(self):
        try:
            with open(COMMAND_HISTORY_FILE, 'rb') as f:
                history = pickle.load(f)
                self.command_history.extend(history)
        except (FileNotFoundError, pickle.PickleError):
            pass
    
    def save_command_history(self):
        with open(COMMAND_HISTORY_FILE, 'wb') as f:
            pickle.dump(list(self.command_history), f)
    
    def add_to_command_history(self, command):
        self.command_history.append(command)
        self.save_command_history()
    
    def initialize_telegram_bot(self):
        if self.telegram_bot.token:
            threading.Thread(
                target=self.start_telegram_bot_async,
                daemon=True
            ).start()
    
    def start_telegram_bot_async(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.telegram_bot.start_bot())
        except Exception as e:
            self.print_to_terminal(f"Failed to start Telegram bot: {e}")
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Monitoring Session", command=self.new_session)
        file_menu.add_command(label="Save Threat Log", command=self.save_threat_log)
        file_menu.add_separator()
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_command(label="Import Data", command=self.import_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Dark/Light Mode", command=self.toggle_theme)
        view_menu.add_command(label="Reset Dashboard", command=self.reset_dashboard)
        view_menu.add_separator()
        view_menu.add_command(label="Show Command History", command=self.show_command_history)
        view_menu.add_command(label="Clear Command History", command=self.clear_command_history)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_separator()
        tools_menu.add_command(label="IP Management", command=self.open_ip_management)
        tools_menu.add_command(label="Threat Analysis", command=self.open_threat_analysis)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Telegram menu
        telegram_menu = tk.Menu(menubar, tearoff=0)
        telegram_menu.add_command(label="Configure Telegram", command=self.configure_telegram)
        telegram_menu.add_command(label="Test Telegram Connection", command=self.test_telegram_connection)
        telegram_menu.add_command(label="Start Telegram Bot", command=self.start_telegram_bot)
        telegram_menu.add_command(label="Stop Telegram Bot", command=self.stop_telegram_bot)
        telegram_menu.add_separator()
        telegram_menu.add_command(label="Telegram Status", command=self.show_telegram_status)
        menubar.add_cascade(label="Telegram", menu=telegram_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_keyboard_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create paned window for resizable sections
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left pane (dashboard)
        self.left_pane = ttk.Frame(self.paned_window, width=500)
        self.paned_window.add(self.left_pane, weight=1)
        
        # Right pane (terminal and logs)
        self.right_pane = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_pane, weight=2)
    
    def setup_dashboard(self):
        # Notebook for multiple dashboard tabs
        self.dashboard_notebook = ttk.Notebook(self.left_pane)
        self.dashboard_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Overview tab
        self.overview_tab = ttk.Frame(self.dashboard_notebook)
        self.dashboard_notebook.add(self.overview_tab, text="📊 Overview")
        
        # System status frame
        status_frame = ttk.LabelFrame(self.overview_tab, text="System Status")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Monitoring status
        monitoring_status_frame = ttk.Frame(status_frame)
        monitoring_status_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(monitoring_status_frame, text="Monitoring:").pack(side=tk.LEFT)
        self.monitoring_status_label = ttk.Label(
            monitoring_status_frame, 
            text="❌ Inactive", 
            foreground="red",
            font=('Segoe UI', 10, 'bold')
        )
        self.monitoring_status_label.pack(side=tk.RIGHT)
        
        # Telegram status
        telegram_status_frame = ttk.Frame(status_frame)
        telegram_status_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(telegram_status_frame, text="Telegram Bot:").pack(side=tk.LEFT)
        self.telegram_status_label = ttk.Label(
            telegram_status_frame, 
            text="❌ Inactive", 
            foreground="red",
            font=('Segoe UI', 10, 'bold')
        )
        self.telegram_status_label.pack(side=tk.RIGHT)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.overview_tab, text="Real-time Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_labels = {}
        stats = [
            ("Total Packets", "total_packets"),
            ("TCP Packets", "tcp_packets"),
            ("UDP Packets", "udp_packets"),
            ("ICMP Packets", "icmp_packets"),
            ("Threats Detected", "threats_detected"),
            ("DOS Attempts", "dos_attempts"),
            ("Port Scans", "ports_scanned"),
            ("SYN Floods", "syn_floods"),
            ("UDP Floods", "udp_floods")
        ]
        
        for i, (label, key) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=i//3, column=i%3, sticky="ew", padx=5, pady=3)
            ttk.Label(frame, text=f"{label}:").pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(
                frame, 
                text="0", 
                width=8,
                font=('Segoe UI', 9, 'bold'),
                foreground="#007acc"
            )
            self.stats_labels[key].pack(side=tk.RIGHT)
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(self.overview_tab, text="Monitoring Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ip_entry = ttk.Combobox(control_frame, values=self.recent_ips, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(control_frame, text="Interface:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        self.interface_combobox = ttk.Combobox(
            control_frame, 
            textvariable=self.interface_var,
            values=interfaces,
            state="readonly",
            width=20
        )
        if interfaces:
            self.interface_var.set(interfaces[0])
        self.interface_combobox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        
        self.start_button = ttk.Button(
            button_frame, 
            text="▶ Start Monitoring", 
            command=self.start_monitoring
        )
        self.start_button.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="⏹ Stop Monitoring", 
            command=self.stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Quick actions frame
        quick_actions_frame = ttk.LabelFrame(self.overview_tab, text="Quick Actions")
        quick_actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        action_buttons = [
            ("📡 Ping IP", self.quick_ping),
            ("🔍 Scan Network", self.quick_scan),
            ("📊 View Stats", self.quick_stats),
            ("🚨 View Threats", self.quick_threats)
        ]
        
        for i, (text, command) in enumerate(action_buttons):
            btn = ttk.Button(
                quick_actions_frame,
                text=text,
                command=command
            )
            btn.grid(row=i//2, column=i%2, padx=5, pady=3, sticky="ew")
        
        # Charts frame
        charts_frame = ttk.Frame(self.overview_tab)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet type pie chart
        self.pie_frame = ttk.LabelFrame(charts_frame, text="📈 Packet Types Distribution")
        self.pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(5, 4), dpi=80)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=self.pie_frame)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threats bar chart
        self.bar_frame = ttk.LabelFrame(charts_frame, text="🚨 Detected Threats")
        self.bar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(5, 4), dpi=80)
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=self.bar_frame)
        self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threats tab
        self.threats_tab = ttk.Frame(self.dashboard_notebook)
        self.dashboard_notebook.add(self.threats_tab, text="🚨 Threat Log")
        
        # Threat log controls
        threat_controls_frame = ttk.Frame(self.threats_tab)
        threat_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            threat_controls_frame, 
            text="🔄 Refresh", 
            command=self.update_threat_log
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            threat_controls_frame, 
            text="🗑️ Clear", 
            command=self.clear_threat_log
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            threat_controls_frame, 
            text="💾 Export", 
            command=self.export_threat_log
        ).pack(side=tk.LEFT)
        
        self.threat_log = scrolledtext.ScrolledText(
            self.threats_tab,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 9)
        )
        self.threat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # IP Management tab
        self.ip_management_tab = ttk.Frame(self.dashboard_notebook)
        self.dashboard_notebook.add(self.ip_management_tab, text="🌐 IP Management")
        
        self.setup_ip_management()
        
        # Update charts with initial data
        self.update_charts()
    
    def setup_ip_management(self):
        # IP Management controls
        ip_controls_frame = ttk.LabelFrame(self.ip_management_tab, text="IP List Management")
        ip_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ip_controls_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ip_management_entry = ttk.Entry(ip_controls_frame, width=20)
        self.ip_management_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(ip_controls_frame, text="List Type:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.ip_list_type = tk.StringVar(value="whitelist")
        ttk.Combobox(
            ip_controls_frame,
            textvariable=self.ip_list_type,
            values=["whitelist", "blacklist"],
            state="readonly",
            width=15
        ).grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        ttk.Label(ip_controls_frame, text="Description:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ip_description_entry = ttk.Entry(ip_controls_frame, width=20)
        self.ip_description_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        
        button_frame = ttk.Frame(ip_controls_frame)
        button_frame.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            button_frame,
            text="➕ Add IP",
            command=self.add_ip_to_list
        ).pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        ttk.Button(
            button_frame,
            text="➖ Remove IP",
            command=self.remove_ip_from_list
        ).pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        ttk.Button(
            button_frame,
            text="🔄 Refresh Lists",
            command=self.refresh_ip_lists
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # IP Lists display
        lists_frame = ttk.Frame(self.ip_management_tab)
        lists_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Whitelist frame
        whitelist_frame = ttk.LabelFrame(lists_frame, text="✅ Whitelisted IPs")
        whitelist_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.whitelist_tree = ttk.Treeview(
            whitelist_frame,
            columns=('ip', 'description', 'added'),
            show='headings',
            height=10
        )
        self.whitelist_tree.heading('ip', text='IP Address')
        self.whitelist_tree.heading('description', text='Description')
        self.whitelist_tree.heading('added', text='Added')
        
        self.whitelist_tree.column('ip', width=120)
        self.whitelist_tree.column('description', width=200)
        self.whitelist_tree.column('added', width=120)
        
        whitelist_scrollbar = ttk.Scrollbar(whitelist_frame, orient=tk.VERTICAL, command=self.whitelist_tree.yview)
        self.whitelist_tree.configure(yscrollcommand=whitelist_scrollbar.set)
        self.whitelist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Blacklist frame
        blacklist_frame = ttk.LabelFrame(lists_frame, text="❌ Blacklisted IPs")
        blacklist_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.blacklist_tree = ttk.Treeview(
            blacklist_frame,
            columns=('ip', 'description', 'added'),
            show='headings',
            height=10
        )
        self.blacklist_tree.heading('ip', text='IP Address')
        self.blacklist_tree.heading('description', text='Description')
        self.blacklist_tree.heading('added', text='Added')
        
        self.blacklist_tree.column('ip', width=120)
        self.blacklist_tree.column('description', width=200)
        self.blacklist_tree.column('added', width=120)
        
        blacklist_scrollbar = ttk.Scrollbar(blacklist_frame, orient=tk.VERTICAL, command=self.blacklist_tree.yview)
        self.blacklist_tree.configure(yscrollcommand=blacklist_scrollbar.set)
        self.blacklist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        blacklist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load initial IP lists
        self.refresh_ip_lists()
    
    def setup_terminal(self):
        terminal_frame = ttk.LabelFrame(self.right_pane, text="💻 Command Terminal")
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 10),
            height=20
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Command input with history navigation
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Label(input_frame, text="➜").pack(side=tk.LEFT, padx=(0, 5))
        self.command_entry = ttk.Entry(input_frame, font=('Consolas', 10))
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.bind("<Return>", self.execute_command)
        self.command_entry.bind("<Up>", self.command_history_up)
        self.command_entry.bind("<Down>", self.command_history_down)
        
        # Add some help text
        self.print_to_terminal("🚀 Advanced Network Based Intrusion Detection System v2.0")
        self.print_to_terminal("Type 'help' for available commands or use the menu for advanced features\n")
    
    def setup_status_bar(self):
        self.status_bar = ttk.Frame(self.root, height=25)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(
            self.status_bar, 
            text="✅ System Ready", 
            relief=tk.SUNKEN,
            anchor=tk.W,
            font=('Segoe UI', 9)
        )
        self.status_label.pack(fill=tk.X, side=tk.LEFT, padx=2)
        
        self.monitoring_status = ttk.Label(
            self.status_bar,
            text="📡 Not Monitoring",
            relief=tk.SUNKEN,
            anchor=tk.W,
            width=20,
            font=('Segoe UI', 9)
        )
        self.monitoring_status.pack(side=tk.RIGHT, fill=tk.Y, padx=2)
        
        self.telegram_bot_status = ttk.Label(
            self.status_bar,
            text="🤖 Telegram: Inactive",
            relief=tk.SUNKEN,
            anchor=tk.W,
            width=20,
            font=('Segoe UI', 9)
        )
        self.telegram_bot_status.pack(side=tk.RIGHT, fill=tk.Y, padx=2)
    
    def apply_theme(self):
        theme_name = 'modern_dark' if self.dark_mode else 'modern_light'
        style = ttk.Style()
        style.theme_use(theme_name)
        
        # Configure text widgets based on theme
        if self.dark_mode:
            self.terminal_output.config(
                bg='#1e1e1e',
                fg='#00ff00',
                insertbackground='#00ff00',
                selectbackground='#363636'
            )
            self.threat_log.config(
                bg='#1e1e1e',
                fg='#ffffff',
                insertbackground='#ffffff',
                selectbackground='#363636'
            )
            
            # Configure matplotlib charts for dark theme
            self.pie_ax.set_facecolor('#1e1e1e')
            self.pie_fig.patch.set_facecolor('#1e1e1e')
            self.pie_ax.tick_params(colors='white')
            self.pie_ax.title.set_color('white')
            
            self.bar_ax.set_facecolor('#1e1e1e')
            self.bar_fig.patch.set_facecolor('#1e1e1e')
            self.bar_ax.tick_params(colors='white')
            self.bar_ax.title.set_color('white')
        else:
            self.terminal_output.config(
                bg='black',
                fg='#00ff00',
                insertbackground='#00ff00',
                selectbackground='#cccccc'
            )
            self.threat_log.config(
                bg='white',
                fg='black',
                insertbackground='black',
                selectbackground='#cccccc'
            )
            
            # Configure matplotlib charts for light theme
            self.pie_ax.set_facecolor('white')
            self.pie_fig.patch.set_facecolor('white')
            self.pie_ax.tick_params(colors='black')
            self.pie_ax.title.set_color('black')
            
            self.bar_ax.set_facecolor('white')
            self.bar_fig.patch.set_facecolor('white')
            self.bar_ax.tick_params(colors='black')
            self.bar_ax.title.set_color('black')
        
        self.pie_canvas.draw()
        self.bar_canvas.draw()
        
        # Update status bar colors
        if self.dark_mode:
            self.status_bar.configure(style='Dark.TFrame')
        else:
            self.status_bar.configure(style='TFrame')
    
    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.save_config()
        self.apply_theme()
        status = "Dark" if self.dark_mode else "Light"
        self.print_to_terminal(f"Theme changed to {status} mode")
    
    def get_network_interfaces(self):
        try:
            interfaces = netifaces.interfaces()
            return [iface for iface in interfaces if iface != 'lo']
        except:
            return ["eth0", "wlan0", "en0"]  # Fallback interfaces
    
    def start_monitoring(self):
        ip_address = self.ip_entry.get().strip()
        if not ip_address:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        if not SecurityUtils.validate_ip_address(ip_address):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        if ip_address not in self.recent_ips:
            self.recent_ips.append(ip_address)
            self.ip_entry['values'] = self.recent_ips
            self.save_config()
        
        if self.monitor.start_monitoring(interface, ip_address):
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.monitoring_status_label.config(text="✅ Active", foreground="green")
            self.monitoring_status.config(text=f"📡 Monitoring {ip_address}")
            self.print_to_terminal(f"🚀 Started monitoring {ip_address} on interface {interface}")
            self.update_status(f"Monitoring {ip_address}")
            self.db.add_system_event("MONITORING_START", f"Started monitoring {ip_address}")
        else:
            messagebox.showerror("Error", "Monitoring is already in progress")
    
    def start_monitoring_from_telegram(self, ip_address, user_id):
        """Start monitoring from Telegram bot"""
        interface = self.interface_var.get()
        if not interface:
            interface = self.get_network_interfaces()[0] if self.get_network_interfaces() else "eth0"
        
        if self.monitor.start_monitoring(interface, ip_address):
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.monitoring_status_label.config(text="✅ Active", foreground="green")
            self.monitoring_status.config(text=f"📡 Monitoring {ip_address}")
            self.print_to_terminal(f"🤖 Telegram user {user_id} started monitoring {ip_address}")
            self.update_status(f"Monitoring {ip_address} (via Telegram)")
            self.db.add_system_event("MONITORING_START", f"Telegram user {user_id} started monitoring {ip_address}")
            return True
        return False
    
    def stop_monitoring(self):
        if self.monitor.stop_monitoring():
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.monitoring_status_label.config(text="❌ Inactive", foreground="red")
            self.monitoring_status.config(text="📡 Not Monitoring")
            self.print_to_terminal("⏹ Monitoring stopped")
            self.update_status("Ready")
            self.db.add_system_event("MONITORING_STOP", "Monitoring stopped by user")
            return True
        return False
    
    def stop_monitoring_from_telegram(self, user_id):
        """Stop monitoring from Telegram bot"""
        if self.monitor.stop_monitoring():
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.monitoring_status_label.config(text="❌ Inactive", foreground="red")
            self.monitoring_status.config(text="📡 Not Monitoring")
            self.print_to_terminal(f"🤖 Telegram user {user_id} stopped monitoring")
            self.update_status("Ready")
            self.db.add_system_event("MONITORING_STOP", f"Telegram user {user_id} stopped monitoring")
            return True
        return False
    
    def update_stats(self):
        # Update monitoring status
        if self.monitor.is_monitoring:
            stats = self.monitor.get_stats()
            
            # Update stats labels
            for key, label in self.stats_labels.items():
                label.config(text=str(stats.get(key, 0)))
            
            # Update charts
            self.update_charts()
            
            # Update threat log
            self.update_threat_log()
        
        # Update Telegram bot status
        telegram_status = "✅ Active" if self.telegram_bot.is_running else "❌ Inactive"
        telegram_color = "green" if self.telegram_bot.is_running else "red"
        self.telegram_status_label.config(text=telegram_status, foreground=telegram_color)
        self.telegram_bot_status.config(
            text=f"🤖 Telegram: {'Active' if self.telegram_bot.is_running else 'Inactive'}"
        )
        
        # Schedule next update
        self.root.after(UPDATE_INTERVAL * 1000, self.update_stats)
    
    def update_charts(self):
        stats = self.monitor.get_stats()
        
        # Update pie chart
        self.pie_ax.clear()
        if stats["total_packets"] > 0:
            labels = ['TCP', 'UDP', 'ICMP', 'Other']
            sizes = [
                stats["tcp_packets"],
                stats["udp_packets"],
                stats["icmp_packets"],
                max(0, stats["total_packets"] - stats["tcp_packets"] - stats["udp_packets"] - stats["icmp_packets"])
            ]
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
            self.pie_ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            self.pie_ax.axis('equal')
            self.pie_ax.set_title('Packet Types Distribution')
        
        # Update bar chart
        self.bar_ax.clear()
        threat_types = ['DOS', 'Port Scans', 'SYN Flood', 'UDP Flood']
        threat_counts = [
            stats.get("dos_attempts", 0),
            stats.get("ports_scanned", 0),
            stats.get("syn_floods", 0),
            stats.get("udp_floods", 0)
        ]
        
        if any(threat_counts):
            colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
            bars = self.bar_ax.bar(threat_types, threat_counts, color=colors)
            self.bar_ax.set_title('Detected Threats')
            self.bar_ax.set_ylabel('Count')
            
            # Add value labels on bars
            for bar, count in zip(bars, threat_counts):
                height = bar.get_height()
                self.bar_ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                                f'{count}', ha='center', va='bottom')
        
        self.pie_canvas.draw()
        self.bar_canvas.draw()
    
    def update_threat_log(self):
        if not self.detector.threat_log:
            return
        
        self.threat_log.config(state=tk.NORMAL)
        self.threat_log.delete(1.0, tk.END)
        
        for entry in self.detector.threat_log[-MAX_LOG_LINES:]:
            self.threat_log.insert(tk.END, entry + "\n")
        
        self.threat_log.config(state=tk.DISABLED)
        self.threat_log.see(tk.END)
    
    def clear_threat_log(self):
        self.detector.threat_log.clear()
        self.threat_log.config(state=tk.NORMAL)
        self.threat_log.delete(1.0, tk.END)
        self.threat_log.config(state=tk.DISABLED)
        self.print_to_terminal("Threat log cleared")
    
    def print_to_terminal(self, text):
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, text + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    def update_status(self, message):
        self.status_label.config(text=message)
    
    # Command history navigation
    def command_history_up(self, event):
        if hasattr(self, '_history_index'):
            self._history_index -= 1
            if self._history_index < 0:
                self._history_index = 0
            else:
                self.command_entry.delete(0, tk.END)
                self.command_entry.insert(0, self.command_history[self._history_index])
        elif self.command_history:
            self._history_index = len(self.command_history) - 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self._history_index])
        return "break"
    
    def command_history_down(self, event):
        if hasattr(self, '_history_index'):
            self._history_index += 1
            if self._history_index >= len(self.command_history):
                self._history_index = len(self.command_history)
                self.command_entry.delete(0, tk.END)
            else:
                self.command_entry.delete(0, tk.END)
                self.command_entry.insert(0, self.command_history[self._history_index])
        return "break"
    
    def execute_command(self, event=None):
        command = self.command_entry.get().strip()
        self.command_entry.delete(0, tk.END)
        
        if not command:
            return
        
        # Add to command history
        self.add_to_command_history(command)
        self.db.add_command_history(command, "terminal")
        
        self.print_to_terminal(f"➜ {command}")
        
        # Remove history index attribute after command execution
        if hasattr(self, '_history_index'):
            delattr(self, '_history_index')
        
        # Parse and execute command
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "help":
            self.show_help()
        elif cmd == "ping" and len(parts) > 1:
            self.run_ping(' '.join(parts[1:]))
        elif cmd == "start" and len(parts) > 2 and parts[1].lower() == "monitoring":
            ip = parts[2]
            self.ip_entry.set(ip)
            self.start_monitoring()
        elif cmd == "stop":
            self.stop_monitoring()
        elif cmd == "exit":
            self.on_closing()
        elif cmd == "clear":
            self.terminal_output.config(state=tk.NORMAL)
            self.terminal_output.delete(1.0, tk.END)
            self.terminal_output.config(state=tk.DISABLED)
        elif cmd == "history":
            self.show_command_history()
        elif cmd == "config" and len(parts) > 2:
            if parts[1].lower() == "telegram" and parts[2].lower() == "token":
                token = ' '.join(parts[3:]) if len(parts) > 3 else ""
                self.config_telegram_token(token)
            elif parts[1].lower() == "telegram" and parts[2].lower() == "chat_id":
                chat_id = ' '.join(parts[3:]) if len(parts) > 3 else ""
                self.config_telegram_chat_id(chat_id)
        elif cmd == "test" and len(parts) > 1 and parts[1].lower() == "telegram":
            self.test_telegram_connection()
        elif cmd == "add" and len(parts) > 2 and parts[1].lower() == "ip":
            ip = parts[2]
            list_type = parts[3] if len(parts) > 3 else "whitelist"
            description = ' '.join(parts[4:]) if len(parts) > 4 else "Added via terminal"
            self.add_ip_to_list_gui(ip, list_type, description)
        elif cmd == "remove" and len(parts) > 2 and parts[1].lower() == "ip":
            ip = parts[2]
            self.remove_ip_from_list_gui(ip)
        else:
            self.print_to_terminal(f"❌ Unknown command: {command}")
            self.print_to_terminal("Type 'help' for available commands")
    
    def show_help(self):
        help_text = """
🤖 *Advanced Cyber Security Monitor Commands:*

*Basic Commands:*
  help                           - Show this help message
  ping <IP>                      - Ping a network host
  start monitoring <IP>          - Start monitoring specific IP address
  stop                           - Stop monitoring
  exit                           - Exit the application
  clear                          - Clear terminal output
  history                        - Show command history

*Telegram Commands:*
  config telegram token <TOKEN>  - Configure Telegram bot token
  config telegram chat_id <ID>   - Configure Telegram chat ID
  test telegram                  - Test Telegram connection

*IP Management Commands:*
  add ip <IP> [list_type] [desc] - Add IP to whitelist/blacklist
  remove ip <IP>                 - Remove IP from lists

*Network Commands:*
  netstat                        - Show network statistics
  net share                      - Show shared resources (Windows)
  ifconfig [/all]                - Show network interface configuration
  nmap --script vuln <target>    - Scan for vulnerabilities

*Examples:*
  ping 8.8.8.8
  start monitoring 192.168.1.100
  add ip 10.0.0.5 blacklist "Suspicious IP"
  config telegram token 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
"""
        self.print_to_terminal(help_text)
    
    def run_ping(self, target):
        if not target:
            self.print_to_terminal("Usage: ping <IP_ADDRESS_OR_HOSTNAME>")
            return
        
        self.print_to_terminal(f"Pinging {target}...")
        
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            count = "4"
            result = subprocess.run(
                ["ping", param, count, target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.print_to_terminal(f"✅ Ping successful:\n{result.stdout}")
            else:
                self.print_to_terminal(f"❌ Ping failed:\n{result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.print_to_terminal(f"⏰ Ping timeout for {target}")
        except Exception as e:
            self.print_to_terminal(f"❌ Ping error: {str(e)}")
    
    def show_command_history(self):
        history = list(self.command_history)[-20:]  # Show last 20 commands
        if not history:
            self.print_to_terminal("No command history")
            return
        
        self.print_to_terminal("📜 Command History (last 20 commands):")
        for i, cmd in enumerate(history, 1):
            self.print_to_terminal(f"  {i:2d}. {cmd}")
    
    def clear_command_history(self):
        self.command_history.clear()
        self.save_command_history()
        self.print_to_terminal("Command history cleared")
    
    def config_telegram_token(self, token):
        if not token:
            self.print_to_terminal("Usage: config telegram token <YOUR_BOT_TOKEN>")
            return
        
        self.telegram_bot.token = token
        self.telegram_bot.save_config()
        self.print_to_terminal("✅ Telegram token configured")
        
        # Try to restart bot with new token
        if self.telegram_bot.is_running:
            self.stop_telegram_bot()
        self.start_telegram_bot()
    
    def config_telegram_chat_id(self, chat_id):
        if not chat_id:
            self.print_to_terminal("Usage: config telegram chat_id <YOUR_CHAT_ID>")
            return
        
        self.telegram_bot.chat_id = chat_id
        self.telegram_bot.save_config()
        self.print_to_terminal("✅ Telegram chat ID configured")
    
    def test_telegram_connection(self):
        if not self.telegram_bot.token:
            self.print_to_terminal("❌ Telegram token not configured")
            return
        
        try:
            bot = telegram.Bot(token=self.telegram_bot.token)
            user = bot.get_me()
            self.print_to_terminal(f"✅ Telegram connection successful!")
            self.print_to_terminal(f"   Bot Name: {user.first_name}")
            self.print_to_terminal(f"   Bot Username: @{user.username}")
            self.print_to_terminal(f"   Bot ID: {user.id}")
            
            if self.telegram_bot.chat_id:
                self.print_to_terminal(f"   Chat ID: {self.telegram_bot.chat_id}")
            else:
                self.print_to_terminal("   ⚠️  Chat ID not configured")
                
        except Exception as e:
            self.print_to_terminal(f"❌ Telegram connection failed: {str(e)}")
    
    def configure_telegram(self):
        dialog = TelegramConfigDialog(self.root, self.telegram_bot, self)
        self.root.wait_window(dialog.top)
    
    def start_telegram_bot(self):
        if self.telegram_bot.is_running:
            self.print_to_terminal("⚠️  Telegram bot is already running")
            return
        
        if not self.telegram_bot.token:
            self.print_to_terminal("❌ Telegram token not configured. Please configure it first.")
            return
        
        threading.Thread(
            target=self.start_telegram_bot_async,
            daemon=True
        ).start()
    
    def start_telegram_bot_async(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            success, message = loop.run_until_complete(self.telegram_bot.start_bot())
            self.print_to_terminal(f"🤖 {message}")
        except Exception as e:
            self.print_to_terminal(f"❌ Failed to start Telegram bot: {e}")
    
    def stop_telegram_bot(self):
        if not self.telegram_bot.is_running:
            self.print_to_terminal("⚠️  Telegram bot is not running")
            return
        
        threading.Thread(
            target=self.stop_telegram_bot_async,
            daemon=True
        ).start()
    
    def stop_telegram_bot_async(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            success, message = loop.run_until_complete(self.telegram_bot.stop_bot())
            self.print_to_terminal(f"🤖 {message}")
        except Exception as e:
            self.print_to_terminal(f"❌ Failed to stop Telegram bot: {e}")
    
    def show_telegram_status(self):
        status = "✅ Active" if self.telegram_bot.is_running else "❌ Inactive"
        token_status = "✅ Configured" if self.telegram_bot.token else "❌ Not configured"
        chat_status = "✅ Configured" if self.telegram_bot.chat_id else "❌ Not configured"
        
        status_text = f"""
🤖 Telegram Bot Status:
  Bot Status: {status}
  Token: {token_status}
  Chat ID: {chat_status}
  Allowed Users: {len(self.telegram_bot.allowed_users)}
  
  Commands available via Telegram:
  /start, /help, /ping_ip, /start_monitoring_ip, /stop, /status, /stats, /threats, /add_ip, /remove_ip, /history, /clear, /exit
"""
        self.print_to_terminal(status_text)
    
    def add_ip_to_list(self):
        ip = self.ip_management_entry.get().strip()
        list_type = self.ip_list_type.get()
        description = self.ip_description_entry.get().strip() or "Added via GUI"
        
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        if not SecurityUtils.validate_ip_address(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        success = self.db.add_ip_to_list(ip, list_type, description)
        
        if success:
            self.print_to_terminal(f"✅ Added {ip} to {list_type}")
            self.ip_management_entry.delete(0, tk.END)
            self.ip_description_entry.delete(0, tk.END)
            self.refresh_ip_lists()
        else:
            messagebox.showerror("Error", f"IP {ip} already exists in {list_type}")
    
    def add_ip_to_list_gui(self, ip, list_type="whitelist", description="Added via terminal"):
        if not SecurityUtils.validate_ip_address(ip):
            self.print_to_terminal(f"❌ Invalid IP address format: {ip}")
            return
        
        if list_type not in ['whitelist', 'blacklist']:
            self.print_to_terminal(f"❌ Invalid list type. Use 'whitelist' or 'blacklist'")
            return
        
        success = self.db.add_ip_to_list(ip, list_type, description)
        
        if success:
            self.print_to_terminal(f"✅ Added {ip} to {list_type}")
            self.refresh_ip_lists()
        else:
            self.print_to_terminal(f"❌ IP {ip} already exists in {list_type}")
    
    def remove_ip_from_list(self):
        ip = self.ip_management_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        success = self.db.remove_ip_from_list(ip)
        
        if success:
            self.print_to_terminal(f"✅ Removed {ip} from all lists")
            self.ip_management_entry.delete(0, tk.END)
            self.refresh_ip_lists()
        else:
            messagebox.showerror("Error", f"IP {ip} not found in any list")
    
    def remove_ip_from_list_gui(self, ip):
        if not SecurityUtils.validate_ip_address(ip):
            self.print_to_terminal(f"❌ Invalid IP address format: {ip}")
            return
        
        success = self.db.remove_ip_from_list(ip)
        
        if success:
            self.print_to_terminal(f"✅ Removed {ip} from all lists")
            self.refresh_ip_lists()
        else:
            self.print_to_terminal(f"❌ IP {ip} not found in any list")
    
    def refresh_ip_lists(self):
        # Clear existing items
        for tree in [self.whitelist_tree, self.blacklist_tree]:
            for item in tree.get_children():
                tree.delete(item)
        
        # Load whitelisted IPs
        whitelist = self.db.get_ip_list('whitelist')
        for item in whitelist:
            self.whitelist_tree.insert('', tk.END, values=(
                item['ip_address'],
                item['description'],
                item['created_at'][:16]  # Shorten timestamp
            ))
        
        # Load blacklisted IPs
        blacklist = self.db.get_ip_list('blacklist')
        for item in blacklist:
            self.blacklist_tree.insert('', tk.END, values=(
                item['ip_address'],
                item['description'],
                item['created_at'][:16]  # Shorten timestamp
            ))
    
    def get_monitoring_status_for_telegram(self):
        if self.monitor.is_monitoring:
            stats = self.monitor.get_stats()
            info = self.monitor.get_monitoring_info()
            
            status_text = f"""
📊 *Monitoring Status: ACTIVE*

*Target Information:*
  • IP Address: `{info['target_ip']}`
  • Interface: `{info['interface']}`

*Current Statistics:*
  • Total Packets: `{stats['total_packets']}`
  • TCP Packets: `{stats['tcp_packets']}`
  • UDP Packets: `{stats['udp_packets']}`
  • ICMP Packets: `{stats['icmp_packets']}`
  • Threats Detected: `{stats['threats_detected']}`
  • DOS Attempts: `{stats['dos_attempts']}`
  • Port Scans: `{stats['ports_scanned']}`
"""
        else:
            status_text = """
📊 *Monitoring Status: INACTIVE*

No active monitoring session.
Use `/start_monitoring_ip <IP>` to start monitoring.
"""
        
        return status_text
    
    def get_stats_for_telegram(self):
        stats = self.monitor.get_stats()
        
        stats_text = f"""
📈 *System Statistics*

*Packet Statistics:*
  • Total Packets: `{stats['total_packets']}`
  • TCP Packets: `{stats['tcp_packets']}`
  • UDP Packets: `{stats['udp_packets']}`
  • ICMP Packets: `{stats['icmp_packets']}`

*Threat Statistics:*
  • Total Threats: `{stats['threats_detected']}`
  • DOS Attempts: `{stats['dos_attempts']}`
  • Port Scans: `{stats['ports_scanned']}`
  • SYN Floods: `{stats['syn_floods']}`
  • UDP Floods: `{stats['udp_floods']}`

*System Info:*
  • Monitoring: `{'ACTIVE' if self.monitor.is_monitoring else 'INACTIVE'}`
  • Telegram Bot: `{'ACTIVE' if self.telegram_bot.is_running else 'INACTIVE'}`
"""
        return stats_text
    
    # Additional methods for the enhanced functionality
    def new_session(self):
        if self.monitor.is_monitoring:
            if not messagebox.askyesno("Confirm", "Stop current monitoring session?"):
                return
            self.stop_monitoring()
        
        self.ip_entry.set("")
        self.monitor = NetworkMonitor(self.detector)
        self.print_to_terminal("🆕 New session created")
        self.update_status("New session ready")
        self.db.add_system_event("NEW_SESSION", "New monitoring session created")
    
    def save_threat_log(self):
        if not self.detector.threat_log:
            messagebox.showinfo("Info", "No threat log entries to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Save Threat Log"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("\n".join(self.detector.threat_log))
                self.print_to_terminal(f"💾 Threat log saved to {filename}")
                self.db.add_system_event("EXPORT_THREATS", f"Threat log exported to {filename}")
            except IOError as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def export_threat_log(self):
        self.save_threat_log()
    
    def reset_dashboard(self):
        for key, label in self.stats_labels.items():
            label.config(text="0")
        
        self.pie_ax.clear()
        self.bar_ax.clear()
        self.pie_canvas.draw()
        self.bar_canvas.draw()
        
        self.threat_log.config(state=tk.NORMAL)
        self.threat_log.delete(1.0, tk.END)
        self.threat_log.config(state=tk.DISABLED)
        
        self.print_to_terminal("🔄 Dashboard reset")
        self.db.add_system_event("DASHBOARD_RESET", "Dashboard reset by user")
    
    def export_data(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export System Data"
        )
        
        if filename:
            try:
                export_data = {
                    "timestamp": datetime.now().isoformat(),
                    "version": VERSION,
                    "threat_log": self.detector.threat_log,
                    "config": self.config,
                    "recent_ips": self.recent_ips,
                    "command_history": list(self.command_history)
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                self.print_to_terminal(f"💾 System data exported to {filename}")
                self.db.add_system_event("EXPORT_DATA", f"System data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def import_data(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Import System Data"
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    import_data = json.load(f)
                
                # Validate import data
                if "version" not in import_data:
                    messagebox.showerror("Error", "Invalid data file format")
                    return
                
                # Import threat log
                if "threat_log" in import_data:
                    self.detector.threat_log = import_data["threat_log"][-MAX_LOG_LINES:]
                
                # Import recent IPs
                if "recent_ips" in import_data:
                    self.recent_ips = import_data["recent_ips"]
                    self.ip_entry['values'] = self.recent_ips
                
                # Import command history
                if "command_history" in import_data:
                    self.command_history.clear()
                    self.command_history.extend(import_data["command_history"][-MAX_COMMAND_HISTORY:])
                    self.save_command_history()
                
                self.print_to_terminal(f"📥 System data imported from {filename}")
                self.update_threat_log()
                self.db.add_system_event("IMPORT_DATA", f"System data imported from {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import data: {str(e)}")
    
    def open_network_scanner(self):
        self.print_to_terminal("🛠️  Opening network scanner... (Feature in development)")
        # Implementation would go here
    
    def open_vulnerability_scanner(self):
        self.print_to_terminal("🛠️  Opening vulnerability scanner... (Feature in development)")
        # Implementation would go here
    
    def open_packet_analyzer(self):
        self.print_to_terminal("🛠️  Opening packet analyzer... (Feature in development)")
        # Implementation would go here
    
    def open_ip_management(self):
        self.dashboard_notebook.select(self.ip_management_tab)
        self.print_to_terminal("🌐 Opening IP management...")
    
    def open_threat_analysis(self):
        self.dashboard_notebook.select(self.threats_tab)
        self.print_to_terminal("🚨 Opening threat analysis...")
    
    def quick_ping(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.run_ping(ip)
        else:
            messagebox.showinfo("Info", "Please enter an IP address first")
    
    def quick_scan(self):
        self.print_to_terminal("🔍 Quick network scan initiated...")
        # Implementation would go here
    
    def quick_stats(self):
        stats = self.monitor.get_stats()
        stats_text = f"""
📊 Quick Stats:
  Total Packets: {stats['total_packets']}
  Threats Detected: {stats['threats_detected']}
  Monitoring: {'Active' if self.monitor.is_monitoring else 'Inactive'}
"""
        self.print_to_terminal(stats_text)
    
    def quick_threats(self):
        if self.detector.threat_log:
            self.dashboard_notebook.select(self.threats_tab)
        else:
            messagebox.showinfo("Info", "No threats detected yet")
    
    def show_user_guide(self):
        guide = """
📖 Advanced Cyber Security Monitor User Guide

1. Monitoring:
   - Enter target IP address and select network interface
   - Click "Start Monitoring" to begin
   - Real-time statistics and threats will be displayed

2. Dashboard:
   - Overview: Real-time statistics and charts
   - Threat Log: Security threats and events
   - IP Management: Whitelist and blacklist management

3. Terminal Commands:
   - Use commands for quick operations
   - Type 'help' for available commands
   - Command history is saved and accessible

4. Telegram Integration:
   - Configure bot token and chat ID
   - Control monitoring via Telegram commands
   - Receive alerts and status updates

5. IP Management:
   - Add IPs to whitelist to exclude from monitoring
   - Add IPs to blacklist for enhanced monitoring
   - Manage IP lists via GUI or commands

6. Data Export:
   - Export threat logs and system data
   - Import previous sessions
   - Save reports for analysis

Keyboard Shortcuts:
  - Up/Down: Navigate command history
  - Ctrl+C: Copy selected text
  - Ctrl+V: Paste text
"""
        messagebox.showinfo("User Guide", guide)
    
    def show_keyboard_shortcuts(self):
        shortcuts = """
⌨️ Keyboard Shortcuts:

Terminal:
  Up Arrow    - Previous command in history
  Down Arrow  - Next command in history
  Enter       - Execute command
  Ctrl+C      - Copy selected text
  Ctrl+V      - Paste text

General:
  Ctrl+N      - New session
  Ctrl+S      - Save threat log
  Ctrl+Q      - Exit application
  F1          - Show help
  F5          - Refresh dashboard
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def show_about(self):
        about = f"""
🚀 Advanced Network Based Intrusion Detection System v{VERSION}

Author: Ian Carter Kulani
E-mail: iancarterkulani@gmail.com
Phone: +265(0)988061969

A comprehensive network monitoring and threat detection tool with 
advanced features including Telegram integration, real-time analytics, 
and enterprise-grade security monitoring.

Features:
- Real-time network traffic monitoring
- DOS/DDOS attack detection
- Port scan detection
- Vulnerability scanning
- Telegram bot integration
- Interactive command terminal
- Advanced data visualization
- IP whitelist/blacklist management
- Threat intelligence database
- Data export/import capabilities

Developed for educational and professional security purposes.
© 2024 All rights reserved.
"""
        messagebox.showinfo("About", about)
    
    def on_closing(self):
        if self.monitor.is_monitoring:
            if messagebox.askyesno("Confirm", "Monitoring is active. Stop monitoring and exit?"):
                self.monitor.stop_monitoring()
                self.db.add_system_event("SYSTEM_SHUTDOWN", "Application closed by user")
                self.root.destroy()
        else:
            self.db.add_system_event("SYSTEM_SHUTDOWN", "Application closed by user")
            self.root.destroy()

class TelegramConfigDialog:
    def __init__(self, parent, telegram_bot, main_app):
        self.telegram_bot = telegram_bot
        self.main_app = main_app
        self.top = tk.Toplevel(parent)
        self.top.title("Telegram Bot Configuration")
        self.top.geometry("500x400")
        self.top.resizable(False, False)
        self.top.transient(parent)
        self.top.grab_set()
        
        self.setup_dialog()
    
    def setup_dialog(self):
        main_frame = ttk.Frame(self.top, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="🤖 Telegram Bot Configuration", 
                 font=('Segoe UI', 14, 'bold')).pack(pady=(0, 20))
        
        # Bot Token
        token_frame = ttk.Frame(main_frame)
        token_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(token_frame, text="Bot Token:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        self.token_entry = ttk.Entry(token_frame, width=50, show="•")
        self.token_entry.insert(0, self.telegram_bot.token or "")
        self.token_entry.pack(fill=tk.X, pady=5)
        
        ttk.Label(token_frame, text="Get your token from @BotFather on Telegram", 
                 font=('Segoe UI', 8), foreground="gray").pack(anchor=tk.W)
        
        # Chat ID
        chat_id_frame = ttk.Frame(main_frame)
        chat_id_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(chat_id_frame, text="Chat ID:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        self.chat_id_entry = ttk.Entry(chat_id_frame, width=50)
        self.chat_id_entry.insert(0, self.telegram_bot.chat_id or "")
        self.chat_id_entry.pack(fill=tk.X, pady=5)
        
        ttk.Label(chat_id_frame, text="Your Telegram chat ID (optional for personal bot)", 
                 font=('Segoe UI', 8), foreground="gray").pack(anchor=tk.W)
        
        # Instructions
        instructions = """
Instructions:
1. Create a bot with @BotFather on Telegram
2. Copy the bot token and paste it above
3. (Optional) Add your chat ID for personal notifications
4. Test the connection to verify configuration
5. Start the bot to enable Telegram commands

Available Telegram Commands:
/start, /help, /ping_ip, /start_monitoring_ip, /stop, 
/status, /stats, /threats, /add_ip, /remove_ip, /history, 
/clear, /exit
"""
        instructions_text = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            height=8,
            font=('Segoe UI', 9)
        )
        instructions_text.insert(1.0, instructions)
        instructions_text.config(state=tk.DISABLED)
        instructions_text.pack(fill=tk.X, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            button_frame,
            text="Test Connection",
            command=self.test_connection
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Save Configuration",
            command=self.save_configuration
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Start Bot",
            command=self.start_bot
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Close",
            command=self.top.destroy
        ).pack(side=tk.RIGHT)
    
    def test_connection(self):
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showerror("Error", "Please enter a bot token")
            return
        
        try:
            bot = telegram.Bot(token=token)
            user = bot.get_me()
            messagebox.showinfo("Success", 
                              f"Connection successful!\n\n"
                              f"Bot Name: {user.first_name}\n"
                              f"Username: @{user.username}\n"
                              f"ID: {user.id}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed:\n{str(e)}")
    
    def save_configuration(self):
        token = self.token_entry.get().strip()
        chat_id = self.chat_id_entry.get().strip()
        
        if not token:
            messagebox.showerror("Error", "Please enter a bot token")
            return
        
        self.telegram_bot.token = token
        self.telegram_bot.chat_id = chat_id
        self.telegram_bot.save_config()
        
        messagebox.showinfo("Success", "Configuration saved successfully!")
        self.main_app.print_to_terminal("✅ Telegram configuration updated")
    
    def start_bot(self):
        self.save_configuration()
        self.main_app.start_telegram_bot()
        self.top.destroy()

def main():
    # Set up logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Center the window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()