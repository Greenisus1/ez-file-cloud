#!/usr/bin/env python3
"""EZ file cloud: password-free file inbox for a trusted LAN."""
import argparse
import concurrent.futures
import secrets
import time
import hashlib
import http.client
import json
import ipaddress
import subprocess
import struct
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import threading
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

VERSION = '1.2'
PORT = 8765
MAX_BYTES = 10 * 1024 ** 3
USER_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z')


def username_ok(name):
    return bool(USER_RE.fullmatch(name))


def filename_ok(name):
    return (bool(name) and name not in ('.', '..') and len(name.encode('utf-8')) <= 200
            and not any(c in name for c in '/\\')
            and not any(ord(c) < 32 or ord(c) == 127 for c in name))


def local_networks():
    """Actual connected IPv4 subnets, not every private IP range."""
    addresses = []
    if sys.platform.startswith('linux'):
        import fcntl
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for index, name in socket.if_nameindex():
                request = struct.pack('256s', name.encode()[:15])
                try:
                    addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, request)[20:24])
                    mask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x891b, request)[20:24])
                    addresses.append((addr, mask))
                except OSError:
                    continue
    elif sys.platform == 'darwin':
        result = subprocess.run(['/sbin/ifconfig'], check=True, capture_output=True, text=True)
        for addr, mask in re.findall(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)', result.stdout):
            if mask.startswith('0x'):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            addresses.append((addr, mask))
    private_ranges = [ipaddress.ip_network(x) for x in
                      ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']]
    networks = set()
    for addr, mask in addresses:
        ip = ipaddress.ip_address(addr)
        net = ipaddress.ip_network(addr + '/' + mask, strict=False)
        if any(ip in private and net.subnet_of(private) for private in private_ranges):
            networks.add(net)
    if not networks:
        raise ValueError('No private LAN subnet found. Connect to local Wi-Fi or Ethernet first.')
    return sorted(networks, key=str)


# One tiny UDP query replaces typing an IP. No subnet-wide TCP port scan.
DISCOVERY_PORT = 8764
DISCOVERY_MAGIC = 'EZFC_DISCOVER_1'
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(x) for x in
                         ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'))


def display_name(value):
    # Network names are data, never terminal control sequences.
    return ''.join(c for c in str(value) if c.isprintable())[:80] or 'Receiver'


def discovery_targets():
    targets = {'255.255.255.255'}
    # Directed broadcasts also reach secondary interfaces on Linux/macOS.
    # Windows uses its OS-routed limited broadcast, with no shell commands.
    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        try:
            targets.update(str(net.broadcast_address) for net in local_networks()
                           if net.prefixlen <= 30)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return sorted(targets)


class DiscoveryResponder:
    def __init__(self, server, port=DISCOVERY_PORT, bind='0.0.0.0'):
        self.server = server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((bind, port))
            self.socket.settimeout(0.2)
        except BaseException:
            self.socket.close()
            raise
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        # Bound response rate: discovery is not an unrestricted UDP reflector.
        window, replies = time.monotonic(), 0
        while not self.stopped.is_set():
            try:
                packet, peer = self.socket.recvfrom(1024)
                if not any(ipaddress.ip_address(peer[0]) in net
                           for net in self.server.allowed_networks):
                    continue
                query = json.loads(packet)
                if (not isinstance(query, dict) or query.get('app') != DISCOVERY_MAGIC
                        or not isinstance(query.get('nonce'), str)
                        or not re.fullmatch('[a-f0-9]{32}', query['nonce'])):
                    continue
                now = time.monotonic()
                if now - window >= 1:
                    window, replies = now, 0
                if replies >= 20:
                    continue
                replies += 1
                response = {'app': DISCOVERY_MAGIC, 'nonce': query['nonce'],
                            'port': self.server.server_port,
                            'name': display_name(socket.gethostname()), 'version': VERSION}
                self.socket.sendto(json.dumps(response).encode('utf-8'), peer)
            except socket.timeout:
                continue
            except (OSError, ValueError, TypeError):
                continue

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=1)
        self.socket.close()


def receiver_health(host, port, timeout=1):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request('GET', '/health')
        response = conn.getresponse()
        info = json.loads(response.read(8192))
        return (response.status == 200 and isinstance(info, dict)
                and info.get('app') == 'EZ file cloud'
                and info.get('mode') == 'file-inbox')
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def discover_receivers(timeout=3.0, port=DISCOVERY_PORT, targets=None, networks=None):
    """Broadcast on the LAN, then verify replies at their actual source IP."""
    targets = discovery_targets() if targets is None else targets
    if networks is None:
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            networks = local_networks()  # Fail closed if we cannot ground the LAN.
        else:
            # Windows broadcast is LAN-scoped. Accept only private source IPs.
            networks = PRIVATE_NETWORKS
    nonce = secrets.token_hex(16)
    query = json.dumps({'app': DISCOVERY_MAGIC, 'nonce': nonce}).encode('utf-8')
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        deadline, next_query = time.monotonic() + timeout, 0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_query:
                for target in targets:
                    try:
                        sock.sendto(query, (target, port))
                    except OSError:
                        pass  # Another active interface may still work.
                next_query = now + 0.8
            sock.settimeout(max(0.001, min(0.2, deadline - time.monotonic())))
            try:
                packet, peer = sock.recvfrom(1024)
                if not any(ipaddress.ip_address(peer[0]) in net for net in networks):
                    continue
                reply = json.loads(packet)
                if (not isinstance(reply, dict) or reply.get('app') != DISCOVERY_MAGIC
                        or reply.get('nonce') != nonce or type(reply.get('port')) is not int
                        or not 1 <= reply['port'] <= 65535):
                    continue
                key = (peer[0], reply['port'])
                if len(found) < 16 or key in found:
                    found[key] = {'host': peer[0], 'port': reply['port'],
                                  'name': display_name(reply.get('name', 'Receiver'))}
            except socket.timeout:
                pass
            except (OSError, ValueError, TypeError):
                continue
    # A UDP announcement alone is not enough: check the HTTP app.
    candidates = sorted(found.values(), key=lambda item: (item['name'], item['host'], item['port']))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        valid = list(pool.map(lambda item: receiver_health(item['host'], item['port']), candidates))
    return [item for item, ok in zip(candidates, valid) if ok]


def choose_receiver(interactive_selection=True):
    print('Looking for EZ file cloud receivers on your local network...', flush=True)
    receivers = discover_receivers()
    if not receivers:
        raise ValueError('No receiver found. Start the UPDATED script on the Pi with receive, '
                         'use the same local network, and allow UDP 8764 and TCP 8765 '
                         'in its firewall. Guest Wi-Fi/device isolation can block discovery.')
    if len(receivers) == 1:
        selected = receivers[0]
    else:
        for number, item in enumerate(receivers, 1):
            print('{} . {} ({}:{})'.format(number, item['name'], item['host'], item['port']))
        if not interactive_selection:
            raise ValueError('Multiple receivers found. Use the menu to choose one; no files sent.')
        value = input('Choose receiver number: ').strip()
        if not value.isdigit() or not 1 <= int(value) <= len(receivers):
            raise ValueError('Choose a receiver number from the list.')
        selected = receivers[int(value) - 1]
    print('Receiver: {} ({}:{})'.format(selected['name'], selected['host'], selected['port']))
    return '{}:{}'.format(selected['host'], selected['port'])


def make_server(root, host, port, max_bytes, networks=None):
    networks = local_networks() if networks is None else networks
    root = Path(root).expanduser().absolute()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = root.resolve()
    lock = threading.Lock()
    slots = threading.BoundedSemaphore(4)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'EZFileCloud/' + VERSION

        def reply(self, code, payload):
            body = json.dumps(payload).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def allowed(self):
            peer = ipaddress.ip_address(self.client_address[0])
            if not any(peer in network for network in networks):
                self.reply(403, {'error': 'Same-network devices only.'})
                return False
            return True

        def open_user(self, user):
            if not username_ok(user):
                raise ValueError('Invalid username.')
            return os.open(str(root / user), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

        def list_files(self, user):
            directory_fd = self.open_user(user)
            try:
                files = []
                for name in os.listdir(directory_fd):
                    if not filename_ok(name) or name.startswith('.ezfc-'):
                        continue
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        files.append({'filename': name, 'bytes': info.st_size})
                    if len(files) > 1000:
                        self.reply(413, {'error': 'Folder exceeds the 1000-file listing limit.'})
                        return
                self.reply(200, {'username': user, 'files': sorted(files, key=lambda f: f['filename'])})
            finally:
                os.close(directory_fd)

        def download_file(self, user, name):
            if not filename_ok(name) or name.startswith('.ezfc-'):
                raise ValueError('Invalid filename.')
            directory_fd = self.open_user(user)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
            with os.fdopen(fd, 'rb') as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError('Only regular files can be downloaded.')
                size = os.fstat(source.fileno()).st_size
                digest = hashlib.sha256()
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(chunk)
                source.seek(0)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(size))
                self.send_header('X-Content-SHA256', digest.hexdigest())
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                remaining = size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)

        def do_GET(self):
            if not self.allowed():
                return
            parts = urlsplit(self.path)
            route = parts.path.split('/')
            if self.path == '/health':
                self.reply(200, {'app': 'EZ file cloud', 'version': VERSION,
                                 'max_bytes': max_bytes, 'mode': 'file-inbox'})
                return
            if parts.query or parts.fragment or len(route) not in (3, 4) or route[1] not in ('files', 'download'):
                self.reply(404, {'error': 'Use the app to list or download a username folder.'})
                return
            if not slots.acquire(blocking=False):
                self.reply(503, {'error': 'Receiver busy. Try again shortly.'})
                return
            try:
                self.connection.settimeout(60)
                if route[1] == 'files' and len(route) == 3:
                    self.list_files(unquote(route[2], errors='strict'))
                elif route[1] == 'download' and len(route) == 4:
                    self.download_file(unquote(route[2], errors='strict'), unquote(route[3], errors='strict'))
                else:
                    self.reply(404, {'error': 'Unknown route.'})
            except FileNotFoundError:
                self.reply(404, {'error': 'Username folder or file not found.'})
            except (ValueError, UnicodeError):
                self.reply(400, {'error': 'Invalid username or filename.'})
            except (BrokenPipeError, ConnectionError, TimeoutError):
                pass
            except OSError:
                self.reply(403, {'error': 'Cannot access folder or file; symlinks are not allowed.'})
            finally:
                slots.release()

        def do_PUT(self):
            if not self.allowed():
                return
            if not slots.acquire(blocking=False):
                self.reply(503, {'error': 'Receiver busy. Try again shortly.'})
                return
            temporary = None
            directory_fd = None
            try:
                self.connection.settimeout(60)
                parts = urlsplit(self.path)
                route = parts.path.split('/')
                if parts.query or len(route) != 4 or route[1] != 'upload':
                    self.reply(400, {'error': 'Expected /upload/username/filename.'})
                    return
                user, name = (unquote(x, errors='strict') for x in route[2:])
                if not username_ok(user) or not filename_ok(name) or name.startswith('.ezfc-'):
                    self.reply(400, {'error': 'Invalid username or filename.'})
                    return
                lengths = self.headers.get_all('Content-Length', [])
                if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not lengths[0].isdigit():
                    self.reply(411, {'error': 'One valid Content-Length is required.'})
                    return
                size = int(lengths[0])
                if size > max_bytes:
                    self.reply(413, {'error': 'File exceeds receiver size limit.'})
                    return
                expected = self.headers.get('X-Content-SHA256', '')
                if not re.fullmatch('[a-f0-9]{64}', expected):
                    self.reply(400, {'error': 'SHA-256 checksum required.'})
                    return
                if shutil.disk_usage(root).free < size + 16 * 1024 ** 2:
                    self.reply(507, {'error': 'Not enough free space on receiver.'})
                    return
                # Open the user directory without following a symlink. All file
                # operations use this directory descriptor, not a mutable path.
                folder = root / user
                with lock:
                    folder.mkdir(mode=0o700, exist_ok=True)
                    directory_fd = os.open(str(folder), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                temporary = '.ezfc-' + os.urandom(16).hex() + '.part'
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
                digest = hashlib.sha256()
                with os.fdopen(fd, 'wb') as out:
                    remaining = size
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError('Transfer interrupted; incomplete file removed.')
                        out.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if digest.hexdigest() != expected:
                    self.reply(422, {'error': 'Checksum mismatch; file not saved.'})
                    return
                # Linking publishes a complete file without overwriting any
                # existing name, even with simultaneous uploads.
                stem, suffix = os.path.splitext(name)
                number = 0
                while True:
                    saved_name = name if number == 0 else '{}-{}{}'.format(stem, number, suffix)
                    try:
                        os.link(temporary, saved_name, src_dir_fd=directory_fd,
                                dst_dir_fd=directory_fd, follow_symlinks=False)
                        break
                    except FileExistsError:
                        number += 1
                        if number > 10000:
                            raise ValueError('Too many files with this name.')
                self.reply(201, {'username': user, 'filename': saved_name,
                                 'bytes': size, 'sha256': digest.hexdigest()})
            except (ValueError, UnicodeError) as exc:
                self.reply(400, {'error': str(exc)})
            except (TimeoutError, ConnectionError):
                self.reply(408, {'error': 'Transfer timed out or disconnected; partial file removed.'})
            except OSError as exc:
                print('Storage error:', exc, file=sys.stderr)
                self.reply(500, {'error': 'Receiver could not save the file. Check storage and permissions.'})
            finally:
                if temporary is not None and directory_fd is not None:
                    try:
                        os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                if directory_fd is not None:
                    os.close(directory_fd)
                slots.release()

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.allowed_networks = networks
    return server, root


def receive(args):
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ValueError('Receiver needs Linux or macOS.')
    server, root = make_server(args.folder, args.bind, args.port, args.max_mb * 1024 ** 2)
    print('\nEZ file cloud receiver', flush=True)
    print('Files go to: ' + str(root), flush=True)
    print('Listening on port ' + str(server.server_port), flush=True)
    print('Accepted LAN subnets: ' + ', '.join(map(str, server.allowed_networks)), flush=True)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1', 80))
            print('Likely LAN address: http://{}:{}'.format(probe.getsockname()[0], server.server_port), flush=True)
    except OSError:
        pass
    print('Senders find this receiver automatically. No IP typing needed.', flush=True)
    print('No passwords and no encryption. Use only on trusted Wi-Fi/LAN.', flush=True)
    print('Only detected local IPv4 subnets are accepted; LAN users can use any username.', flush=True)
    print('LAN users can list/download ANY username folder. Usernames are not private accounts.', flush=True)
    print('Do not port-forward or tunnel it.', flush=True)
    print('Keep this terminal open. Ctrl+C stops the receiver.\n', flush=True)
    discovery = None
    try:
        discovery = DiscoveryResponder(server)
        print('LAN discovery ready on UDP ' + str(DISCOVERY_PORT), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nReceiver stopped.')
    finally:
        if discovery is not None:
            discovery.close()
        server.server_close()


def parse_receiver(value):
    value = value.strip()
    if '://' not in value:
        value = 'http://' + value
    parts = urlsplit(value)
    if parts.scheme != 'http' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('Use the receiver LAN IP, optionally with :8765. HTTP only.')
    return parts.hostname, parts.port or PORT


def send_file(receiver, user, path):
    if not username_ok(user):
        raise ValueError('Username: 1-48 letters, numbers, underscores or hyphens; start with a letter or number.')
    host, port = parse_receiver(receiver)
    path = Path(path).expanduser()
    if not path.is_file() or not filename_ok(path.name):
        raise ValueError('Choose an existing regular file with a supported filename.')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Only regular files can be sent.')
        size = os.fstat(source.fileno()).st_size
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
        source.seek(0)
        # Check the receiver before streaming, so an oversized upload is
        # explained instead of failing as a broken pipe mid-send.
        check = http.client.HTTPConnection(host, port, timeout=10)
        try:
            check.request('GET', '/health')
            health = check.getresponse()
            info = json.loads(health.read(65536))
            if health.status != 200 or info.get('app') != 'EZ file cloud':
                raise ValueError('That address is not an EZ file cloud receiver.')
            if size > info.get('max_bytes', 0):
                raise ValueError('File exceeds receiver size limit ({} MiB).'.format(info.get('max_bytes', 0) // 1024 ** 2))
        finally:
            check.close()
        connection = http.client.HTTPConnection(host, port, timeout=60)
        try:
            connection.request('PUT', '/upload/{}/{}'.format(quote(user, safe=''), quote(path.name, safe='')),
                               body=source, headers={'Content-Length': str(size),
                               'X-Content-SHA256': digest.hexdigest(),
                               'Content-Type': 'application/octet-stream'})
            response = connection.getresponse()
            data = json.loads(response.read(65536))
            if response.status != 201:
                raise ValueError(data.get('error', 'Receiver returned HTTP ' + str(response.status)))
            if data.get('sha256') != digest.hexdigest() or data.get('bytes') != size:
                raise ValueError('Receiver confirmation did not match the sent file.')
            print('Saved: {}/{} ({} bytes, checksum verified)'.format(data['username'], data['filename'], data['bytes']))
            return data
        finally:
            connection.close()


def list_remote_files(receiver, user):
    if not username_ok(user):
        raise ValueError('Invalid username.')
    host, port = parse_receiver(receiver)
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request('GET', '/files/' + quote(user, safe=''))
        response = connection.getresponse()
        data = json.loads(response.read(1024 * 1024))
        if response.status != 200:
            raise ValueError(data.get('error', 'Cannot list folder.'))
        files = data.get('files')
        if (not isinstance(files, list) or len(files) > 1000
                or any(not isinstance(f, dict) or not isinstance(f.get('filename'), str)
                       or not filename_ok(f['filename']) or type(f.get('bytes')) is not int
                       or f['bytes'] < 0 for f in files)):
            raise ValueError('Receiver returned an invalid file list.')
        return files
    finally:
        connection.close()


def download_file(receiver, user, name, folder):
    if not username_ok(user) or not filename_ok(name) or name.startswith('.ezfc-'):
        raise ValueError('Invalid username or filename.')
    folder = Path(folder).expanduser().absolute()
    folder.mkdir(parents=True, exist_ok=True)
    host, port = parse_receiver(receiver)
    connection = http.client.HTTPConnection(host, port, timeout=60)
    temporary = None
    try:
        connection.request('GET', '/download/{}/{}'.format(quote(user, safe=''), quote(name, safe='')))
        response = connection.getresponse()
        if response.status != 200:
            data = json.loads(response.read(65536))
            raise ValueError(data.get('error', 'Download failed.'))
        expected = response.getheader('X-Content-SHA256', '')
        length = response.getheader('Content-Length', '')
        if not length.isdigit() or not re.fullmatch('[a-f0-9]{64}', expected):
            raise ValueError('Invalid download metadata.')
        size = int(length)
        if shutil.disk_usage(folder).free < size + 16 * 1024 ** 2:
            raise ValueError('Not enough local disk space for this file.')
        # Exclusive random temp name. Never overwrite a local file or symlink.
        temporary = folder / ('.ezfc-' + secrets.token_hex(16) + '.part')
        digest = hashlib.sha256()
        with temporary.open('xb') as target:
            remaining = size
            while remaining:
                chunk = response.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError('Download interrupted; incomplete file removed.')
                target.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            target.flush()
            os.fsync(target.fileno())
        if digest.hexdigest() != expected:
            raise ValueError('Download checksum mismatch; file not saved.')
        stem, suffix = os.path.splitext(name)
        for number in range(10001):
            saved = folder / (name if number == 0 else '{}-{}{}'.format(stem, number, suffix))
            try:
                os.link(temporary, saved)
                print('Downloaded: {} ({} bytes, checksum verified)'.format(saved, size))
                return saved
            except FileExistsError:
                continue
        raise ValueError('Too many local files with this name.')
    finally:
        connection.close()
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def interactive():
    print('\nEZ file cloud\n1. Receive files on this device\n2. Send files to a receiver\n3. Grab previously sent files')
    choice = input('Choose 1, 2 or 3: ').strip()
    if choice == '1':
        receive(argparse.Namespace(folder=str(Path.home() / 'EZ-file-cloud'), bind='0.0.0.0', port=PORT, max_mb=10240))
    elif choice == '2':
        receiver = choose_receiver()
        user = input('Your username: ').strip()
        if not username_ok(user):
            raise ValueError('Username: 1-48 letters, numbers, underscores or hyphens; start with a letter or number.')
        print('Paste one file path at a time. Spaces are fine; do not add quotes. Blank line finishes.')
        while True:
            path = input('File path: ').strip()
            if not path:
                break
            try:
                send_file(receiver, user, path)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                print('Not sent: ' + str(exc))
    elif choice == '3':
        receiver = choose_receiver()
        user = input('Your username: ').strip()
        files = list_remote_files(receiver, user)
        if not files:
            print('No files in this username folder.')
            return
        for number, item in enumerate(files, 1):
            print('{} . {} ({} bytes)'.format(number, display_name(item['filename']), item['bytes']))
        value = input('File number to download: ').strip()
        if not value.isdigit() or not 1 <= int(value) <= len(files):
            raise ValueError('Choose a file number from the list.')
        default = str(Path.home() / 'EZ-file-cloud-downloads')
        folder = input('Save folder [Enter for {}]: '.format(default)).strip() or default
        download_file(receiver, user, files[int(value)-1]['filename'], folder)
    else:
        raise ValueError('Choose 1, 2 or 3.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    recv = sub.add_parser('receive', help='Start the password-free LAN inbox.')
    recv.add_argument('--folder', default=str(Path.home() / 'EZ-file-cloud'))
    recv.add_argument('--bind', default='0.0.0.0')
    recv.add_argument('--port', type=int, default=PORT)
    recv.add_argument('--max-mb', type=int, default=10240)
    send = sub.add_parser('send', help='Send one or more files.')
    send.add_argument('receiver', help='Use auto to discover, or a LAN IP for legacy/manual use.')
    send.add_argument('username')
    send.add_argument('files', nargs='+')
    sub.add_parser('scan', help='List local receivers without sending files.')
    listing = sub.add_parser('list', help='List a username folder.')
    listing.add_argument('receiver')
    listing.add_argument('username')
    get = sub.add_parser('get', help='Download one file without overwriting local files.')
    get.add_argument('receiver')
    get.add_argument('username')
    get.add_argument('filename')
    get.add_argument('--folder', default=str(Path.home() / 'EZ-file-cloud-downloads'))
    args = parser.parse_args()
    try:
        if args.command == 'receive':
            if args.max_mb < 1 or not 1 <= args.port <= 65535:
                raise ValueError('Use a positive size limit and a port from 1 to 65535.')
            receive(args)
        elif args.command == 'send':
            receiver = choose_receiver(False) if args.receiver == 'auto' else args.receiver
            for path in args.files:
                send_file(receiver, args.username, path)
        elif args.command in ('list', 'get'):
            receiver = choose_receiver(False) if args.receiver == 'auto' else args.receiver
            if args.command == 'list':
                for item in list_remote_files(receiver, args.username):
                    print('{} ({} bytes)'.format(display_name(item['filename']), item['bytes']))
            else:
                download_file(receiver, args.username, args.filename, args.folder)
        elif args.command == 'scan':
            receivers = discover_receivers()
            for item in receivers:
                print('{} ({}:{})'.format(item['name'], item['host'], item['port']))
            if not receivers:
                raise ValueError('No receivers found. Start the updated receiver on your LAN.')
        else:
            interactive()
    except (OSError, ValueError, http.client.HTTPException, EOFError) as exc:
        print('EZ file cloud: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nStopped.')
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
