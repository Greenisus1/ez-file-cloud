import concurrent.futures
import hashlib
import http.client
import importlib.util
import json
import ipaddress
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import quote

spec = importlib.util.spec_from_file_location('ezfc', str(Path(__file__).with_name('ezfilecloud.py')))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.server, self.root = app.make_server(self.base / 'inbox', '127.0.0.1', 0, 3*1024*1024, [ipaddress.ip_network('127.0.0.0/8')])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.receiver = '127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, route, body=b'', headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, route, body, headers or {})
        response = conn.getresponse()
        result = response.status, json.loads(response.read())
        conn.close()
        return result

    def put(self, user, name, body=b'data', digest=None):
        return self.request('PUT', '/upload/'+quote(user, safe='')+'/'+quote(name, safe=''), body,
                            {'X-Content-SHA256': digest or hashlib.sha256(body).hexdigest()})

    def test_send_binary_and_spaces(self):
        path = self.base / 'holiday photo.bin'
        payload = os.urandom(2*1024*1024+17)
        path.write_bytes(payload)
        data = app.send_file(self.receiver, 'SampleUser', path)
        self.assertEqual(data['bytes'], len(payload))
        self.assertEqual((self.root/'SampleUser'/path.name).read_bytes(), payload)

    def test_zero_and_unicode(self):
        self.assertEqual(self.put('Maya', 'hello.txt', b'')[0], 201)
        self.assertEqual(self.put('Maya', 'café.jpg')[0], 201)
        self.assertEqual((self.root/'Maya'/'hello.txt').read_bytes(), b'')

    def test_duplicates_and_concurrency(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda n: self.put('SampleUser', 'same.txt', str(n).encode()), range(4)))
        self.assertTrue(all(status == 201 for status, data in results))
        self.assertEqual(len(list((self.root/'SampleUser').glob('same*.txt'))), 4)
        self.assertEqual({p.read_bytes() for p in (self.root/'SampleUser').glob('same*.txt')}, {b'0',b'1',b'2',b'3'})

    def test_reject_traversal_and_bad_names(self):
        for user, name in [('..','ok'), ('a/b','ok'), ('SampleUser','../escape'), ('SampleUser','..'), ('SampleUser','bad\\name'), ('SampleUser','bad\nname')]:
            self.assertEqual(self.put(user, name)[0], 400)
        self.assertFalse((self.base/'escape').exists())

    def test_symlink_directory_and_destination(self):
        outside = self.base/'outside'
        outside.mkdir()
        (self.root/'Evil').symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.put('Evil', 'x')[0], 500)
        self.assertEqual(list(outside.iterdir()), [])
        (self.root/'SampleUser').mkdir()
        target = outside/'secret'
        target.write_bytes(b'original')
        (self.root/'SampleUser'/'file').symlink_to(target)
        self.assertEqual(self.put('SampleUser','file')[1]['filename'], 'file-1')
        self.assertEqual(target.read_bytes(), b'original')

    def test_bad_checksum_and_limit(self):
        self.assertEqual(self.put('SampleUser', 'bad', digest='0'*64)[0], 422)
        self.assertEqual(list((self.root/'SampleUser').iterdir()), [])
        self.assertEqual(self.request('PUT', '/upload/SampleUser/huge', b'',
            {'Content-Length': str(3*1024*1024+1), 'X-Content-SHA256': '0'*64})[0], 413)
        big = self.base / 'big.bin'
        big.write_bytes(b'x'*(3*1024*1024+1))
        with self.assertRaisesRegex(ValueError, 'size limit'):
            app.send_file(self.receiver, 'SampleUser', big)

    def test_unscoped_paths_not_exposed(self):
        self.assertEqual(self.request('GET','/health')[0], 200)
        for path in ['/', '/SampleUser/file', '/upload/SampleUser/file']:
            self.assertEqual(self.request('GET',path)[0],404)

    def test_interrupted_upload(self):
        sock = __import__('socket').create_connection(('127.0.0.1',self.server.server_port))
        sock.sendall(b'PUT /upload/SampleUser/partial HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nX-Content-SHA256: '+b'0'*64+b'\r\n\r\nshort')
        sock.shutdown(__import__('socket').SHUT_WR)
        while sock.recv(4096):
            pass
        sock.close()
        # Response is sent before finally cleanup; wait on active upload slots.
        for _ in range(100):
            if not list((self.root/'SampleUser').iterdir()):
                break
            __import__('time').sleep(.01)
        self.assertEqual(list((self.root/'SampleUser').iterdir()), [])

    def test_outside_network_rejected(self):
        self.server.allowed_networks[:] = [ipaddress.ip_network('192.168.50.0/24')]
        self.assertEqual(self.request('GET', '/health')[0], 403)
        self.assertEqual(self.put('SampleUser','nope')[0], 403)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_local_subnet_detection(self):
        networks = app.local_networks()
        self.assertTrue(networks)
        self.assertTrue(all(not net.is_loopback for net in networks))

    def test_receiver_validation(self):
        self.assertEqual(app.parse_receiver('http://127.0.0.1:8765'),('127.0.0.1',8765))
        for value in ['https://host','http://user:password@host','http://host/path']:
            with self.assertRaises(ValueError): app.parse_receiver(value)

    def test_list_and_download_binary_unicode(self):
        payload = os.urandom(2*1024*1024+17)
        self.assertEqual(self.put('Maya', 'café holiday.bin', payload)[0], 201)
        self.assertEqual(self.put('Maya', 'empty', b'')[0], 201)
        files = app.list_remote_files(self.receiver, 'Maya')
        self.assertEqual([f['filename'] for f in files], ['café holiday.bin', 'empty'])
        folder = self.base / 'downloads'
        saved = app.download_file(self.receiver, 'Maya', 'café holiday.bin', folder)
        self.assertEqual(saved.read_bytes(), payload)
        saved2 = app.download_file(self.receiver, 'Maya', 'café holiday.bin', folder)
        self.assertNotEqual(saved, saved2)
        self.assertEqual(saved2.read_bytes(), payload)
        self.assertEqual(app.download_file(self.receiver, 'Maya', 'empty', folder).read_bytes(), b'')
        self.assertEqual(list(folder.glob('.ezfc-*')), [])

    def test_download_traversal_symlinks_missing_and_network(self):
        outside = self.base / 'private'
        outside.mkdir()
        (outside/'secret').write_bytes(b'private')
        (self.root/'Bad').symlink_to(outside, target_is_directory=True)
        (self.root/'Maya').mkdir()
        (self.root/'Maya'/'secret').symlink_to(outside/'secret')
        (self.root/'Maya'/'.ezfc-temporary.part').write_bytes(b'partial')
        self.assertEqual(app.list_remote_files(self.receiver, 'Maya'), [])
        for route in ['/files/..', '/download/Maya/..', '/download/Maya/a%2Fb', '/download/Maya/.ezfc-temporary.part']:
            self.assertEqual(self.request('GET', route)[0], 400)
        for route in ['/files/Bad', '/download/Bad/secret', '/download/Maya/secret']:
            self.assertEqual(self.request('GET', route)[0], 403)
        self.assertEqual(self.request('GET', '/files/Unknown')[0], 404)
        self.server.allowed_networks[:] = [ipaddress.ip_network('192.168.50.0/24')]
        for route in ['/files/Maya', '/download/Maya/secret']:
            self.assertEqual(self.request('GET', route)[0], 403)

    def test_download_does_not_follow_local_symlink(self):
        self.put('Maya', 'file', b'new')
        folder = self.base/'downloads'
        folder.mkdir()
        original = self.base/'original'
        original.write_bytes(b'old')
        (folder/'file').symlink_to(original)
        self.assertEqual(app.download_file(self.receiver, 'Maya', 'file', folder).name, 'file-1')
        self.assertEqual(original.read_bytes(), b'old')

    def test_discovery_and_send_without_ip(self):
        responder = app.DiscoveryResponder(self.server, port=0, bind='127.0.0.1')
        try:
            found = app.discover_receivers(timeout=.3, port=responder.port, targets=['127.0.0.1'], networks=[ipaddress.ip_network('127.0.0.0/8')])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]['port'], self.server.server_port)
            path = self.base/'discovered.txt'
            path.write_bytes(b'auto')
            from unittest.mock import patch
            with patch.object(app, 'discover_receivers', return_value=found):
                receiver = app.choose_receiver()
            app.send_file(receiver, 'Maya', path)
            self.assertEqual((self.root/'Maya'/path.name).read_bytes(), b'auto')
        finally:
            responder.close()
        self.assertFalse(responder.thread.is_alive())

    def test_discovery_rejects_outside_and_malformed(self):
        import socket
        responder = app.DiscoveryResponder(self.server, port=0, bind='127.0.0.1')
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(.1)
                for query in [b'not-json', b'[]', b'{"app":"wrong"}', b'{"app":"EZFC_DISCOVER_1","nonce":"bad"}']:
                    sock.sendto(query, ('127.0.0.1', responder.port))
                    with self.assertRaises(socket.timeout):
                        sock.recvfrom(1024)
            self.server.allowed_networks[:] = [ipaddress.ip_network('192.168.50.0/24')]
            found = app.discover_receivers(timeout=.2, port=responder.port, targets=['127.0.0.1'], networks=[ipaddress.ip_network('127.0.0.0/8')])
            self.assertEqual(found, [])
        finally:
            responder.close()

    def test_discovery_selection(self):
        from unittest.mock import patch
        choices = [{'name':'Pi one', 'host':'192.168.1.2', 'port':8765}, {'name':'Pi two', 'host':'192.168.1.3', 'port':8766}]
        with patch.object(app, 'discover_receivers', return_value=choices):
            with self.assertRaisesRegex(ValueError, 'Multiple receivers'):
                app.choose_receiver(False)
            with patch('builtins.input', return_value='2'):
                self.assertEqual(app.choose_receiver(), '192.168.1.3:8766')
            with patch('builtins.input', return_value='0'):
                with self.assertRaises(ValueError):
                    app.choose_receiver()
        with patch.object(app, 'discover_receivers', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'No receiver found'):
                app.choose_receiver()
        self.assertEqual(app.display_name('Pi\x1b\nName'), 'PiName')

    def test_discovery_broadcast_real_interface(self):
        server, root = app.make_server(self.base/'lan-inbox', '0.0.0.0', 0, 1024)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        responder = app.DiscoveryResponder(server, port=0)
        try:
            found = app.discover_receivers(timeout=.5, port=responder.port)
            self.assertTrue(any(f['port'] == server.server_port for f in found))
        finally:
            responder.close()
            server.shutdown()
            server.server_close()

    def test_download_bad_checksum_and_interrupted_cleanup(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class BadDownload(BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.send_response(200)
                handler.send_header('Content-Length', '100')
                handler.send_header('X-Content-SHA256', '0'*64)
                handler.end_headers()
                handler.wfile.write(b'short')
            def log_message(handler, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), BadDownload)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        folder = self.base/'bad-download'
        try:
            with self.assertRaises((ValueError, http.client.HTTPException)):
                app.download_file('127.0.0.1:'+str(server.server_port), 'Maya', 'bad', folder)
            self.assertEqual(list(folder.iterdir()), [])
        finally:
            server.shutdown()
            server.server_close()

    def test_menu_grab_and_send(self):
        from unittest.mock import patch
        found = [{'name':'Test Pi', 'host':'127.0.0.1', 'port':self.server.server_port}]
        path = self.base/'menu file.txt'
        path.write_bytes(b'menu payload')
        with patch.object(app, 'discover_receivers', return_value=found):
            with patch('builtins.input', side_effect=['2', 'Maya', str(path), '']):
                app.interactive()
            with patch('builtins.input', side_effect=['3', 'Maya', '1', str(self.base/'grabbed')]):
                app.interactive()
        self.assertEqual((self.base/'grabbed'/path.name).read_bytes(), b'menu payload')

    def test_download_full_bad_checksum_cleanup(self):
        from unittest.mock import patch
        self.put('Maya', 'bad', b'payload')
        original = http.client.HTTPResponse.getheader
        def header(response, name, default=None):
            if name == 'X-Content-SHA256':
                return '0'*64
            return original(response, name, default)
        folder = self.base/'checksum'
        with patch.object(http.client.HTTPResponse, 'getheader', header):
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                app.download_file(self.receiver, 'Maya', 'bad', folder)
        self.assertEqual(list(folder.iterdir()), [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
