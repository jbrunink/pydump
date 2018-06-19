from __future__ import print_function
from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from apiclient import http
from apiclient import errors
import apiclient

from http.server import *
from http import HTTPStatus
import sqlite3
import io
import os
import urllib
import mimetypes
import pprint
from socketserver import ThreadingMixIn
import sys
import json
from requests_toolbelt import MultipartDecoder
import cgi
import datetime
import base64
import httplib2

google_service=None
sqlite_database=None

class DatabaseNotFound(Exception):
    pass

def getDatabase():
    global sqlite_database
    if sqlite_database:
        return sqlite_database
    if os.getenv('DATABASE') and os.path.isfile(os.getenv('DATABASE')):
        conn = sqlite3.connect(os.getenv('DATABASE'))
        return conn
    else:
        raise DatabaseNotFound

def getGoogle():
    SCOPES = 'https://www.googleapis.com/auth/drive.file'
    store = file.Storage('credentials.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
        creds = tools.run_flow(flow, store)
    google_service = build(
        'drive',
        'v3',
        http=creds.authorize(Http())
    )
    return google_service

class handler(SimpleHTTPRequestHandler):
    error_message_format = """%(code)d %(message)s"""
    server_version = 'hoi :) alles goed?'
    sys_version = 'fakkof'

    def handle(self):
        try:
            super().handle()
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, message='Iets ging echt verschrikkelijk mis, het is gewoon niet te geloom')
            raise e

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.headers['X-Real-IP'] if 'X-Real-IP' in self.headers else self.address_string(),
                          self.log_date_time_string(),
                          format%args))

    def do_GET(self):
        f = self.send_head()
        if f:
            media_request = http.MediaIoBaseDownload(self.wfile, f)
            done = False
            while done is False:
                try:
                    download_progress, done = media_request.next_chunk()
                except Exception as e:
                    print(e)
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_HEAD(self):
        self.send_head()

    def do_POST(self):
        database = getDatabase()
        session = {
            'username': None,
            'apiKey': None,
            'isAuthorised': None,
            'binaryFile': None,
            'originalFilename': None
        }
        if 'API-Key' in self.headers:
            cursor = database.execute('SELECT username,apiKey FROM `users` WHERE `apiKey` = ?', (self.headers['API-Key'],))
            row = cursor.fetchone()
            if row:
                username, apiKey = row
                session['username'] = username
                session['apiKey'] = apiKey
                session['isAuthorised'] = True
            else:
                self.send_error(HTTPStatus.FORBIDDEN, message='You must provide a valid API key.')
                return
        else:
            self.send_error(HTTPStatus.FORBIDDEN, message='You must provide an API key')
            return
        if int(self.headers['Content-Length']) > int(os.getenv('MAX_UPLOAD_BYTES', 8388608)):
            self.send_error(HTTPStatus.NOT_ACCEPTABLE, message='You have exceeded filelimit size, kgg over')
            return
        multipart_decoder = MultipartDecoder(
            self.rfile.read(int(self.headers['Content-Length'])),
            self.headers['Content-Type']
        )
        for part in multipart_decoder.parts:
            for index, value in part.headers.items():
                index, value = cgi.parse_header(value.decode('utf-8'))
                if 'name' in value:
                    if value['name'] == 'upload':
                        session['binaryFile'] = part.content
                if 'filename' in value:
                    session['originalFilename'] = value['filename']

        if session['isAuthorised'] and session['binaryFile']:
            if not mimetypes.inited:
                mimetypes.init()
            mimetype, encoding = mimetypes.guess_type(session['originalFilename']) if mimetypes.guess_type(session['originalFilename'])[0] else ('application/octet-stream', None,)
            media_body = apiclient.http.MediaIoBaseUpload(
                io.BytesIO(session['binaryFile']),
                mimetype=mimetype
            )
            body = {
                'name': base64.b64encode(bytearray('{}.{}'.format(datetime.datetime.now(), session['originalFilename']),'utf-8')).decode('utf-8'),
                'parents': [os.getenv('ROOT_FOLDER')],
                'originalFilename': session['originalFilename'],
                'createdTime': datetime.datetime.utcnow().isoformat() + 'Z'
            }
            new_file = getGoogle().files().create(body=body, media_body=media_body, fields='id,name,originalFilename,md5Checksum,createdTime,mimeType,size').execute()
            cursor = database.execute(
                'INSERT INTO `uploads` (googleId, name, originalFilename, mimeType, md5Checksum, createdTime, size) VALUES (?,?,?,?,?,?,?)',
                (new_file['id'], new_file['name'], new_file['originalFilename'], new_file['mimeType'], new_file['md5Checksum'], new_file['createdTime'], new_file['size'],))
            database.commit()

            jsons = json.dumps(
                {
                    'url': '{}/{}'.format(
                        os.getenv('URL'),
                        new_file['id']
                    )
                }
            )
            self.send_response(
                HTTPStatus.OK
            )
            self.send_header(
                'Content-type',
                'text/plain'
            )
            self.send_header(
                "Content-Length",
                len(jsons)
            )
            self.end_headers()
            self.wfile.write(
                bytearray(
                    jsons,
                    'utf-8')
            )
        else:
            self.send_error(HTTPStatus.FORBIDDEN)
            return

    def send_head(self):
        f = None
        if self.path == '/':
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        else:
            database = getDatabase()
            parts = urllib.parse.urlsplit(self.path)
            id = parts.path[1:]
            cursor = database.execute("SELECT id,googleId,originalFilename,mimeType,md5Checksum,createdTime,size FROM `uploads` WHERE googleId = ?", (id,))
            row = cursor.fetchone()
            if row:
                id, googleId, originalFilename, mimeType, md5Checksum, createdTime, size = row
                try:
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", mimeType)
                    self.send_header("Content-Length", size)
                    self.send_header('Content-Disposition', 'inline; filename="{}"'.format(originalFilename))
                    self.end_headers()
                    f = getGoogle().files().get_media(fileId=googleId)
                except Exception as e:
                    print(e)
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
        return f


def cleancrap():
    google = getGoogle()

    pass

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

server = ThreadingSimpleServer(('0.0.0.0', 8000), handler)

try:
    while True:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print("\nShutting down server per users request.")

"""
def run(server_class=HTTPServer, handler_class=handler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

run()"""