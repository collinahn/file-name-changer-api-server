# API 서버
'''
nohup gunicorn app:app -b 0.0.0.0:9906 -w 2 --timeout 10 --preload &
'''
import json
import os
import time
import platform
import secrets
from flask import Flask, render_template, send_file, request
from flask.json import jsonify
from flask_cors import CORS

from server_logger import Logger
from __auth import SECRET_KEY, API_KEY

app = Flask(__name__)
CORS(app, expose_headers=["Content-Disposition"])  # configure send_file header

if platform.system() == 'Linux':
    IP_ADDR = '0.0.0.0'
else:
    IP_ADDR = '127.0.0.1'
PORT = 9906  # 게이트웨이, 공유기 포트포워딩 필요

log = Logger()


def invalid_auth_header():
    return request.headers.get('auth') != SECRET_KEY


def log_fail_tries():
    log.WARNING(
        f'private key unmatched - possible threat from {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}')


def bad_request():
    return 'Bad Request', 400


def success():
    return 'Success', 200


def get_latest_version():
    latest = 'v0.0.0'
    with open('./version.txt', encoding='UTF-8') as f:
        if versions := f.readlines():
            latest = versions[-1].replace('\n', '')
            log.INFO(f'{latest = }')
        else:
            log.ERROR('version info not exist')
    return latest


def save_log_file(txt: str) -> bool:
    log_file_dir = f'./report/{time.strftime("%Y-%m-%d", time.localtime(time.time()))}_{secrets.token_hex(6)}.log'
    try:
        with open(log_file_dir, 'w', encoding='utf-8') as f:
            log.INFO(f'writing {log_file_dir}')
            f.write(txt)
    except Exception as e:
        log.CRITICAL(e, '/ file write failure')
        return False
    return True


@app.get('/api/v1/server-health-check')
def health_check():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    return success()


@app.get('/api/v1/version-info')
def version():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    latest = get_latest_version()

    log.INFO(
        f'latest version informed to {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}')

    return jsonify({
        'document': {
            'new_version': latest
        }
    })


@app.post('/api/v1/download-latest')
def download():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    log.INFO(
        f'request file download from {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}')

    path = f'{os.getcwd()}/release/'
    fileName = f'{get_latest_version()}.exe'
    fullFilePath = path + fileName

    fileList = os.listdir('./release')
    if fileName in fileList:
        log.INFO(
            f'latest version sent to {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}')
        response = send_file(
            fullFilePath,
            mimetype='application/octet-stream',
            download_name=fileName,
            as_attachment=True
        )
        response.headers["x-filename"] = fileName
        response.headers["Access-Control-Expose-Headers"] = 'x-filename'
        return response

    log.ERROR('something went wrong while file transfer')
    return 'Not Found', 404


@app.post('/api/v1/map-html')
def map():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    data: dict = json.loads(request.get_data())
    log.INFO(
        f'requested map from {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}, {data = }')

    try:
        requested_lat = float(data.get('lat', 37.5074415))
        requested_lon = float(data.get('lon', 126.721393317))
        log.INFO(f'{requested_lat = }, {requested_lon = }')
    except ValueError as ve:
        log.ERROR(f'{ve} / {data.get("lat") = } {data.get("lon")}')
        return bad_request()

    return render_template('map.html', init_lat=requested_lat, init_lon=requested_lon, appkey=API_KEY)


@app.post('/api/v1/log-report')
def log_collector():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    data: dict = json.loads(request.get_data())
    log.INFO(
        f'sending log from {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} data off')

    if logtxt := data.get('log', None):
        log.INFO('log data successfully received')
        if save_log_file(logtxt):
            return success()

    return bad_request()


@app.post('/api/v1/report')
def report():
    if invalid_auth_header():
        log_fail_tries()
        return bad_request()

    data: dict = json.loads(request.get_data())

    log.INFO(
        f'{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}: {data = }')
    return success()


if __name__ == '__main__':
    if platform.system() == "Linux":
        import gevent.pywsgi
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        app_server = gevent.pywsgi.WSGIServer((IP_ADDR, PORT), app)
        app_server.serve_forever()

    else:
        app.run(host=IP_ADDR, port=PORT, use_reloader=False)
