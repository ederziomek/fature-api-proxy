import os
import sys
import requests
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import hashlib

# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
CORS(app, origins="*")

# Configurações do API Proxy
app.config['SECRET_KEY'] = 'api_proxy_secret_key_2025'
app.config['CACHE_TIMEOUT'] = 1800  # 30 minutos
app.config['RATE_LIMIT'] = 100  # requests por minuto

# Cache em memória simples
cache = {}
rate_limit_store = {}

# Configuração de APIs externas
EXTERNAL_APIS = {
    'fature-internal': {
        'base_url': 'http://api-gateway.fature.svc.cluster.local',
        'timeout': 30,
        'cache_enabled': True
    },
    'external-data': {
        'base_url': 'https://fature-real-data-service-production.up.railway.app',
        'timeout': 180,
        'cache_enabled': True
    },
    'reports': {
        'base_url': 'http://report-service.fature.svc.cluster.local',
        'timeout': 120,
        'cache_enabled': False  # Relatórios sempre atualizados
    }
}

def get_client_ip():
    """Obtém o IP real do cliente"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def check_rate_limit(client_ip):
    """Verifica se o cliente excedeu o rate limit"""
    now = datetime.now()
    minute_key = now.strftime('%Y-%m-%d-%H-%M')
    
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = {}
    
    if minute_key not in rate_limit_store[client_ip]:
        rate_limit_store[client_ip][minute_key] = 0
    
    # Limpa entradas antigas (mais de 2 minutos)
    for ip in list(rate_limit_store.keys()):
        for key in list(rate_limit_store[ip].keys()):
            key_time = datetime.strptime(key, '%Y-%m-%d-%H-%M')
            if now - key_time > timedelta(minutes=2):
                del rate_limit_store[ip][key]
        if not rate_limit_store[ip]:
            del rate_limit_store[ip]
    
    rate_limit_store[client_ip][minute_key] += 1
    return rate_limit_store[client_ip][minute_key] <= app.config['RATE_LIMIT']

def get_cache_key(url, params, headers):
    """Gera chave única para cache"""
    cache_data = {
        'url': url,
        'params': dict(params) if params else {},
        'headers': {k: v for k, v in headers.items() if k.lower() in ['authorization', 'content-type']}
    }
    return hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()

def get_from_cache(cache_key):
    """Recupera dados do cache se válidos"""
    if cache_key in cache:
        cached_data = cache[cache_key]
        if datetime.now() - cached_data['timestamp'] < timedelta(seconds=app.config['CACHE_TIMEOUT']):
            return cached_data['data']
        else:
            del cache[cache_key]
    return None

def set_cache(cache_key, data):
    """Armazena dados no cache"""
    cache[cache_key] = {
        'data': data,
        'timestamp': datetime.now()
    }

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'api-proxy',
        'timestamp': datetime.now().isoformat(),
        'cache_size': len(cache),
        'rate_limit_clients': len(rate_limit_store)
    }), 200

@app.route('/proxy/<api_name>/<path:endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_request(api_name, endpoint):
    """Proxy para APIs externas com cache e rate limiting"""
    
    # Verificar rate limit
    client_ip = get_client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({
            'error': 'Rate limit exceeded',
            'limit': app.config['RATE_LIMIT'],
            'window': '1 minute'
        }), 429
    
    # Verificar se a API está configurada
    if api_name not in EXTERNAL_APIS:
        return jsonify({
            'error': 'API not configured',
            'available_apis': list(EXTERNAL_APIS.keys())
        }), 404
    
    api_config = EXTERNAL_APIS[api_name]
    target_url = f"{api_config['base_url']}/{endpoint}"
    
    # Preparar headers
    headers = dict(request.headers)
    headers.pop('Host', None)  # Remove host header
    
    # Verificar cache para GET requests
    cache_key = None
    if request.method == 'GET' and api_config['cache_enabled']:
        cache_key = get_cache_key(target_url, request.args, headers)
        cached_response = get_from_cache(cache_key)
        if cached_response:
            response = Response(
                cached_response['content'],
                status=cached_response['status_code'],
                headers=cached_response['headers']
            )
            response.headers['X-Cache'] = 'HIT'
            return response
    
    try:
        # Fazer requisição para API externa
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            timeout=api_config['timeout'],
            allow_redirects=False
        )
        
        # Preparar resposta
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = {
            key: value for key, value in response.headers.items()
            if key.lower() not in excluded_headers
        }
        response_headers['X-Proxied-By'] = 'fature-api-proxy'
        response_headers['X-Cache'] = 'MISS'
        
        # Armazenar no cache se aplicável
        if request.method == 'GET' and api_config['cache_enabled'] and response.status_code == 200:
            cache_data = {
                'content': response.content,
                'status_code': response.status_code,
                'headers': response_headers
            }
            set_cache(cache_key, cache_data)
        
        return Response(
            response.content,
            status=response.status_code,
            headers=response_headers
        )
        
    except requests.exceptions.Timeout:
        return jsonify({
            'error': 'Request timeout',
            'api': api_name,
            'timeout': api_config['timeout']
        }), 504
        
    except requests.exceptions.ConnectionError:
        return jsonify({
            'error': 'Connection error',
            'api': api_name,
            'target_url': target_url
        }), 502
        
    except Exception as e:
        return jsonify({
            'error': 'Proxy error',
            'message': str(e)
        }), 500

@app.route('/cache/stats', methods=['GET'])
def cache_stats():
    """Estatísticas do cache"""
    now = datetime.now()
    valid_entries = 0
    expired_entries = 0
    
    for cache_key, cache_data in cache.items():
        if now - cache_data['timestamp'] < timedelta(seconds=app.config['CACHE_TIMEOUT']):
            valid_entries += 1
        else:
            expired_entries += 1
    
    return jsonify({
        'total_entries': len(cache),
        'valid_entries': valid_entries,
        'expired_entries': expired_entries,
        'cache_timeout': app.config['CACHE_TIMEOUT'],
        'rate_limit_clients': len(rate_limit_store)
    })

@app.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Limpa o cache"""
    cache.clear()
    return jsonify({
        'message': 'Cache cleared successfully',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/apis', methods=['GET'])
def list_apis():
    """Lista APIs disponíveis"""
    return jsonify({
        'available_apis': {
            name: {
                'base_url': config['base_url'],
                'timeout': config['timeout'],
                'cache_enabled': config['cache_enabled']
            }
            for name, config in EXTERNAL_APIS.items()
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)

