"""API HTTP educacional do inventário. Execute somente em rede confiável."""
import json
import math
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from Dados_Beta import ativos, salvar_ativos
from Enums_Beta import criar_equipamento
from Riscos_Beta import calcular_riscos, configurar_dependencia

LOCK = threading.RLock()


def procurar(id_):
    return next((a for a in ativos if a.id == id_), None)


class Handler(BaseHTTPRequestHandler):
    def enviar(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def receber(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 100_000:
            raise ValueError('JSON muito grande')
        raw = self.rfile.read(length)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('O corpo deve ser um objeto JSON')
        return data

    def processar(self, method):
        partes = [p for p in urlparse(self.path).path.split('/') if p]
        with LOCK:
            try:
                if method == 'GET' and partes == ['health']:
                    return self.enviar(200, {'status': 'ok'})
                if method == 'GET' and partes == ['ativos']:
                    return self.enviar(200, [a.para_dicionario() for a in ativos])
                if method == 'GET' and partes == ['riscos']:
                    r = calcular_riscos()
                    return self.enviar(200, r)
                if method == 'POST' and partes == ['ativos']:
                    dado = self.receber()
                    id_ = int(dado['id'])
                    if id_ <= 0 or procurar(id_):
                        raise ValueError('ID deve ser positivo e único')
                    for campo in ('nome', 'setor', 'responsavel'):
                        if not str(dado.get(campo, '')).strip():
                            raise ValueError('Campo obrigatório: '+campo)
                    a = criar_equipamento(id_, dado['nome'], dado['tipo'], dado['setor'], dado['responsavel'])
                    ativos.append(a)
                    salvar_ativos()
                    return self.enviar(201, a.para_dicionario())
                if len(partes) >= 2 and partes[0] == 'ativos':
                    id_ = int(partes[1])
                    a = procurar(id_)
                    if a is None:
                        return self.enviar(404, {'erro': 'Ativo não encontrado'})
                    if method == 'GET' and len(partes) == 2:
                        return self.enviar(200, a.para_dicionario())
                    if method == 'DELETE' and len(partes) == 2:
                        ativos.remove(a)
                        for outro in ativos:
                            outro.dependencias.pop(str(id_), None)
                        salvar_ativos()
                        return self.enviar(200, {'removido': id_})
                    if method == 'PUT' and len(partes) == 2:
                        dado = self.receber()
                        for campo in ('nome', 'setor', 'responsavel'):
                            if campo in dado:
                                if not isinstance(dado[campo], str) or not dado[campo].strip():
                                    raise ValueError('Campo inválido: '+campo)
                        novo = criar_equipamento(a.id, dado.get('nome', a.nome), dado.get('tipo', a.tipo),
                                               dado.get('setor', a.setor), dado.get('responsavel', a.responsavel))
                        novo.vulnerabilidades = a.vulnerabilidades
                        novo.dependencias = a.dependencias
                        ativos[ativos.index(a)] = novo
                        salvar_ativos()
                        return self.enviar(200, novo.para_dicionario())
                    if len(partes) == 3 and partes[2] == 'vulnerabilidades' and method == 'POST':
                        dado = self.receber()
                        for campo in ('descricao', 'categoria', 'severidade', 'status', 'nota_cvss'):
                            if campo not in dado:
                                raise ValueError('Campo ausente: '+campo)
                        import uuid
                        nota = float(dado['nota_cvss'])
                        if not math.isfinite(nota) or not 0 <= nota <= 10:
                            raise ValueError('nota_cvss deve estar entre 0 e 10')
                        if not str(dado['descricao']).strip() or not str(dado['categoria']).strip():
                            raise ValueError('Descrição/categoria obrigatórias')
                        v = {k: dado[k] for k in ('descricao', 'categoria', 'severidade', 'status')}
                        v['id'] = str(uuid.uuid4())
                        v['nota_cvss'] = nota
                        a.vulnerabilidades.append(v)
                        salvar_ativos()
                        return self.enviar(201, v)
                if method == 'POST' and partes == ['dependencias']:
                    dado = self.receber()
                    a = configurar_dependencia(dado['destino_id'], dado['origem_id'], dado['peso'])
                    salvar_ativos()
                    return self.enviar(200, a.para_dicionario())
                return self.enviar(404, {'erro': 'Rota não encontrada'})
            except (ValueError, KeyError, TypeError, IndexError, OverflowError, json.JSONDecodeError) as exc:
                return self.enviar(400, {'erro': str(exc)})

    def do_GET(self): self.processar('GET')
    def do_POST(self): self.processar('POST')
    def do_PUT(self): self.processar('PUT')
    def do_DELETE(self): self.processar('DELETE')


if __name__ == '__main__':
    porta = int(os.environ.get('PORT', '8000'))
    servidor = ThreadingHTTPServer(('0.0.0.0', porta), Handler)
    print(f'API pronta na porta {porta}', flush=True)
    servidor.serve_forever()
