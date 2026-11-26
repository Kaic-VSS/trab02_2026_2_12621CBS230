import json
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import numpy as np
import pytest

import Dados_Beta as dados
from Enums_Beta import Equipamento, Notebook, Servidor, criar_equipamento
from Riscos_Beta import calcular_riscos, configurar_dependencia
from API_Beta import Handler
from http.server import ThreadingHTTPServer
import Ativos_Beta as cadastro


@pytest.fixture
def dados_isolados(tmp_path, monkeypatch):
    monkeypatch.setattr(dados, 'caminho_json', tmp_path / 'ativos.json')
    dados.ativos.clear()
    yield dados
    dados.ativos.clear()


def test_heranca_e_polimorfismo():
    assert isinstance(criar_equipamento(1, 'A', 1, 'TI', 'Ana'), Notebook)
    assert isinstance(criar_equipamento(2, 'B', 2, 'TI', 'Ana'), Servidor)
    a = criar_equipamento(1, 'A', 1, 'TI', 'Ana')
    assert a.descricao_tecnica() != Equipamento.descricao_tecnica(a)


def test_json_lista_e_dependencias(dados_isolados):
    a = criar_equipamento(1, 'A', 1, 'TI', 'Ana')
    b = criar_equipamento(2, 'B', 2, 'TI', 'Ana')
    dados.ativos.extend([a, b])
    configurar_dependencia(2, 1, 0.3)
    dados.salvar_ativos()
    registro = json.loads(dados.caminho_json.read_text(encoding='utf8'))
    assert isinstance(registro, list)
    assert registro[1]['dependencias'] == {'1': 0.3}
    assert isinstance(dados.carregar_ativos()[1], Servidor)


def test_matriz_e_riscos(dados_isolados):
    a = criar_equipamento(1, 'A', 1, 'TI', 'Ana')
    b = criar_equipamento(2, 'B', 2, 'TI', 'Ana')
    c = criar_equipamento(3, 'C', 3, 'TI', 'Ana')
    a.vulnerabilidades.append({'descricao':'Falha A','nota_cvss':5.0})
    b.vulnerabilidades.append({'descricao':'Falha B','nota_cvss':4.0})
    dados.ativos.extend([a, b, c])
    configurar_dependencia(2, 1, 0.2)
    configurar_dependencia(3, 2, 0.5)
    r = calcular_riscos()
    assert r['M'] == [[1, 0], [0, 1], [0, 0]]
    assert r['v'] == [5, 4]
    assert r['b'] == [5, 4, 0]
    assert r['x'] == pytest.approx([5, 5, 2.5])
    assert np.allclose((np.eye(3)-np.array(r['A'])) @ r['x'], r['b'])


def test_sem_vulnerabilidades(dados_isolados):
    dados.ativos.append(criar_equipamento(1, 'A', 1, 'TI', 'Ana'))
    r=calcular_riscos()
    assert r['M']==[[]]
    assert r['b']==[0]
    assert r['x']==[0]


@pytest.mark.parametrize('origem,peso', [(1,0.1),(2,-0.1),(2,1.0),(2,float('nan'))])
def test_dependencia_invalida(dados_isolados, origem, peso):
    dados.ativos.extend([criar_equipamento(1,'A',1,'TI','A'),criar_equipamento(2,'B',2,'TI','B')])
    with pytest.raises(ValueError):
        configurar_dependencia(1, origem, peso)


def test_soma_pesos_impede_instabilidade(dados_isolados):
    for i in (1,2,3):
        dados.ativos.append(criar_equipamento(i, 'A', 1, 'TI', 'A'))
    configurar_dependencia(1, 2, 0.6)
    with pytest.raises(ValueError):
        configurar_dependencia(1, 3, 0.4)
    assert dados.ativos[0].dependencias == {'2':0.6}


def test_dados_legados(dados_isolados):
    a=criar_equipamento(1,'A',1,'TI','Ana')
    a.vulnerabilidades.append({'descricao':'Legada','severidade':'Alta'})
    dados.ativos.append(a)
    assert calcular_riscos()['b'] == [7.5]


def test_json_mantem_atualizacoes(dados_isolados, monkeypatch):
    a=criar_equipamento(1,'A',1,'TI','Ana')
    dados.ativos.append(a)
    monkeypatch.setattr('builtins.input', lambda _: 's')
    cadastro.RemoverATV(a)
    assert dados.carregar_ativos() == []


def test_cadastro_sem_vulnerabilidades(dados_isolados, monkeypatch):
    entradas=iter(['1','Laptop','1','TI','Ana','n'])
    monkeypatch.setattr('builtins.input', lambda _: next(entradas))
    cadastro.cadastro_ativo()
    assert len(dados.carregar_ativos()) == 1
    assert dados.carregar_ativos()[0].vulnerabilidades == []


def test_remocao_limpa_dependencias(dados_isolados, monkeypatch):
    a=criar_equipamento(1,'A',1,'TI','Ana')
    b=criar_equipamento(2,'B',2,'TI','Ana')
    dados.ativos.extend([a,b])
    configurar_dependencia(2,1,0.3)
    monkeypatch.setattr('builtins.input', lambda _: 's')
    cadastro.RemoverATV(a)
    assert b.dependencias == {}


@pytest.fixture
def api(dados_isolados):
    srv=ThreadingHTTPServer(('127.0.0.1',0), Handler)
    t=threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f'http://127.0.0.1:{srv.server_port}'
    srv.shutdown()
    srv.server_close()
    t.join(timeout=2)


def consultar(url, method='GET', data=None):
    payload = json.dumps(data).encode() if data is not None else None
    req=Request(url, data=payload, method=method, headers={'Content-Type':'application/json'})
    try:
        with urlopen(req, timeout=2) as res:
            return res.status, json.load(res)
    except HTTPError as e:
        return e.code, json.load(e)


def test_api_crud_e_risco(api):
    assert consultar(api+'/health')[1]['status']=='ok'
    status,a=consultar(api+'/ativos','POST', {'id':1,'nome':'Servidor','tipo':2,'setor':'TI','responsavel':'Ana'})
    assert status==201
    assert consultar(api+'/ativos','POST', {'id':1,'nome':'A','tipo':1,'setor':'TI','responsavel':'Ana'})[0]==400
    assert consultar(api+'/ativos/1')[1]['classe']=='Servidor'
    status,v=consultar(api+'/ativos/1/vulnerabilidades','POST', {'descricao':'Falha','categoria':'Rede','severidade':'Alta','status':'Aberta','nota_cvss':7.2})
    assert status==201
    assert consultar(api+'/riscos')[1]['b'] == pytest.approx([7.2])
    assert consultar(api+'/ativos/1','PUT',{'nome':'Servidor novo'})[1]['nome']=='Servidor novo'
    assert consultar(api+'/ativos/1','DELETE')[0]==200
    assert consultar(api+'/ativos')[1]==[]


def test_api_dependencia(api):
    for i in (1,2):
        assert consultar(api+'/ativos','POST', {'id':i,'nome':f'A{i}','tipo':1,'setor':'TI','responsavel':'A'})[0]==201
    assert consultar(api+'/dependencias','POST',{'destino_id':2,'origem_id':1,'peso':0.2})[0]==200
    assert consultar(api+'/ativos/2')[1]['dependencias'] == {'1':0.2}
