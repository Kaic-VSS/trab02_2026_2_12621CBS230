"""Modelo de risco linear do Trabalho 02: b=Mv; (I-A)x=b."""
import math
import numpy as np
from Dados_Beta import ativos, salvar_ativos
from Validacoes_Beta import ler_campo

# Compatibilidade com vulnerabilidades criadas antes de existir nota CVSS.
# São valores convencionais documentados, NÃO CVSS oficiais.
MAPA_LEGADO = {"baixa": 2.0, "média": 5.0, "media": 5.0,
               "alta": 7.5, "crítica": 9.5, "critica": 9.5}


def nota_vulnerabilidade(vulnerabilidade):
    if "nota_cvss" in vulnerabilidade:
        valor = float(vulnerabilidade["nota_cvss"])
        if not math.isfinite(valor) or not 0 <= valor <= 10:
            raise ValueError("Nota CVSS deve estar entre 0 e 10.")
        return valor
    nome = str(vulnerabilidade.get("severidade", "")).strip().lower()
    if nome not in MAPA_LEGADO:
        raise ValueError("Vulnerabilidade sem nota CVSS e sem severidade conhecida.")
    return MAPA_LEGADO[nome]


def configurar_dependencia(destino_id, origem_id, peso, equipamentos=None):
    """A[destino,origem] = fração transmitida do risco da origem ao destino."""
    if equipamentos is None:
        equipamentos = ativos
    indice = {a.id: a for a in equipamentos}
    destino_id, origem_id = int(destino_id), int(origem_id)
    if destino_id not in indice or origem_id not in indice:
        raise ValueError("Os dois equipamentos precisam estar cadastrados.")
    if destino_id == origem_id:
        raise ValueError("Um equipamento não pode depender de si mesmo.")
    peso = float(peso)
    if not math.isfinite(peso) or not 0 <= peso < 1:
        raise ValueError("O peso deve estar em [0, 1).")
    destino = indice[destino_id]
    novas = dict(destino.dependencias)
    if peso == 0:
        novas.pop(str(origem_id), None)
    else:
        novas[str(origem_id)] = peso
    if sum(float(x) for x in novas.values()) >= 1 - 1e-12:
        raise ValueError("Soma dos pesos das dependências do destino deve ser menor que 1.")
    destino.dependencias = novas
    return destino


def calcular_riscos(equipamentos=None):
    """Constrói M, v, A e resolve sem calcular inversa explicitamente."""
    if equipamentos is None:
        equipamentos = ativos
    equipamentos = sorted(equipamentos, key=lambda a: a.id)
    n = len(equipamentos)
    if n == 0:
        return {"equipamentos": [], "M": [], "v": [], "A": [], "b": [], "x": [], "condicao": None}
    indice = {a.id: i for i, a in enumerate(equipamentos)}
    if len(indice) != n:
        raise ValueError("IDs de equipamentos duplicados.")
    colunas = []
    for i, ativo in enumerate(equipamentos):
        for vulnerabilidade in ativo.vulnerabilidades:
            colunas.append((i, nota_vulnerabilidade(vulnerabilidade)))
    M = np.zeros((n, len(colunas)), dtype=float)
    v = np.array([nota for _, nota in colunas], dtype=float)
    for j, (i, _) in enumerate(colunas):
        M[i, j] = 1.0
    b = M @ v
    A = np.zeros((n, n), dtype=float)
    for i, ativo in enumerate(equipamentos):
        for origem, peso in ativo.dependencias.items():
            origem_id = int(origem)
            if origem_id not in indice:
                raise ValueError(f"Dependência para ID inexistente: {origem_id}")
            j = indice[origem_id]
            valor = float(peso)
            if i == j or not math.isfinite(valor) or not 0 <= valor < 1:
                raise ValueError("Dependência inválida: origem igual ao destino ou peso fora do intervalo.")
            A[i, j] = valor
        if A[i, :].sum() >= 1 - 1e-12:
            raise ValueError("Dependências com soma de linha >= 1.")
    sistema = np.eye(n) - A
    if np.linalg.matrix_rank(sistema) < n:
        raise ValueError("I-A não é invertível. Corrija as dependências.")
    condicao = float(np.linalg.cond(sistema))
    if not math.isfinite(condicao) or condicao > 1e12:
        raise ValueError("Sistema numericamente instável (número de condição elevado).")
    x = np.linalg.solve(sistema, b)
    return {"equipamentos": [a.id for a in equipamentos], "M": M.tolist(),
            "v": v.tolist(), "A": A.tolist(), "b": b.tolist(),
            "x": x.tolist(), "condicao": condicao}


def exibir_riscos():
    try:
        resultado = calcular_riscos()
        if not resultado["equipamentos"]:
            print("Nenhum equipamento cadastrado.")
            return
        print("\n=== RISCO LINEAR DOS EQUIPAMENTOS ===")
        for id_, proprio, efetivo in zip(resultado["equipamentos"], resultado["b"], resultado["x"]):
            print(f"Equipamento {id_}: próprio={proprio:.3f} | efetivo={efetivo:.3f}")
        print(f"Condição de (I-A): {resultado['condicao']:.3g}")
    except ValueError as erro:
        print(f"Não foi possível calcular: {erro}")


def menu_dependencias():
    print("\nUma dependência A[i,j] transmite ao equipamento i uma fração do risco de j.")
    try:
        destino = int(ler_campo("ID do equipamento que recebe o risco: "))
        origem = int(ler_campo("ID do equipamento de origem: "))
        peso = float(ler_campo("Peso [0,1), 0 para remover: ").replace(",", "."))
        configurar_dependencia(destino, origem, peso)
        salvar_ativos()
        print("Dependência salva no JSON.")
    except (ValueError, OverflowError) as erro:
        print(f"Entrada ou dependência inválida: {erro}")
