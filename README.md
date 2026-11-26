# Trabalho 02 — Inventário de ativos e vulnerabilidades

Projeto acadêmico em Python, POO, JSON, matriz linear de riscos e Docker. Baseado no código fornecido pelo estudante, com correções preservando os nomes de arquivos do projeto anterior.

## 1. Requisitos e decisões

- Cada ativo é uma instância de `Equipamento` ou subclasse (`Notebook`, `Servidor`, `Roteador`, `Software`). O tipo é definido por `TipoAtivo` (Enum).
- Os objetos são serializados em um **array JSON** em `ativos.json`. As dependências são armazenadas **dentro de cada objeto**: `"dependencias": {"id_origem": peso}`. Um peso representa a fração do risco de outro equipamento que chega ao equipamento atual.
- `Riscos_Beta.py` implementa `b=Mv` e resolve `(I-A)x=b` com `numpy.linalg.solve`, após verificação de posto e número de condição. A soma das dependências de cada equipamento deve ser **menor que 1**, favorecendo a invertibilidade.
- Cada registro de vulnerabilidade cadastrada representa uma coluna em M (nota CVSS de 0 a 10), vinculada a um equipamento. Se aparecer a mesma descrição em dois ativos, são dois registros/colunas; por opção de modelagem simplificada, cada associação tem seu próprio identificador.
- **Registros antigos:** quando `nota_cvss` não está disponível, as classes Baixa/Média/Alta/Crítica são convertidas convencionalmente em 2/5/7,5/9,5 para permitir migração. **Essa conversão NÃO corresponde a notas CVSS oficiais.** Corrija as notas numéricas na fonte para apresentações do modelo.
- Não há autenticação na API educacional. Execute apenas em computador/rede de testes autorizada, não publique na internet aberta sem proteção.

## 2. Execução no Windows — VS Code

Abra um terminal na pasta que contém `Menus_Alpha.py`:

```powershell
py -m pip install -r requirements-dev.txt
py Menus_Alpha.py
```

Para testes:

```powershell
py -m pytest -q
```

Se `py` não funcionar, use `python` no lugar. **Não sobrescreva seu JSON original sem backup.** Se quiser usar outro caminho, defina `ATIVOS_JSON` antes de iniciar o processo.

## 3. Menu de riscos

- **Menu principal → 3 → 2:** cadastrar dependência. Ex.: equipamento 2 recebe 20% do risco do equipamento 1: `destino=2`, `origem=1`, `peso=0.2`.
- **Menu principal → 3 → 1:** mostrar `b` (próprio) e `x` (efetivo) por ID.
- Para excluir uma dependência, informe peso `0`. Não é permitido criar autodependência nem soma de dependências de um equipamento maior ou igual a 1.
- No cadastro das vulnerabilidades, o campo `nota_cvss` numérico é solicitado além da classificação textual.

### Exemplo manual de validação

Três ativos, vulnerabilidades de notas 5 no ativo 1, 4 no ativo 2 e nenhuma no ativo 3. Configure dependências `A[2,1]=0.2`, `A[3,2]=0.5` (IDs iniciando em 1). Assim:

```
M = [[1,0], [0,1], [0,0]]
v = [5,4]
b = [5,4,0]
A = [[0,0,0], [0.2,0,0], [0,0.5,0]]
x = [5,5,2.5]
```

Verificação: `x2 = b2 + 0.2*x1 = 5`, `x3 = 0 + 0.5*x2 = 2.5`.

## 4. Docker

O arquivo `compose.yaml` define a API como serviço contínuo, com reinício automático, volume persistente e verificação de saúde.

```powershell
docker compose up -d --build
docker compose ps
docker compose logs --tail 30
docker compose down
```

- Teste de saúde local: `http://localhost:2230/health`.
- JSON dos dados do Docker fica no **volume nomeado**, não necessariamente no `ativos.json` da sua pasta do Windows.
- `docker compose down` preserva o volume; **não use `docker compose down -v`** se deseja manter os cadastros.
- O serviço começa com um volume vazio quando implantado pela primeira vez. Para transportar dados antigos, será necessária uma migração/cópia cuidadosa do JSON.
- O serviço expõe a porta **somente no localhost** do computador/servidor, como medida de segurança. Se o docente exigir acesso remoto, alinhe com ele a forma autorizada de disponibilizar o acesso, por exemplo túnel SSH ou proxy com autenticação.
- Estar configurado com `restart: unless-stopped` **não comprova** funcionamento por 24 horas. O servidor real precisa ficar ativo, e deve-se registrar horários/estado, logs e confirmar com o docente qual evidência é aceita.
- O menu de terminal continua acessível localmente por `py Menus_Alpha.py`; a API Docker funciona sem solicitar input e pode permanecer ativa durante 24h.

## 5. API REST e Postman

Serviço HTTP iniciado com `py API_Beta.py` (após instalar dependências) ou `docker compose up -d --build`.

| Método | Caminho | Ação |
|---|---|---|
| GET | `/health` | Saúde do processo |
| GET | `/ativos` | Lista todos |
| GET | `/ativos/1` | Consulta um |
| POST | `/ativos` | Cria um |
| PUT | `/ativos/1` | Atualiza dados básicos |
| DELETE | `/ativos/1` | Remove ativo e associações |
| POST | `/ativos/1/vulnerabilidades` | Cadastra vulnerabilidade |
| POST | `/dependencias` | Define dependência |
| GET | `/riscos` | Matrizes M, v, A, risco próprio b e risco efetivo x |

O arquivo `Postman_Trabalho02.json` pode ser importado no Postman. A coleção usa `{{base_url}} = http://localhost:2230`. Use a requisição de cadastrar ativo antes das demais em uma base vazia.

## 6. GitHub

- Coloque `testes.yml` na pasta **`.github/workflows/`**, não na raiz.
- Coloque `test_projeto.py` dentro da pasta `tests/`.
- O repositório precisa registrar histórico real de desenvolvimento com branches e merges, conforme a avaliação anterior; arquivos criados agora não simulam histórico passado.
- Revise `.gitignore`, evite credenciais e testes com dados pessoais, e envie os arquivos de código ao repositório autorizado.

## 7. Limitações e pendências antes da avaliação

1. Não foi executado um contêiner Docker real nem realizada hospedagem por 24h neste ambiente. Essa comprovação deve ser feita no servidor disponibilizado pelo professor, em ambiente autorizado.
2. A API é educacional e ainda não tem autenticação, bloqueio de abuso ou transações; não a exponha como serviço público.
3. Falta confirmar no GitHub o histórico de **mais de dois branches e merges** solicitado na primeira avaliação.
4. Faça uma demonstração de cinco minutos com cadastro, persistência, consulta, dependências e risco. Entenda o cálculo matemático e a escolha de estrutura de dados antes de apresentar.
