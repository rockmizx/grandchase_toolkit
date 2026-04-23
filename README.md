# GrandChase Toolkit

Toolkit completo para extrair, decriptar e decompilar arquivos do GrandChase (Epic Games).

## Estrutura

```
grandchase_toolkit/
├── README.md                  ← Este arquivo
├── requirements.txt           ← Dependências Python
├── keys/
│   ├── algo3_keys.json        ← Chaves AES-256-CBC (acumula entre updates)
│   ├── algo2_table_full.bin   ← Tabela Blowfish (13.790 entradas)
│   ├── algo2_table.bin        ← Tabela Blowfish (984 entradas, legada)
│   └── offsets.json           ← Offsets das funções crypto
├── scripts/
│   ├── 01_dump_exe.py         ← Dump do .exe desprotegido (Ghidra)
│   ├── 02_find_offsets.py     ← Encontrar offsets após atualização
│   ├── 03_capture_keys.py     ← Capturar chaves AES em runtime
│   ├── 04_extract_koms.py     ← Extrair arquivos dos KOMs
│   ├── 05_decrypt_all.py      ← Decriptar Lua/STG
│   ├── 06_decompile_all.py    ← Decompilar KL → Lua legível
│   └── pipeline.py            ← Pipeline completo (04→05→06)
├── extractor/
│   └── kom_crypto.py          ← Engine de parsing KOM (V0.1 a V1.0)
├── decompiler/
│   └── ljd_decompiler/        ← Decompilador LJD (KL bytecode)
├── docs/
│   ├── UPDATE_GUIDE.md        ← Como atualizar offsets/chaves
│   ├── KOM_FORMAT.md          ← Formato KOM documentado
│   └── CRYPTO_PIPELINE.md     ← Pipeline de criptografia
└── output/
    ├── extracted/             ← Saída da extração
    ├── decrypted/             ← Saída da decriptação
    └── decompiled/            ← Saída da decompilação
```

## Instalação

```bash
# 1. Instalar Python 3.10+
# 2. Instalar dependências
pip install -r requirements.txt

# Ou com venv:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Uso Rápido

### Pipeline Completo (offline — sem precisar do jogo aberto)

```bash
# Extrair + Decriptar + Decompilar todos os KOMs
python scripts/pipeline.py

# Com caminho customizado do jogo
python scripts/pipeline.py --game-dir "C:\Program Files\Epic Games\GrandChaseuVQ2P"

# Apenas decriptar e decompilar (KOMs já extraídos)
python scripts/pipeline.py --skip-extract

# Filtrar por nome
python scripts/pipeline.py --filter Solene
```

### Scripts Individuais

```bash
# Extrair KOMs
python scripts/04_extract_koms.py
python scripts/04_extract_koms.py --input arquivo.kom
python scripts/04_extract_koms.py --list     # Apenas listar

# Decriptar Lua/STG
python scripts/05_decrypt_all.py
python scripts/05_decrypt_all.py --algo3-only

# Decompilar bytecode KL
python scripts/06_decompile_all.py
python scripts/06_decompile_all.py --filter CharScript
```

## Após Atualização do Jogo

Quando o jogo atualiza, os offsets das funções crypto mudam e podem surgir novas
chaves AES. Siga estes passos:

```bash
# 1. Abra o jogo e espere a tela de login

# 2. Encontrar novos offsets (automático via assinaturas de bytes)
.venv\Scripts\python.exe scripts/02_find_offsets.py

# 3. Capturar novas chaves AES (⚠ terminal como ADMINISTRADOR, navegue pelo jogo)
.venv\Scripts\python.exe scripts/03_capture_keys.py --auto-merge

# 4. Rodar o pipeline normalmente
.venv\Scripts\python.exe scripts/pipeline.py --force
```

Para detalhes completos sobre o processo de atualização, veja `docs/UPDATE_GUIDE.md`.

## Algoritmos de Criptografia

O GrandChase usa 3 algoritmos para proteger os arquivos dentro dos KOMs:

| Algoritmo | Criptografia | Arquivos |
|-----------|-------------|----------|
| **Algo 0** | zlib apenas (sem encriptação) | Maioria dos recursos |
| **Algo 2** | Blowfish-ECB → zlib | Assets (.frm, .dds, .p3m) |
| **Algo 3** | AES-256-CBC → zlib → Blowfish-ECB | Lua e STG |

Para detalhes técnicos, veja `docs/CRYPTO_PIPELINE.md`.

## Chaves e Tabelas

### algo3_keys.json
Base de pares (key, iv) para AES-256-CBC. Acumula entre atualizações.
Capturadas via Frida em runtime (script 03).

### algo2_table_full.bin
Tabela de valores para derivação de chaves Blowfish.
13.790 entradas × 5 × int64 = 551.600 bytes.
Derivação: `sum(5_valores)` → `str(total).encode('ascii')` → SHA-256 → chave de 32 bytes.

### offsets.json
RVAs das funções crypto no GrandChase.exe (relativos ao módulo base).
Inclui assinaturas de bytes para busca automática e histórico de offsets.

## Notas

- **Frida** é necessário apenas para os scripts 01, 02 e 03 (runtime hooks).
  Os scripts 04, 05 e 06 funcionam 100% offline.
- **Administrador**: O script 03 (capture_keys) precisa rodar em terminal com
  privilégios de Administrador para o Frida injetar no processo protegido.
- **Themida**: O jogo usa Themida para proteção. O script 03 usa retry automático
  e setTimeout no JS para aguardar o desempacotamento.
- **venv**: Sempre use `.venv\Scripts\python.exe` para garantir o Python 64-bit
  correto com Frida compatível.
- O decompilador LJD usa um formato customizado de bytecode (KL, não LuaJIT padrão)
  com remapeamento de 97 opcodes.
