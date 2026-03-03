# Recovery Tool

Ferramenta local para **recuperação de arquivos deletados (Undelete)** em volumes do Windows, com **interface web** simples para selecionar a **unidade de origem** e a **pasta de destino**.

---

## O que este sistema faz

- Varre uma unidade/volume (ex.: `C:` / `D:` / `E:`) buscando **entradas de arquivos deletados**.
- Tenta recuperar os arquivos e copiar para a pasta de destino escolhida.
- Exibe o progresso e o status da varredura/recuperação pela interface.
- Suporta recuperação de múltiplos tipos de arquivo (ex.: imagens, PDFs, ZIP/7Z e outros), conforme a disponibilidade dos dados no disco.

> **Observação:** a qualidade da recuperação depende do estado do disco. Se os setores já foram sobrescritos após a deleção, o arquivo pode ser recuperado parcialmente ou não ser recuperável.

---

## Requisitos

- Windows 10/11
- Python 3.10+ (recomendado)
- Permissão de Administrador (**necessária** para leitura direta do volume `\\.\X:`)

---

## Como executar em modo desenvolvimento

### 1) Criar e ativar o ambiente virtual

```powershell
cd C:\Projetos\recovery_tool
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2) Instalar dependências

```powershell
pip install -r requirements.txt
```

### 3) Executar a aplicação

```powershell
python app.py
```

### 4) Abrir no navegador

```text
http://127.0.0.1:5000
```

> **Importante:** execute o terminal como **Administrador**, caso contrário a leitura do volume pode falhar.

---

## Como gerar o executável (PyInstaller)

### Pré-requisitos

Instale o PyInstaller no mesmo ambiente virtual do projeto:

```powershell
pip install pyinstaller
```

### Build usando o arquivo `.spec`

Na raiz do projeto (onde está o `RecoveryTool.spec`), execute:

```powershell
pyinstaller --noconfirm --clean RecoveryTool.spec
```

### Saída do executável

Após o build, o executável será gerado em:

```text
dist\RecoveryTool\
```

> Dependendo do `.spec`, pode existir também um executável diretamente em `dist\`.

---

## Boas práticas e cuidados

- **Nunca** salve os arquivos recuperados na **mesma unidade** que está sendo analisada (para evitar sobrescrita de dados).
- Para maximizar as chances de recuperação:
  - pare de usar a unidade assim que notar a deleção;
  - recupere para um disco externo ou outra partição.
- Em casos de corrupção física/ruídos de disco, considere **clonagem setor-a-setor** antes de tentar recuperar.
