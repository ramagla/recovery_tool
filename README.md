@"
# Recovery Tool

Ferramenta local para **recuperação de arquivos deletados (Undelete)** em volumes do Windows, com interface web simples para selecionar unidade de origem e pasta de destino.

## O que este sistema faz

- Varre uma unidade/volume (ex.: `C:` / `D:` / `E:`) buscando **entradas de arquivos deletados**.
- Tenta recuperar os arquivos e copiar para a pasta de destino escolhida.
- Exibe o progresso e o status da varredura/recuperação pela interface.
- Suporta recuperação de múltiplos tipos de arquivo (ex.: imagens, PDFs, ZIP/7Z e outros), conforme a disponibilidade dos dados no disco.

> Observação: a qualidade da recuperação depende do estado do disco. Se os setores já foram sobrescritos após a deleção, o arquivo pode ser recuperado parcialmente ou não ser recuperável.

## Requisitos

- Windows 10/11
- Python 3.10+ (recomendado)
- Permissão de Administrador (necessária para leitura direta do volume `\\.\X:`)

## Como executar em modo desenvolvimento

1) Criar e ativar ambiente virtual:

```powershell
cd C:\Projetos\recovery_tool
python -m venv venv
.\venv\Scripts\Activate.ps1
