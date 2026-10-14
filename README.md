# PrivEsc Enumerator (CTF Mode)

Ferramenta de enumeração e ajuda de exploração para privilege escalation em Linux em CTFs ou labs autorizados.

## Objetivo

A pessoa começa como utilizador normal e usa esta ferramenta para descobrir vetores de escalada. A ferramenta funciona em dois modos:

- `enum`: apenas enumera o sistema e gera relatórios
- `exploit` / `suggest`: roda a enumeração e depois usa um motor de sugestões para apontar os vetores mais prováveis

> Importante: isto não executa exploits automaticamente. É uma ferramenta de auxiliador de CTF, que mostra os payloads e vetores mais comuns para investigação.

## Stack

- Bash
- Python 3
- `sudo`, `find`, `getcap`, `crontab`, `systemctl`, `uname`

## Uso

```bash
cd privilege_escalation_enumerator
./scripts/priv_esc_enum.sh enum
./scripts/priv_esc_enum.sh exploit
./scripts/priv_esc_enum.sh suggest
```

Ou com pasta de output:

```bash
./scripts/priv_esc_enum.sh exploit /tmp/priv-esc-output
```

## O que enumera

- identidade e grupos
- kernel e distro
- `sudo -l`
- `SUID` e `SGID`
- `capabilities`
- cron jobs
- `systemd` services
- paths graváveis
- sugestões de exploração para cada vetor

## Modo exploit/suggest

O modo `exploit` funciona como um mecanismo de “auto-suggest”, parecido a um `sqlmap` de enumeração: recorre à informação recolhida e aponta os vetores mais prováveis, com comandos e padrões conhecidos.

Ainda assim, não executa a escalada automaticamente.

## Notas

- Usa-se em CTFs autorizados ou laboratórios controlados.
- Recomendado para learning, Blue Team, Red Team em ambiente controlado.
- O exploit final sempre deve ser aplicado manualmente e validado no contexto do desafio.

## Autor

0xander
