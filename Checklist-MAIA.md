# Checklist Completo para Metodologia MAIA 

## Introdução

Este checklist completo fornece um guia passo a passo para utilizar a metodologia MAIA. O objetivo é auxiliar na identificação de vulnerabilidades em sistemas de computadores, focando na coleta de informações, enumeração e exploração limitada.

## Metodologia MAIA

A metodologia MAIA divide o processo em quatro fases:

- **Coleta de Informação:** Reunir informações sobre o alvo, como endereços IP, serviços em execução e vulnerabilidades conhecidas.
- **Enumeração:** Explorar os sistemas e serviços do alvo para identificar pontos de entrada e vulnerabilidades.
- **Exploração Limitada:** Explorar as vulnerabilidades encontradas para obter acesso aos sistemas e dados do alvo, de forma limitada e controlada.

## Ferramentas e Recursos

### Fase 1: Coleta de Informação

**Objetivo:** Reunir o máximo de informações sobre o alvo.

**Ferramentas:**
- Google Hacking: Busca por informações confidenciais através do Google.
- Crt.sh: Busca por certificados SSL/TLS que podem revelar subdomínios e hosts adicionais.
- Webarchive: Acessa versões arquivadas de sites para encontrar informações que não estão mais disponíveis online.
- Shodan: Busca por dispositivos e serviços expostos na internet.

**Outras ferramentas:**
- TheHarvester: Coleta emails e outros dados de sites e redes sociais.
- SpiderFoot: Coleta informações de diversos recursos online.
- Netcraft: Mapeia redes e identifica hosts e serviços ativos.
- WhatWeb: Identifica tecnologias web em uso em um site.
- Censys: Busca por hosts e serviços com base em diversas características.
- ZoomEye: Busca por hosts e serviços com base em diversas características.

**Recursos Adicionais:**
- [Guia de Coleta de Informação](https://dle.rae.es/inv%C3%A1lido)
- [Lista de ferramentas de coleta de informação](https://dle.rae.es/inv%C3%A1lido)

### Fase 2: Enumeração

**Objetivo:** Explorar os sistemas e serviços do alvo para identificar pontos de entrada e vulnerabilidades.

**Ferramentas:**
- Enumeração de DNS:
    - DNSMap: Mapeia e enumera registros DNS.
    - Fierce: Ferramenta de reconhecimento de DNS.
- Nmap: Mapeia redes e identifica hosts e serviços ativos.
- Dirsearch: Busca por diretórios e arquivos ocultos em um site.
- Nikto: Scanner de vulnerabilidades web automatizado.

**Outras ferramentas:**
- Hydra: Realiza ataques de força bruta contra serviços.
- Medusa: Realiza ataques de força bruta contra serviços.
- OWASP ZAP: Scanner de vulnerabilidades web automatizado.
- Burp Suite: Suite de ferramentas para testes de segurança web.
- SQLMap: Ferramenta para testes de injeção de SQL.

**Recursos Adicionais:**
- [Guia de Enumeração](https://dle.rae.es/inv%C3%A1lido)
- [Lista de ferramentas de enumeração](https://dle.rae.es/inv%C3%A1lido)

### Fase 3: Exploração Limitada

**Objetivo:** Explorar as vulnerabilidades encontradas para obter acesso aos sistemas e dados do alvo, de forma limitada e controlada.

**Ferramentas:**
- Metasploit: Framework para testes de penetração.

**Outras ferramentas:**
- PowerSploit: Ferramenta para automatizar tarefas no PowerShell.
- Mimikatz: Ferramenta para extrair credenciais do Windows.

**Observações:**
- É importante ter cuidado ao explorar vulnerabilidades para não causar danos aos sistemas.
- A documentação dos resultados do pseudo-pentest é fundamental para que as medidas de remediação possam ser tomadas.

**Recursos Adicionais:**
- [Guia de Exploração](https://dle.rae.es/inv%C3%A1lido)
- [Lista de ferramentas de exploração](https://dle.rae.es/inv%C3%A1lido)

## Considerações

- Adapte a lista de ferramentas às suas necessidades.
- Tenha conhecimento técnico para usar as ferramentas.
- Combine ferramentas automatizadas com testes manuais.

## Recomendações

- Obtenha autorização da organização antes de iniciar o pseudo-pentest.
- Siga as leis e regulamentações loc
