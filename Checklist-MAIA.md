# Checklist Completo para Metodologia MAIA 

## Introdução

Este checklist completo fornece um guia passo a passo para utilizar a metodologia MAIA. O objetivo é auxiliar na identificação de vulnerabilidades em sistemas de computadores, focando na coleta de informações, enumeração e exploração limitada.

## Metodologia MAIA

A metodologia MAIA divide o processo em quatro fases:

- **Coleta de Informação:** Reunir informações sobre o alvo, como endereços IP, subdomínios, certificados e credenciais.
- **Enumeração:** Reunir informações sobre portas e serviços do alvo para identificar pontos de pontecial vulnerabilidade.
- **Exploração:** Explorar as vulnerabilidades encontradas para obter acesso aos sistemas e dados do alvo, de forma limitada e controlada.
- **Análise de exposição de vulnerabilidade:** Quantificar e mensurar as vulnerabilidades encontradas

## Ferramentas e Recursos
### Fase 1: Coleta de Informação

**Objetivo:** Reunir o máximo de informações sobre o alvo.

**Ferramentas:**
- Google Hacking: Busca por informações confidenciais através do Google. Base de dados com dorks
  [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- Crt.sh: Busca por certificados SSL/TLS que podem revelar subdomínios e hosts adicionais.
  [Certificate Search](https://crt.sh/)
- Webarchive: Acessa versões arquivadas de sites para encontrar informações que não estão mais disponíveis online.
  [Wayback Machine - Internet Archive](http://web.archive.org/)
- Shodan: Busca por dispositivos e serviços expostos na internet.
  [Shodan Search Engine](https://www.shodan.io/)


### Fase 2: Enumeração

**Objetivo:** Reunir informações sobre portas e serviços do alvo para identificar pontos de pontecial vulnerabilidade.

**Ferramentas:**
- Enumeração de DNS:
    - DNSMap: Mapeia e enumera registros DNS. [DNSMap](https://dnsmap.io/)
    - Fierce: Ferramenta de reconhecimento de DNS. [Fierce](https://github.com/mschwager/fierce) 
- Nmap: Mapeia redes e identifica hosts e serviços ativos. [Nmap](https://nmap.org/)   
- Dirsearch: Busca por diretórios e arquivos ocultos em um site. [Dirsearch](https://github.com/maurosoria/dirsearch)
- Nikto: Scanner de vulnerabilidades web automatizado. [Nikto](https://github.com/sullo/nikto)

### Fase 3: Exploração 
**Objetivo:** Explorar as vulnerabilidades encontradas para obter acesso aos sistemas e dados do alvo, de forma limitada e controlada.

**Ferramentas:**
- Metasploit: Framework para uso de exploit públicos e modos auxiliares em testes de segurança. [Metasploit](https://www.metasploit.com/)

**Observações:**
- É importante ter cuidado ao explorar vulnerabilidades para não causar danos aos sistemas.
- A documentação dos resultados do pseudo-pentest é fundamental para que as medidas de remediação possam ser tomadas.


## Considerações

- Adapte a lista de ferramentas às suas necessidades.
- Tenha conhecimento técnico para usar as ferramentas.
- Combine ferramentas automatizadas com testes manuais.


### Fase 4: Análise de Exposição de Vulnerabilidade 
