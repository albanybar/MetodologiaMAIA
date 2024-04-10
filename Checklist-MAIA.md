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

Na etapa inicial, é feito o cálculo do Índice de Exposição de Vulnerabilidades (IEV) para cada vulnerabilidade identificada. O IEV é composto por cinco categorias distintas. A cada categoria, é atribuído um valor que corresponde à avaliação do risco associado a cada vulnerabilidade, conforme explicado a seguir.

- Severidade da Vulnerabilidade: Refere-se à gravidade do impacto que a exploração da vulnerabilidade encontrada pode causar no sistema. Vulnerabilidades com potencial para causar danos mais significativos são classificadas como mais severas. São atribuídos quatro níveis de severidade: Crítica (4), Alta (3), Média (2) e Baixa (1).
  
- Potencial de Exploração: Indica a facilidade ou a dificuldade em explorar a vulnerabilidade. Quanto mais fácil for para explorar a vulnerabilidade, maior será o potencial de exploração. Os níveis são: Alto (4), Médio (3), Baixo (2) e Não Explorado (1).
  
- Impacto do Ataque: Avalia os efeitos adversos que podem ocorrer se a vulnerabilidade for explorada com sucesso. Isso inclui danos à integridade, à confidencialidade ou à disponibilidade dos dados e dos sistemas. Os níveis de impacto são: Alto (4), Médio (3), Baixo (2) e Impacto Mínimo (1).
  
- Mitigação Disponível: Refere-se à eficácia das medidas de mitigação existentes para reduzir ou eliminar o risco associado à vulnerabilidade. Quanto mais eficazes forem as contramedidas disponíveis, menor será o risco. Esta categoria considera o esforço necessário para corrigir a vulnerabilidade. Os níveis são: Nenhuma Mitigação (4), Mitigação Temporária (3), Correção Complexa (2) e Correção Simples (1).
  
- Probabilidade de Ocorrência: Estima a probabilidade de um ataque bem-sucedido contra a vulnerabilidade. Isso pode ser influenciado por vários fatores, como a visibilidade da vulnerabilidade, o perfil do atacante e a maturidade das defesas. Baseando-se na probabilidade de um ataque ocorrer, utilizando o OWASP (Open Source Foundation for Application Security) Top 10 como referência. Os níveis são: Muito Provável (4), Provável (3), Pouco Provável (2) e Raro (1)

A equação `IEV = SV + PE + IA + MD + PO` mostra que o IEV calculado, para cada vulnerabilidade encontrada, corresponde à soma da severidade de vulnerabilidade (SV) com o potencial de exploração (PE), com o impacto do ataque (IA), com a mitigação disponível (MD) e com a probabilidade de ocorrência (PO). A equação fornece uma medida quantitativa para avaliar o nível de risco associado a uma vulnerabilidade específica.

### Etapa de Cálculo do Índice Geral de Exposição de Vulnerabilidade

O Índice Geral de Exposição de Vulnerabilidade (IEVg) é uma métrica crucial na metodologia MAIA. Sua proposta visa oferecer uma noção do grau do risco geral associado a várias vulnerabilidades identificadas durante a análise. Essa métrica é calculada considerando não apenas a gravidade individual de cada vulnerabilidade, mas também o número de ocorrências de cada uma delas.

A fórmula do IEVg é expressa de acordo com a equação `IEVg = (∑(IEV_i * Ocorrencia_i)) / (∑Ocorrencia_i)`. Nela, o `IEV_i` denota o IEV da i-ésima vulnerabilidade. O `Ocorrencia_i` indica a quantidade de vezes que essa vulnerabilidade foi detectada. O `∑(IEV_i * Ocorrencia_i)` representa o número total de ocorrências de vulnerabilidades.

O IEVg é o Índice Geral de Exposição de Vulnerabilidade, uma métrica que avalia o impacto cumulativo de várias vulnerabilidades em um sistema. O `IEV_i` corresponde ao Índice de Exposição de Vulnerabilidade associado à i-ésima vulnerabilidade identificada, representando a gravidade individual de cada falha. A variável `Ocorrencia_i` indica a quantidade de vezes que a i-ésima vulnerabilidade foi identificada durante a análise. É importante ressaltar que a contagem de ocorrências é realizada separadamente para cada tipo de vulnerabilidade, visando uma avaliação precisa. Por exemplo, se 13 senhas forem encontradas em um diretório exposto, essa constatação será considerada como uma única ocorrência no cálculo do índice geral, independentemente do número total de senhas identificadas. Essa abordagem reflete uma análise ponderada que leva em consideração tanto a severidade quanto a frequência das vulnerabilidades, proporcionando uma métrica abrangente para avaliação do risco global no ambiente analisado. O IEVg varia de 0 a 20. Na escala, 0 é o valor para o ambiente mais seguro e 20 é o valor para o ambiente extremamente vulnerável.
