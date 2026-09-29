# Estudo: como funciona o anti-bot F5 Shape no CADESP

> **Cópia sanitizada** do `ESTUDO.md` (gerada em 2026-09-29). IPs reais, chaves
> AES extraídas do script do F5, o ID da task Fargate e um hash de fingerprint
> foram trocados por rótulos estáveis (`<IP-AWS-3>`, `<chave-F5-D>`…): o mesmo
> valor recebe sempre o mesmo rótulo, então comparações como "mesma chave" continuam
> válidas. Support IDs, JA3 e os valores de `hi32` foram mantidos. Uso interno ao time.

> Documento didático da engenharia reversa que fizemos do sistema anti-bot do
> CADESP (`www.cadesp.fazenda.sp.gov.br`). Escrito para ser entendível por
> alguém sem contexto

---

## 1. O problema, em uma frase

O CADESP é uma consulta pública de cadastro de ICMS. Na frente dela existe um
sistema anti-bot da **F5 (linha "Shape Security")**, cuja função é decidir se
quem está acessando é um **navegador de verdade, operado por uma pessoa**, ou um
robô. Se ele confia em você, a consulta funciona. Se desconfia, ela é bloqueada.

Este estudo é sobre **como ele decide isso**. Entender o mecanismo nos permitiu
construir uma POC que interage com o site de forma legítima usando automação —
com uma pessoa resolvendo o CAPTCHA — em vez de ser barrada como robô.

O sistema aparece no código-fonte da página sob o comentário
`APM_DO_NOT_TOUCH` ("não toque"), e todo o seu tráfego passa por um caminho de
URL chamado `/TSPD/`.

---

## 2. A ideia central: fingerprint + comportamento

O F5 combina dois tipos de evidência:

1. **Fingerprint (impressão digital do ambiente)** — características técnicas do
   navegador e da máquina: qual GPU, como ela desenha uma imagem, quais fontes
   estão instaladas, se as funções internas do navegador foram adulteradas, se
   há sinais de automação (`navigator.webdriver`, Selenium, etc.).

2. **Comportamento** — como o mouse se move, o ritmo da digitação, se os cliques
   são "confiáveis" (vindos de hardware real) ou sintéticos.

Cada evidência vira um número. Esses números são cifrados e guardados em
**cookies**. A cada requisição, o servidor lê os cookies e decide se libera.

O resto do documento destrincha cada uma dessas peças.

---

## 3. A arquitetura: três "frames"

A primeira surpresa foi descobrir que não é um script só. São **três contextos
de execução** rodando na mesma página, cada um com um papel:

```
┌─ top (a própria página, ex: Login.aspx / ConsultaPublica.aspx)
│    • Carrega o type=18 (loader) e o type=17 (motor de comportamento)
│    • O type=18 cria o <iframe> escondido "TS_Injection"
│      (nota: antes atribuíamos isso ao inline APM_DO_NOT_TOUCH; o grafo de
│       chamadas verificado — §9 — mostrou que é o type=18)
│
├─ TS_Injection  (iframe oculto — width:0, height:0, display:none)
│    • É onde a COLETA DE FINGERPRINT acontece
│    • type=20 (loader) → type=11 (motor) + type=12 (shaders)
│
└─ clntcap_frame  (segundo iframe — "client capture")
     • Criado pelo próprio type=11; recebe o resultado e marca clntcap_success
```

Descobrimos que os cookies se agrupam por frame através de um prefixo comum.
Todos começam com `083d8fda4cab2` (o identificador do "deploy" do F5), e o 13º
dígito separa os grupos:

- `...cab2000...` → cookies do frame **TS_Injection**
- `...cab2800...` → cookies do frame **clntcap**

---

## 4. Os endpoints `/TSPD/`

Todo o tráfego do F5 passa por URLs `/TSPD/…?type=N`. Cada `type` é uma peça
diferente. Mapeamos todos (tamanhos confirmados por um HAR real):

| type | Tamanho | O que é                                                                                                                                                                                                                                                                                       |
| ---- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `17` | ~130 KB | **Motor comportamental** — registra mouse, teclado, touch; calcula timing e RSD; roda na página principal                                                                                                                                                                                     |
| `18` | ~9 KB   | **Camada de anti-adulteração** — detonador de DOM contra instrumentação (`/debugger\|alert\|console/`), sequestro de `alert`/`confirm`/`prompt`, watchdog de congelamento (6 s desktop) e criação do iframe `TS_Injection`. **Corrigido em §9.3-R35** — antes descrito como "script auxiliar" |
| `20` | ~5 KB   | **Loader do iframe** — contém a config (`bobcmn`) e ponteiros (`blobfp`)                                                                                                                                                                                                                      |
| `11` | ~424 KB | **Motor de fingerprint** — o grande; roda os shaders, lê WebGL/canvas/áudio, faz a detecção de automação                                                                                                                                                                                      |
| `12` | ~53 KB  | **fpdefs** — os shaders GLSL + a textura de referência (a carta ISO 12233)                                                                                                                                                                                                                    |
| `13` | ~566 B  | HTML curto do fluxo clntcap                                                                                                                                                                                                                                                                   |
| `14` | ~209 B  | **clntcap_success** — a casca que sinaliza fim da captura                                                                                                                                                                                                                                     |
| `22` | 0 B     | **Beacon de validação** — GET recorrente que "bate ponto" com o servidor — **corrigido em §9.3-R2.1: dispara 1× por carga de documento, não continuamente**                                                                                                                                   |

Um detalhe importante: **todos são GET**. Não existe um POST que envie o
fingerprint. Isso nos leva à seção sobre cookies (§8).

---

## 5. A ofuscação (e como a quebramos)

O código do F5 é fortemente ofuscado. Strings como `"addEventListener"` não
aparecem no texto; elas são reconstruídas em tempo de execução por funções
pequenas. As principais:

- **`z(offset, ...codes)` / `Z(...)`** — subtrai `offset` de cada número e
  converte para caractere. Ex: `z(38, 135, 138, 138, ...)` → `"addEventListener"`.
- **`L(num, offset)`** — soma `offset` ao número e converte para base36.
  Ex: `L(64012178998596, 38)` → `"mousemove"`.
- **`J(n)`** — anti-tampering; retorna verdadeiro/falso para embaralhar o fluxo.

O truque: cada função (ou escopo aninhado) usa um **offset diferente**. Achamos
7 offsets no type=17 (38, 7, 99, 54, 25, 67, 78) e outros nos demais scripts.
Escrevemos um decodificador que resolve o offset por posição no texto e traduz
todas as chamadas de uma vez — foi assim que lemos o que o código realmente faz.

O script também é **polimórfico**: cada vez que você carrega a página, os
offsets e as constantes-isca mudam, embora a lógica seja idêntica. Por isso não
dá para "fixar" o código por hash — só o conteúdo do type=17 (que é estático por
24h) serve de referência estável.

---

## 6. O motor comportamental (type=17)

Este script fica na página e observa você. Ele registra 16 tipos de evento
(mouse, teclado, touch, movimento do dispositivo) e procura padrões de robô.
Decodificamos os **thresholds exatos** — os limites que separam "humano" de
"bot":

| Nome interno | Valor | O que mede                                                         |
| ------------ | ----- | ------------------------------------------------------------------ |
| `Oi.oj_`     | 500   | tempo mínimo (ms) de movimento de mouse acumulado antes de confiar |
| `Oi.zj_`     | 30    | nº de segmentos de mousemove desejável                             |
| `Oi.SJ_`     | 5     | "retidão": movimento reto demais = robô                            |
| `Oi.s$S`     | 1000  | RSD: o timing entre eventos precisa ser **irregular**              |
| `Oi.sLS`     | 500   | distância grande entre pontos = "teleporte" do cursor              |

E 18 "eventos suspeitos", cada um com um peso (bitmask) que é somado num campo
do cookie. Os mais graves:

- **`oZ_` (peso 13)** — "untrusted event": um evento com `isTrusted=false`, ou
  seja, disparado por JavaScript e não por hardware real. É o pecado capital.
- **`OO_` (peso 8)** — mousedown na coordenada (0,0).
- **`SZ_`** — "selenium sequence detected": o padrão de movimento linear e
  uniforme que Selenium/Playwright geram por padrão.

### O que é RSD, e por que importa tanto

RSD = _Relative Standard Deviation_ (desvio padrão relativo) dos intervalos de
tempo entre eventos. Um robô que move o mouse a cada 16ms exatos tem RSD ≈ 0
(muito regular). Uma pessoa move de forma irregular — pausas curtas, uma longa,
outra média — e tem RSD alto. O F5 exige RSD alto para acreditar que é humano.

**É por isso que a POC gera intervalos deliberadamente irregulares** (ver §10).

---

## 7. O motor de fingerprint (type=11) e os shaders (type=12)

Este é o coração da detecção de ambiente. Decodificando suas ~1.500 strings,
vimos exatamente o que ele coleta.

### 7.1 WebGL — a impressão digital da GPU

O type=12 (`fpdefs`) traz dois **shaders** (programas que rodam na GPU) e uma
**textura de referência**: um JPEG 512×512 em tons de cinza que é uma **carta de
resolução ISO 12233** — o padrão que fotógrafos usam para medir nitidez de
lente. (O arquivo está em `logs/` se você rodou a POC, ou pode ser extraído do
type=12.)

O type=11 aplica essa carta como textura numa cena 3D, renderiza na GPU e **lê
os pixels de volta** (`readPixels`). Como cada combinação de GPU + driver +
sistema operacional interpola e suaviza de um jeito ligeiramente diferente, o
hash dos pixels resultantes é uma **impressão digital estável do stack gráfico**.
A carta de resolução é escolhida de propósito: quanto mais bordas e detalhe
fino, mais as diferenças entre GPUs aparecem.

Além do render, ele lê `UNMASKED_RENDERER_WEBGL` e `UNMASKED_VENDOR_WEBGL` — o
**nome real da GPU**.

**Consequência prática (a mais importante do estudo):** você não pode rodar isso
num servidor headless sem GPU. Sem GPU, o navegador usa um renderizador por
software (SwiftShader), que se identifica como tal e produz um hash que não bate
com hardware nenhum. Falsificar o nome da GPU via JavaScript não resolve, porque
o nome reportado ficaria inconsistente com os pixels realmente produzidos — e
essa inconsistência é, ela própria, detectável.

### 7.2 A detecção de automação: `isNative`

O type=11 carrega uma rotina chamada `safeFn.isNative()`. Ela pega ~30 funções
nativas do navegador (`Array.prototype.map`, `Element.prototype.appendChild`,
`Function.prototype.toString`, etc.) e verifica se cada uma ainda retorna
`() { [native code] }` — a assinatura de uma função original, não modificada.

Por que isso importa: as ferramentas "stealth" (anti-detecção) funcionam
**sobrescrevendo** funções nativas para esconder sinais de automação. Mas ao
fazer isso, elas quebram a assinatura `[native code]`, e o `isNative` detecta.

**Ou seja: usar um stealth plugin aqui PIORA a situação.** A abordagem correta é
o oposto — não tocar em nada nativo.

Ele também faz as checagens clássicas: lê `navigator.webdriver`, procura
`_Selenium_IDE_Recorder` e `callPhantom`.

Curiosamente, **não** encontramos a técnica de detecção de CDP (o truque do
`Runtime.enable` + getter no `.stack` que Cloudflare usa). Então a única
preocupação com `navigator.webdriver` se resolve por uma flag do navegador, sem
precisar de forks especiais.

---

## 8. O sistema de cookies: uma "teia", não um cookie

Aqui está a peça que amarra tudo. **O fingerprint não é enviado por um POST.**
Todos os endpoints `/TSPD/` são GET. Em vez disso:

1. O type=11 coleta tudo, **sela** o payload (o _seal_ Encrypt-then-MAC — cifra XTEA-CBC + HMAC, detalhado na §9.6/§12) e **grava
   o resultado em cookies** via `document.cookie`.
2. Esses cookies **pegam carona** no cabeçalho `Cookie` das requisições GET
   seguintes (os beacons type=22, e o próprio POST do formulário de consulta).
3. O servidor lê os cookies, valida, e **reemite** cookies novos via
   `Set-Cookie` (a "rotação" que você vê rolar sem parar no log).

Os cookies principais:

| Cookie                   | Papel                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| `TS00000000076` (~528 B) | **O payload do fingerprint** — o maior; carrega o resultado da coleta                                 |
| `TSPD_101`               | Cookie principal TSPD (persistente)                                                                   |
| `TSPD_101_DID`           | **Device ID** — descobrimos que é **aleatório por sessão**, não um fingerprint estável de dispositivo |
| `TS0eaa…`, `TS6695…`     | Cookies de sessão comportamental (rotacionam muito)                                                   |
| `TS01ec2f54`             | Cookie domain-wide (amarra os dois frames)                                                            |

Descobrimos também que **vários cookies carregam o mesmo valor espelhado** —
provavelmente um mecanismo de consistência cruzada: se você forjar um e deixar
os outros dessincronizados, o servidor percebe. Isso é mais uma razão pela qual
**deixar o navegador real gerar os cookies** é muito mais robusto do que tentar
fabricá-los em código.

---

## 9. O fluxo completo, do começo ao fim

### 9.1 O grafo de chamadas — VERIFICADO

Isto **não é mais dedução.** Capturamos o iniciador de cada requisição (via CDP,
o mesmo dado da coluna "Iniciador" do DevTools) e montamos o grafo causal real.
Cada aresta abaixo foi comprovada — o número entre colchetes é o iniciador:

```
PÁGINA (Login.aspx / ConsultaPublica.aspx)   ← a raiz (as tags <script> do HTML)
├── type=18  (auxiliar / loader)             [página:12]
│      └── type=20  (loader do iframe)        [type=18]
│             ├── type=11  (fingerprint)       [type=20:26]
│             │      ├── type=13  (clntcap html)       [type=11]
│             │      └── type=14  (clntcap_success)    [type=11]
│             └── type=12  (shaders / fpdefs)  [type=20:37]
│
└── type=17  (comportamental)                [página:34]
       └── type=22 × N  (beacons)             [type=17:180]
```

Três coisas que este grafo **corrigiu ou confirmou** em relação às deduções
anteriores:

- **É o type=18 que cria o loader (type=20)** — não o inline `APM_DO_NOT_TOUCH`
  como supúnhamos. O type=18 é o loader de verdade.
- **O type=20 carrega o type=11 E o type=12** — confirmado (linhas 26 e 37).
- **O clntcap (type=13/14) é filho do type=11** — é o próprio motor de
  fingerprint que cria o frame de captura, depois de coletar, para postar o
  resultado e sinalizar `clntcap_success`.

### 9.2 A sequência, em palavras

> ⚠ **A ordem abaixo é idealizada.** Em 6 de 6 sessões o fio entrega
> `18 → 17 → 20 → (12,11) → 22 → 13 → 14`. Ver §9.3-R2.2.

```
1. Você abre a página. O F5 serve o "desafio" (HTML com APM_DO_NOT_TOUCH inline).
2. A página carrega o type=18 (loader) e o type=17 (comportamental).
3. O type=18 cria o iframe e carrega o type=20 (config do loader).
4. O type=20 carrega o type=11 (coleta) e o type=12 (shaders).
5. O type=11 renderiza a carta ISO 12233 na GPU, lê WebGL/canvas/áudio,
   roda o isNative, checa webdriver — e cria o clntcap (type=13/14).
6. O resultado é cifrado e gravado em cookies (TS00000000076 nasce, ~528 B).
7. O type=17 dispara o beacon type=22.  ← **corrigido em §9.3-R2.1: um par
   (17, 22) por carga de documento, não um heartbeat contínuo.**
8. A partir daí, seus cookies são "confiáveis". O POST do formulário os leva;
   o servidor valida e libera.
9. A consulta (POST WebForms com __VIEWSTATE + CNPJ + CAPTCHA) é aceita e
   devolve o resultado.
```

**Módulos condicionais:** em desafios de retentativa observamos também
`type=8`, `type=4` e `type=21` — não aparecem no fluxo "limpo". A hipótese é que
o F5 **escala** o fingerprint (módulos extras) quando desconfia ou numa segunda
tentativa. Marcado como **dedução** até capturarmos o grafo desse cenário.

O CAPTCHA de imagem é uma camada **independente** do F5: mesmo com o fingerprint
perfeito, a consulta exige o código digitado. Na POC, **você** o resolve.

### 9.3 A terceira camada: F5 ASM (WAF) e o bloqueio transiente

Além do Shape (fingerprint/comportamento) e do CAPTCHA, existe uma **terceira
camada**: o **F5 BIG-IP ASM** — o WAF. Ele é quem efetivamente rejeita uma
requisição, servindo a página:

```
The requested URL was rejected. Please consult with your administrator.
Your support ID is: <numero>
```

Observamos isso ao vivo e capturamos o **tell**: no passo de entrada
(`POST /Pages/Login.aspx`), uma resposta **302** = sucesso (redireciona ao
formulário); uma resposta **200** = a página de bloqueio veio no lugar. Nas
execuções, o mesmo fluxo às vezes deu 302 (passou) e às vezes 200 (bloqueou) —
**mesmos cookies, mesmo CNPJ**. Isso caracteriza um **bloqueio transiente**, não
detecção de bot (detecção bloquearia sempre). A causa provável é a corrida da
rotação de cookies (o cookie de 30s expirando no instante errado).
**← REFUTADO em §9.3-R3.1: a rotação é POR RESPOSTA (dezenas por segundo), e o
`Max-Age=30` é prazo de validade, não período de rotação. Não existe a "janela
de 30 s" que esta frase supõe.** A recuperação
é trivial: **recarregar e repetir** — a próxima requisição passa.

O `support ID` é uma **referência de log server-side** — não é decodificável do
lado do cliente; serve só para o administrador consultar.

**Distinção importante (corrige uma dedução anterior):** um **CAPTCHA errado** é
rejeição da _aplicação_ ("O texto digitado não confere") e **não** faz o F5
escalar. Os módulos condicionais `type=8/4/21` estão ligados a um **re-desafio do
próprio F5** (o cenário de bloqueio/ASM), não ao CAPTCHA errado — confirmamos que
errar o CAPTCHA e repetir mantém o grafo idêntico.

---

### 9.3-R1 — Revisão versionada (2026-09-01): bloqueio persistente e estrutura do support ID

> Esta revisão **não substitui** o texto do §9.3 acima; registra que a evidência
> coletada em 2026-09-01 (16:41–17:13) diverge do baseline em que a formulação
> original se apoiou, e reenquadra a hipótese conforme a metodologia do estudo.
> Camadas mantidas explicitamente separadas: **hipótese / evidência / variáveis
> observáveis / correlações / limitações / validação pendente / ambiente
> necessário**.

**Hipótese (original, §9.3).** O bloqueio do F5 ASM no ponto de entrada é
_transiente_, causado por corrida na rotação do cookie de sessão (~30s), e
recuperável por reload.

**Hipótese concorrente (nova).** O estado de bloqueio depende de estado
server-side associado ao originador (reputação acumulada ao longo de múltiplas
requisições), e não de um sinal instantâneo do cliente.

**Evidência disponível.**

- _Baseline_ (`logs/old/probe-1788266618.csv`, ~09:43–10:04): 13/13 tentativas
  `bloqueado=False`, `resultado=carregou`, nos níveis 10/60/300 e headful.
- _Estado atual_ (4 rodadas, 16:41–17:13): bloqueio no `POST /Pages/Login.aspx`
  em toda tentativa, **escalando** para o próprio `/`, **não recuperável por
  reload**, reincidente através de sessões novas — com fingerprint idêntico ao
  baseline (`renderHash 9900bd39`, `isNative 0/6`, `webdriver=false`).

**Variáveis observáveis identificadas.** `ponto` (`/` vs `/Pages/Login.aspx`),
`support_id` e sua estrutura interna, estado/rotação dos cookies TS por rodada,
`bloqueado`, latência.

**Correlações encontradas (ASSOCIAÇÃO, não causa).**

- O support ID, lido como inteiro de 64 bits e partido no bit 32, tem estrutura:
  a **palavra alta** assume só 2 valores em 13 eventos — `3134348991` (11×) e
  `1324124407` (2×); a **palavra baixa** não é monotônica no tempo (⇒ não é
  contador global; comporta-se como nonce/hash por requisição).
- A palavra-alta minoritária co-ocorre **apenas** com o ponto `/` e **nunca** é o
  primeiro bloqueio de uma rodada. Sugestivo de um segundo campo de identidade/nó,
  porém **n=2 — estatisticamente insuficiente** para qualquer inferência.

**Limitações dos dados.**

- Amostra pequena e não balanceada; classe minoritária com n=2.
- Confounders não controlados: mudança de sessão, expiração/renovação de estado,
  janela temporal, reputação prévia, e a própria variação da palavra-alta do
  support ID (possível troca de origem/nó) coexistindo com os bloqueios.
- O laço de reload automático do `f5monitor` gera múltiplos acessos por rodada,
  misturando a variável "repetição" com as demais — impede atribuição causal.
- Decodificação da palavra-alta como IPv4 (`186.210.94.191` / `78.236.136.247`)
  é **hipótese não verificável offline**; alternativa concorrente: identificador
  de nó/pool do BIG-IP. As duas fazem previsões separáveis só em ambiente
  controlado.

**Conclusão experimental.** A hipótese "transiente por corrida de cookie" **não
explica** o estado persistente/escalante atual: fica _modificada_, não confirmada.
A hipótese de reputação **não pode ser estabelecida causalmente** com os dados
atuais — inclusive porque eles contêm um sinal de identidade concorrente e não
controlado. A análise puramente offline é **insuficiente** para causalidade aqui.

**Comportamento que ainda requer validação dinâmica.** A relação
requisição → estado → bloqueio ao longo do tempo (a curva bloqueio↔recuperação e
sua dependência de identidade e de estado server-side), que é intrinsecamente
dinâmica e não se resolve só com os artefatos estáticos.

**Ambiente necessário para essa validação.** Um ambiente **online sob controle e
autorização** que reproduza as propriedades relevantes: um F5 BIG-IP ASM de
laboratório, ou um mock dos endpoints `/TSPD/` com a lógica de resposta 302/200 e
de estado/reputação. **O local dessa validação — laboratório controlado vs.
serviço de produção de terceiro — é decidido por controle experimental e
autorização; a necessidade de um experimento dinâmico NÃO justifica, por si só,
tráfego adicional contra o serviço de produção.**

---

#### 9.3-R1.a — Atualização (2026-09-01): estrutura do support ID, testada

Com a instrumentação `events-*.jsonl` (opt-in) rodando, dois pontos da §9.3-R1
foram testados sobre TODOS os pares de bloqueio disponíveis:

- **`lo32` = relógio em ms — REFUTADA.** Uma rodada sugeriu Δlo32/Δt ≈ 1000/s
  (relógio em ms). O teste offline sobre ~11 pares mostrou que **só 1 bate**
  ~1000/s; os demais divergem 4–9 ordens de grandeza, com deltas negativos.
  Conclusão: coincidência. `lo32` volta a ser **valor opaco por-requisição**, não
  um eixo temporal utilizável.
- **`lo32` não-monotônico — mantido** (agora com evidência mais forte).
- **`hi32` constante-por-sessão — mantido, ainda n=2 sessões.** Nos dois
  `events.jsonl`, os 2 bloqueios de cada sessão compartilham `hi32`, e as duas
  sessões têm `hi32` distintos. Segue como candidato a identificador de
  sessão/conexão (H1 identidade vs H2 nó/pool ainda não separadas).
- **Associação "minoritária ⟷ ponto `/` ⟷ não-primeiro-bloqueio" — FALSIFICADA.**
  Rodada 1788297212: `hi32` minoritária apareceu no `Login.aspx` (entrada) E como
  1º bloqueio. Era artefato de amostra pequena (n=2).

Consequência: o support ID contribui com **um** observável útil (`hi32` como
rótulo de sessão), não dois. Espaço de hipóteses reduzido, sem tráfego novo.

---

#### 9.3-R1.b — Atualização (2026-09-02): o bloqueio NÃO é cliente-side

Com a instrumentação de cookies/sessão (`t.py`: SESSION STATE por checkpoint,
diff com hash — nunca valor real — e correlação de bloqueio) e o `events.jsonl`,
três candidatos a mecanismo do bloqueio foram testados e **descartados** — cada um
com evidência direta, não por eliminação retórica:

- **Não é fingerprint.** Rodada com **Camoufox (Firefox anti-fingerprint)**, com o
  RENDERER spoofado (`Radeon R9 200 Series`), **bloqueou igual** — mesma sequência
  `REDIRECT→CHALLENGE→BLOCK`, mesmo `hi32`. Trocar o motor/fingerprint do cliente
  não mudou o desfecho.
- **Não é cookie TSPD ausente/defasado.** A correlação de bloqueio mostra o POST
  bloqueado **com `TSPD_101` + `TSPD_101_DID` + `TS00000000076` presentes**; só
  houve rotação de valor (mesmo tamanho), a mesma que ocorre em requests que passam.
  `cookies_stale` no documento de BLOCK = vazio em todas as rodadas.
- **Não é troca de sessão ASP.NET.** A sessão `/(S(...))/` permaneceu **estável**
  entre o pipeline e o POST bloqueado.
- **`hi32` do support ID não é o IP do cliente.** Medido o IP público de saída
  (via navegador): `hi32→186.210.94.191` ≠ IP real `<IP-RESIDENCIAL>` (2 rodadas,
  mesmo IP → mesmo `hi32`). O `hi32` é estável por origem, mas não é o IP bruto.

**Também refutado (obs. manual + logs):** o bloqueio **sobrevive a reload e a
contexto novo (cookie jar zerado)**; recuperar exige reiniciar o navegador — e nem
sempre (uma vez a raiz carregou e o passo seguinte bloqueou de novo).

**Conclusão experimental.** As evidências convergem: o gatilho do bloqueio **não
está nos sinais cliente-side** (fingerprint, cookie, sessão). O que resta é a
camada de **rede/edge/reputação**, que é intrinsecamente dinâmica e só se valida em
ambiente controlado/autorizado. Corolário prático para o estudo: **afinar o cliente
não altera o resultado** — o lever não está no cliente.

**Nota de instrumentação.** O veredito de sessão passou a ser tri-estado
(estável / mudou / indeterminado): quando a URL não traz `/(S(...))/` (ex.: a raiz
pós-reload), registra-se _indeterminado_, não um falso "mudou".

---

#### 9.3-R2 — Revisão (2026-09-02): primeira sessão ACEITA, e o que ela corrige

> Esta revisão **não substitui** §9.3, §9.3-R1, R1.a nem R1.b. Registra a primeira
> sessão que **passou** no `POST /Pages/Login.aspx` (302) com instrumentação de
> `type=`/cookie completa, e as correções que a comparação ACEITA × BLOQUEADA
> impõe ao texto anterior — inclusive a **retratação parcial da conclusão do
> §9.3-R1.b**. Fonte: `logs/forensic/exp_1788347252` (aceita) e
> `exp_1788346277` (bloqueada), mais os 4 `events-*.jsonl` históricos.

**Instrumentação usada.** Pacote `forensic/`: observador passivo pendurado nos
mesmos `page.on(...)` do `f5monitor`, gravando `forensic_timeline.jsonl` +
`session_summary.json` + `report.txt` por execução de `python t.py`
(`MODO="sessao_forense"`: 1 browser → 1 context → 1 page, `freeze_on_block`).
Análise offline: `python forensic_report.py [compare A B]`.

---

##### R2.1 — O modelo do `type=22` estava errado `[FACT]`

O §4 e o §9.2 descrevem o `type=22` como _beacon de validação recorrente_
(`type=22 x N`). Em 6 sessões observadas ele **nunca** se repetiu dentro de uma
mesma carga de documento. O mecanismo real:

| Sessão                       | Documentos carregados | `type=17` | `type=22` |
| ---------------------------- | --------------------- | --------- | --------- |
| aceita (`exp_1788347252`)    | 3                     | 3         | 3         |
| bloqueada (`exp_1788346277`) | 1                     | 1         | 1         |
| 4 sessões históricas         | 1                     | 1         | 1         |

`type=17` e `type=22` disparam **uma vez por carga de documento**, em par. A
sequência correta é:

```
primeira carga:   18 → 17 → 20 → 12 → 11 → 22 → 13 → 14
cargas seguintes:      17 → 22
```

Ou seja: o fingerprint é coletado **uma vez**; o motor comportamental e o beacon
de validação **re-armam por página**. Uma hipótese intermediária de que "o
heartbeat parava nas sessões bloqueadas" foi **descartada**: elas tinham um único
`22` porque carregaram um único documento.

##### R2.2 — A ordem canônica do §9.2 não é a observada `[FACT]`

> ⚠ **Revisado em §9.3-R3.5:** com 12 sessões, a cauda (13, 14, 22 entre si)
> mostrou-se VARIÁVEL. O "6 de 6" abaixo era amostra pequena.

Em **6 de 6** sessões, incluindo a captura manual `separeted-file.log`, a ordem
no fio é `18 → 17 → 20 → (12,11) → 22 → 13 → 14`. O `type=17` é o **segundo**
evento, não o penúltimo, e o `22` vem **antes** de 13/14. O diagrama do §9.2 é
idealizado; nenhum log o reproduz.

##### R2.3 — Atribuição por frame, inédita `[OBSERVATION]`

Com rastreamento de frame (o `initiator_graph.py` usa CDP, indisponível no
Firefox/Camoufox e nunca ligado no `t.py`):

| frame                     | `type=` originados |
| ------------------------- | ------------------ |
| `top`                     | 17, 18, 22         |
| `TSPD` (`/TSPD/?type=20`) | 11, 12, 13         |
| `about:blank` injetado    | 20, 14             |

Dois iframes `about:blank` são anexados por sessão. _Limitação:_ atribuição por
frame do Playwright, não pelo iniciador real.

##### R2.4 — A hipótese de atraso do POST está REFUTADA `[REFUTED]`

Δt entre o último `type=` e o `POST /Pages/Login.aspx`, nas 6 sessões:

| Δt         | status do POST | desfecho   |
| ---------- | -------------- | ---------- |
| 7,6 s      | 200            | BLOCK      |
| 10,1 s     | 200            | BLOCK      |
| 11,0 s     | 200            | BLOCK      |
| **15,0 s** | **302**        | **ACEITA** |
| 22,3 s     | 200            | BLOCK      |
| 24,3 s     | 200            | BLOCK      |

A sessão aceita está **no meio da distribuição**, com bloqueios acima e abaixo.
O atraso do POST **não separa as classes**. Isso encerra também o que restava da
formulação original do §9.3 ("corrida da rotação de ~30s"): nenhuma janela
temporal observada discrimina os desfechos.

##### R2.5 — O instrumento de defasagem do §9.3 produzia falso positivo `[FACT]`

O `dd_post_stale` comparava os cookies enviados no POST contra
`monitor.ts_cookies` **lido depois da resposta**. Como `_handle_response` roda
como task assíncrona, o `Set-Cookie` da própria resposta de bloqueio já havia
sido aplicado ao store. Resultado na sessão `exp_1788346277`:
`dd_post_stale = "TS0eaa6361027,TSPD_101"` — exatamente os dois cookies que a
**resposta** rotacionou, 8 ms _depois_ do POST. O `dd_post_dt_tspd = -0,0s`
(delta **negativo**) é a assinatura da corrida.

Com o corte temporal correto, **os 7 cookies enviados estavam em sincronia**.
Corrigido em `t.py`: `_cap_post` congela `dict(monitor.ts_cookies)` no instante
em que o POST sai. Toda leitura anterior de `dd_post_stale` deve ser descartada.

##### R2.6 — O "baseline saudável" do §9.3-R1 não é comparável `[FACT]`

O §9.3-R1 apoia a tese de degradação em `probe-1788266618.csv` ("13/13
`bloqueado=False`"). Esse log **não possui fase ENTRADA**: nunca clicou no link
de entrada nem executou o `POST /Pages/Login.aspx`. Suas colunas terminam em
`cookies_ts` (sem os campos `dd_*`), e cada tentativa registrou 3 cookies
(`TS0eaa`/`TS01ec`/`TS6695b38b029`), sem `TSPD_101`/`_DID`/`TS00000000076`.

As 13 tentativas mediam **"a raiz carrega?"**, não **"o POST de login passa?"**.
O bloqueio ocorre no POST. O "antes" e o "depois" da degradação são fluxos
diferentes — a comparação do §9.3-R1 está confundida na origem.

##### R2.7 — O cliente apresentava identidade internamente contraditória `[FACT]`

Capturado pelo baseline de context da sessão bloqueada:

| Sinal                          | Valor                                   | Implicação                               |
| ------------------------------ | --------------------------------------- | ---------------------------------------- |
| Playwright                     | `firefox 152.0.4-beta.28`               | motor **Gecko**                          |
| `navigator.userAgent`          | `...Chrome/152.0.0.0 ... Edg/152.0.0.0` | declara **Blink**                        |
| `window.chrome`                | ausente                                 | todo Chrome/Edge real tem                |
| `navigator.vendor`             | `""`                                    | Blink real: `"Google Inc."`              |
| `navigator.productSub`         | `20100101`                              | assinatura **Gecko**; Blink é `20030107` |
| `navigator.buildID`            | `20181001000000`                        | **exclusivo do Firefox**                 |
| `navigator.oscpu`              | presente                                | **exclusivo do Firefox**                 |
| `navigator.deviceMemory`       | `null`                                  | Blink sempre expõe                       |
| `isNative.getters_redefinidos` | `['outerWidth','outerHeight']`          | override **detectável pela página**      |

Nenhum navegador real apresenta esse conjunto. Numa sessão histórica
(`fingerprint-1788343911.json`) o Camoufox chegou a reportar
`oscpu: "Intel Mac OS X 10.15"` sob um UA de Windows.

Duas origens, ambas corrigidas em 2026-09-02:

1. `CONFIG["user_agent"]` fixado num UA de Chrome/Edge — resíduo do tempo em que
   o executor era `browser.py`/msedge — aplicado a um context Camoufox/Gecko.
2. `preparar_contexto()` instalava `Object.defineProperty` em
   `window.outerWidth`/`outerHeight`, contrariando o princípio que o próprio
   `browser.py` documenta ("nada de `add_init_script` sobrescrevendo APIs
   nativas — detectável pelo `isNative`"), e **observável do lado do cliente**.

##### R2.8 — Retratação parcial do §9.3-R1.b

O §9.3-R1.b concluiu: _"o gatilho do bloqueio não está nos sinais cliente-side…
afinar o cliente não altera o resultado — o lever não está no cliente."_ Essa
conclusão se apoiava numa rodada com Camoufox, supondo que ela apresentava uma
identidade **alternativa e coerente**. R2.7 mostra que não: comparou-se uma
identidade incoerente com outra. **A conclusão fica suspensa, não invertida** —
não há prova causal em nenhuma das direções.

##### R2.9 — Hipótese H8 (nova): coerência interna da identidade

> **H8.** O discriminador entre ACEITA e BLOQUEADA é a **coerência interna da
> identidade declarada**, não o valor de nenhum sinal isolado.

**Evidência.** As 5 sessões bloqueadas apresentavam UA de Blink sobre motor
Gecko **mais** getters nativos sobrescritos e detectáveis. A única sessão aceita
apresentou identidade Gecko consistente (`rv:152.0 Gecko/20100101 Firefox/152.0`,
`getters_redefinidos: []`, `inner 1960×1044 / outer 1976×1109` — outer > inner
natural, sem divergência pedido×efetivo).

**Contra-evidência / o que NÃO mudou.** A sessão aceita continuou no Camoufox,
com renderer, canvas e áudio falsificados e variando por launch (`GTX 980` aqui,
`Intel HD 400` na bloqueada) — e passou assim mesmo. Logo, falsificar GPU/canvas
**não é**, por si, o gatilho.

**Status: `WEAKLY_SUPPORTED`. Confiança: `CORRELATION`.**

**Limitações que impedem status mais forte.**

- **n = 1** sessão aceita contra 5 bloqueadas.
- O §9.3 documenta que o bloqueio já foi **transiente**; uma passagem isolada é
  compatível com acaso.
- UA, override e viewport mudaram na mesma leva. O timing saiu da lista (R2.4),
  mas as três mudanças de coerência seguem confundidas entre si.

**Validação pendente.**

1. **Replicar:** 3–4 execuções na config atual. Se mantiver, sobe para
   `SUPPORTED`.
2. **Isolar:** devolver **só** o `user_agent` de Chrome, mantendo o override
   removido. Voltar a bloquear isola o UA incoerente como o sinal.

##### R2.10 — Nota de método

O laço de reload+retry (`MAX_ENTRADAS=4`), apontado como confundidor no
§9.3-R1, foi neutralizado por `freeze_on_block`: 1 resposta BLOCK por sessão,
contra 2–3 nos logs históricos. Toda conclusão desta revisão está classificada
segundo FACT / OBSERVATION / CORRELATION / HYPOTHESIS / REFUTED / UNKNOWN;
nenhuma associação temporal foi convertida em causa.

---

#### 9.3-R3 — Revisão (2026-09-02, tarde): rotação é POR RESPOSTA, e o que a nuvem mostrou

> Não substitui §9.3, R1, R1.a, R1.b nem R2. Base: **12 execuções com baseline
> forense** (7 locais + 5 no Fargate), sendo 9 ACCEPTED, 2 BLOCKED e 1 que não
> chegou ao clique. Inclui a **correção de um erro de análise** cometido nesta
> mesma sessão de trabalho (R3.7).

---

##### R3.1 — A rotação de cookie é POR RESPOSTA, não periódica `[FACT]`

Com um evento `cookie_change` por resposta HTTP, o mecanismo ficou visível:

```
T+1411  ← 200 /Scripts/ProcessamentoSolicitacoesRFB.js   TS0eaa6361027 mudança #3
T+1467  ← 200 /Scripts/Alteracoes/AlteracaoDeOficio.js   TS0eaa6361027 mudança #4
T+1488  ← 200 /Styles/cadesp.css                        TS0eaa6361027 mudança #7
T+1579  ← 200 /Images/Icones/botao_sair.gif             TS0eaa6361027 mudança #14
T+1969  ← 200 /Images/Graficos/cantoInfDir.gif          TS0eaa6361027 mudança #28
```

**28 rotações em 1,2 segundo**, disparadas por CSS, JS, GIF, PNG,
`WebResource.axd`, `ScriptResource.axd` — recursos estáticos, não endpoints do
F5. Total de 52 numa sessão.

**Consequência para a formulação original do §9.3.** O texto fala em "o cookie de
30s expirando no instante errado" e trata rotação e prazo como a mesma coisa.
São duas coisas distintas:

- **rotação** = novo valor a cada resposta com `Set-Cookie` (dezenas por segundo);
- **`Max-Age=30`** = prazo de validade do `TS6695b38b029`, um atributo que o
  servidor envia — não um período de rotação.

Não existe "janela de 30 s" entre rotações a ser perdida. O §9.3-R2.4 já havia
refutado o atraso do POST como discriminador; a R3.1 remove também o mecanismo
que a hipótese original supunha.

##### R3.2 — Duas famílias de cookie `[FACT]`

| rotaciona a cada resposta           | nunca rotaciona na sessão                    |
| ----------------------------------- | -------------------------------------------- |
| `TS0eaa6361027` (52×)               | `TS00000000076` (0) — payload do fingerprint |
| `TS6695b38b029` (17×, `Max-Age=30`) | `TS6695b38b071` (0)                          |
| `TS6695b38b077` (4×)                | `TSPD_101_DID` (0) — device ID               |
| `TS01ec2f54` (2×), `TSPD_101` (2×)  |                                              |

Os cookies que carregam a identidade coletada (`TS00000000076`, `TSPD_101_DID`)
são **estáveis**; os que rotacionam são os de sessão/tráfego.

##### R3.3 — Contagem de rotações NÃO discrimina o desfecho `[REFUTED]`

| execução       | desfecho   | rotações |
| -------------- | ---------- | -------- |
| exp_1788346277 | BLOCKED    | **44**   |
| exp_cloud      | BLOCKED    | **72**   |
| 9 execuções    | ACCEPTED   | 75–79    |
| exp_1788357858 | não chegou | **133**  |

As duas bloqueadas têm as contagens **mais baixas** — e a que mais rotacionou
(133) foi a que ficou repetindo tentativas de clique. A contagem mede
**duração e número de respostas da sessão**, não risco. Correlacionar rotação
com bloqueio sem normalizar por número de respostas produz o sinal invertido.

Isso encerra a **H1** (§9.3-R2 / §26) como formulada: `REFUTED`.

##### R3.4 — `type=17` e `type=22` sempre em par: 12 de 12 `[FACT]`

Contagens por sessão, nas 12 execuções:

```
{17:1, 22:1}  {17:2, 22:2}  {17:3, 22:3} ×9  {17:4, 22:4}
```

**Em nenhuma sessão os dois números divergiram.** Confirmação forte da
§9.3-R2.1: um par (17, 22) por carga de documento. O `type=14` varia entre 1 e 2,
independentemente.

##### R3.5 — A ordem canônica da R2.2 NÃO é estável `[OBSERVATION]`

A §9.3-R2.2 afirmou `18 → 17 → 20 → (12,11) → 22 → 13 → 14` em "6 de 6". Duas
execuções posteriores contradizem:

- `exp_cloud_d1aca865`: `type=14` chegou **12 ms antes** do `type=22`;
- `exp_cloud_1855b4e8`: ordem `14 → 13 → 14` — o **14 antes do 13**.

A ordem tem partes estáveis (18 e 17 primeiro; 20 antes de 11/12) e uma **cauda
variável** (13, 14, 22 entre si). Com diferças de 10–200 ms, pode ser ordem de
entrega ao Playwright e não ordem no fio — mas a afirmação "6 de 6" da R2.2
deve ser lida como **amostra pequena**, não como invariante. É a primeira
evidência positiva para a **H6** (corrida de eventos), que estava sem nenhuma.

##### R3.6 — O bloqueio na nuvem NÃO foi na entrada `[FACT]`

`exp_cloud` (Fargate, 13:26) tinha sido descrito como "bloqueou no dropdown". As
transições mostram mais que isso:

```
T+20040  FORM_SUBMITTED → ACCEPTED   ← o POST de entrada passou (302)
T+29998  ACCEPTED       → BLOCKED    ← bloqueou 10 s depois, no postback do CNPJ
```

**As 5 execuções na nuvem passaram no POST de entrada.** O único bloqueio de
entrada em todo o conjunto continua sendo `exp_1788346277` — o da identidade
contraditória (R2.7). O bloqueio da nuvem é uma **classe diferente de evento**,
com n=1, e não deve ser somado ao outro.

_Nota de instrumentação:_ o rótulo `ACCEPTED` da máquina de estados marca "o
POST de entrada passou", não "a sessão foi aceita" — daí a transição
`ACCEPTED → BLOCKED`, que é semanticamente estranha mas produz `final_state`
correto.

##### R3.7 — Perfil de SO: refutado no local, DESCONHECIDO na nuvem `[REFUTED/UNKNOWN]`

O Camoufox sorteia o SO (windows/macos/linux) a cada launch, mudando UA,
`platform`, resolução e a lista inteira de fontes. Nas 3 primeiras execuções na
nuvem havia divisão perfeita (Windows→bloqueou, macOS→passou ×2).

**Erro de análise cometido e corrigido aqui:** juntei os 12 casos e declarei
`REFUTED`. Pooling só vale se os ambientes forem intercambiáveis, e eles **não
são** (R3.8). Posição correta:

| ambiente | Windows                                   | macOS                    | status                                                             |
| -------- | ----------------------------------------- | ------------------------ | ------------------------------------------------------------------ |
| local    | 3 ACCEPTED, 1 BLOCKED (o do UA fabricado) | 2 ACCEPTED, 1 não chegou | `REFUTED`                                                          |
| nuvem    | 0 ACCEPTED, 1 BLOCKED                     | 4 ACCEPTED               | ~~`UNKNOWN`~~ → **resolvido em §9.3-R4.1: `CORRELATION`, p=0,014** |
| agregado | —                                         | —                        | **inválido**                                                       |

_Verificado ao fixar o SO:_ o spoof do Camoufox é **coerente em todas as
camadas** — declarando macOS ele também remove as fontes exclusivas do Windows
(`Segoe UI`, `Calibri` somem da detecção). Fixar não introduz contradição.
`CONFIG["camoufox"]["os"]` passou a ser variável declarada e registrada no `env`.

##### R3.8 — O Fargate não é comparavel ao local `[FACT]`

|                    | local                       | Fargate              |
| ------------------ | --------------------------- | -------------------- |
| `webgl.renderer`   | `ANGLE (NVIDIA GTX 980...)` | **`None`**           |
| `webgl.renderHash` | presente                    | **`None`**           |
| `audio`            | hash                        | **`err`**            |
| IP de saída        | fixo (`<IP-RESIDENCIAL>`)   | **novo a cada task** |

Não é só ausência de GPU (o §7.1 previa SwiftShader): **não há WebGL algum**, e
o `type=11` não recebe renderer nenhum. Somado ao IP que muda por task, duas
execuções na nuvem nunca são comparáveis entre si na dimensão de origem, nem
com as locais na dimensão de fingerprint.

##### R3.9 — Estado da H8 (coerência interna da identidade)

Depois da remoção dos spoofs (R2.7): **11 execuções, 9 ACCEPTED**, 1 bloqueio
pós-entrada (R3.6) e 1 falha do harness (clique fora da viewport em headless, já
corrigida). O único bloqueio **no POST de entrada** em todo o conjunto é o
único caso com UA fabricado.

**Status: `WEAKLY_SUPPORTED` → mantido.** Não sobe para `SUPPORTED` porque
continua sem grupo de controle: nenhuma execução **reintroduziu** o UA
contraditório para verificar se o bloqueio volta. Sem esse braço, "9 passaram
depois de remover" é série temporal, não experimento.

##### R3.10 — Correções de instrumento

Quatro defeitos do próprio instrumento, encontrados e corrigidos:

1. **`imagemDinamica.aspx` contava como documento principal.** É a imagem do
   CAPTCHA (`content-type: image/gif`), mas a URL termina em `.aspx`. Virava o
   "último estado" da sessão e devolvia `UNKNOWN`. Agora o `content-type`
   confirma; header ausente preserva a regra antiga (nunca inferir).
2. **A máquina de estados marcava `out_of_order` em TODA sessão**, por usar a
   ordem idealizada do §9.2 em vez da observada. Falso positivo permanente que
   poluia a H6 — justamente a hipótese que depende desse sinal.
3. **`dd_post_stale` era falso positivo** (já registrado em R2.5); a correção
   confirma-se: `nenhum` em todas as 11 execuções seguintes.
4. **`navigator.oscpu` e `buildID` não eram capturados no baseline** — apesar de
   serem evidência central da R2.7. Vinham só do `FULL_FP_JS`. Adicionados, com
   uma checagem automática de coerência `userAgent × platform × oscpu` que
   sinaliza no relatório quando os três discordam — o padrão da R2.7 passa a ser
   detectado sozinho.

---

#### 9.3-R4 — Revisão (2026-09-02, fim de tarde): o SO discrimina na AWS, e a explicação óbvia está REFUTADA

> Não substitui nenhuma revisão anterior. Base: **8 execuções no Fargate** com o
> perfil de SO do Camoufox controlado (§9.3-R3.7), somadas às 8 locais.
> Registra um resultado estatisticamente sólido **e** a refutação do mecanismo
> que havíamos proposto para explicá-lo.

---

##### R4.1 — O perfil de SO discrimina o desfecho na AWS `[CORRELATION, p = 0,014]`

| task     | SO declarado | `os` configurado | tela      | IP         | desfecho    |
| -------- | ------------ | ---------------- | --------- | ---------- | ----------- |
| (1ª)     | Windows      | sorteado         | 1920x1080 | <IP-AWS-1> | **BLOCKED** |
| 6da684f3 | Windows      | `windows`        | 2560x1440 | <IP-AWS-2> | **BLOCKED** |
| 48634e53 | Windows      | `windows`        | 2560x1440 | <IP-AWS-3> | **BLOCKED** |
| 0668181c | Linux        | `linux`          | 1485x928  | <IP-AWS-4> | **BLOCKED** |
| 870ba5b4 | macOS        | sorteado         | 1440x900  | <IP-AWS-5> | ACCEPTED    |
| (2ª)     | macOS        | sorteado         | 2816x1584 | <IP-AWS-6> | ACCEPTED    |
| 1aca8659 | macOS        | sorteado         | 2560x1440 | <IP-AWS-7> | ACCEPTED    |
| 855b4e87 | macOS        | `macos`          | 2816x1584 | <IP-AWS-8> | ACCEPTED    |

**4 bloqueios em 8 execuções, todos evitando perfeitamente as 4 macOS.**

Sob a hipótese nula (SO irrelevante), a chance de os 4 bloqueios caírem
exatamente nas 4 não-macOS é:

```
P = 1 / C(8,4) = 1/70 = 0,0143
```

Abaixo do limiar convencional de 0,05. **Este é o primeiro resultado
estatisticamente sólido do estudo.** Continua sendo `CORRELATION`, não causa:
n=8, um único ambiente, e o desenho não controla tempo.

_Como o experimento foi feito:_ `CONFIG["camoufox"]["os"]` virou variável
declarada, ajustável por `F5_CAMOUFOX_OS` na task definition, e registrada no
`env` da timeline forense — as 3 execuções Windows e a Linux foram
deliberadamente forçadas, não sorteadas.

##### R4.2 — H9 (coerência de camada de rede) — `REFUTED`

**Hipótese proposta.** O Camoufox falsifica a camada JS (`userAgent`,
`platform`, `oscpu`, fontes) de forma coerente, mas não alcança a pilha TCP/IP
do kernel, que vaza o SO real (TTL inicial 64 no Linux/macOS, 128 no Windows;
opções TCP distintas). Um BIG-IP é um appliance de rede e faz fingerprinting
passivo de SO na camada 3/4. Logo, "Windows declarado sobre kernel Linux" seria
uma contradição **entre camadas** — a H8 estendida à rede.

A hipótese explicava elegantemente os dados de então: Windows-sobre-Linux
(mismatch) bloqueava, macOS-sobre-Linux (TTL 64 = TTL 64, match) passava, e
Windows-sobre-Windows no local (match) passava.

**Predição testada.** `linux` no Fargate é o caso de **coerência máxima**:
claim e realidade idênticos em toda camada. Deveria passar.

**Resultado.** `exp_cloud_90668181` — `camoufox_os=linux`, UA
`X11; Linux x86_64`, `platform: Linux x86_64`, `oscpu: Linux x86_64`,
`divergencias: []`. **BLOQUEOU** no postback do CNPJ (T+31204), support ID
`13461926412164363221`.

O caso mais coerente possível bloqueou. **A coerência entre camadas não explica
os dados.** `REFUTED`.

_Registrar a refutação importa tanto quanto registrar a confirmação — mesmo
critério aplicado ao `lo32` em §9.3-R1.a._

##### R4.3 — O padrão real é "macOS passa", não "coerente passa" `[OBSERVATION]`

Com a H9 fora, o que sobra é mais estranho do que a explicação que a substituiu:

```
macOS    4/4 passaram
Windows  3/3 bloquearam
Linux    1/1 bloqueou
```

Não é coerência; é o **valor específico** do perfil. Nenhum mecanismo conhecido
explica por que um BIG-IP trataria um cliente macOS diferente de um Linux
quando ambos apresentam identidade JS internamente consistente.

##### R4.4 — Resolução de tela NÃO é o confundidor `[REFUTED]`

O Camoufox sorteia a resolução **junto** com o SO, o que levantaria a suspeita
de que "macOS" e "telas grandes" estivessem amarrados. Os dados já contêm o
contra-exemplo:

| tela      | SO      | desfecho     |
| --------- | ------- | ------------ |
| 2560x1440 | Windows | BLOCKED (×2) |
| 2560x1440 | macOS   | ACCEPTED     |

Mesma resolução, desfechos opostos. A resolução, sozinha, não explica.

##### R4.5 — `hi32` idêntico em 4 bloqueios com 4 IPs distintos `[FACT]`

```
hi32 nos 4 bloqueios : 3134348991  (o mesmo em todos)
IPs nos 4 bloqueios  : <IP-AWS-1>, <IP-AWS-2>,
                       <IP-AWS-3>, <IP-AWS-4>
```

Quatro IPs em faixas AWS diferentes produziram o **mesmo** `hi32`. Reforça
fortemente o §9.3-R1.a e o §9.3-R1.b: `hi32` é estável por origem mas **não é
o IP**. Com n=4 e faixas distintas, a leitura de `hi32` como IPv4 fica ainda
mais difícil de sustentar.

##### R4.6 — Todas as 8 execuções passam no POST de entrada `[FACT]`

Em **8 de 8**, a transição `FORM_SUBMITTED → ACCEPTED` ocorre (302 no
`POST /Pages/Login.aspx`). Quando há bloqueio, ele vem depois, no **postback do
CNPJ**, 9–16 s mais tarde:

```
T+20707  FORM_SUBMITTED → ACCEPTED   (302 na entrada)
T+31204  ACCEPTED       → BLOCKED    (postback do CNPJ)
```

O único bloqueio **na entrada** de todo o estudo continua sendo
`exp_1788346277` — o da identidade contraditória (§9.3-R2.7). São duas classes
de evento e não devem ser somadas.

##### R4.7 — A assimetria local × nuvem permanece sem explicação `[UNKNOWN]`

| ambiente             | Windows      | macOS        |
| -------------------- | ------------ | ------------ |
| local (host Windows) | 3/3 passaram | 2/2 passaram |
| Fargate (host Linux) | 0/3 passaram | 4/4 passaram |

Localmente o SO **não** discrimina; na nuvem discrimina com p=0,014. Qualquer
hipótese futura precisa acomodar as duas coisas ao mesmo tempo. Os ambientes
diferem em pelo menos: ausência total de WebGL no Fargate (§9.3-R3.8), IP
residencial fixo × IPs AWS variáveis, e histórico acumulado da origem.

##### R4.8 — Restrições para qualquer hipótese futura

Qualquer explicação proposta daqui em diante precisa ser compatível com:

1. macOS 4/4 passa, Windows 3/3 e Linux 1/1 bloqueiam — **na AWS**;
2. no local, nenhum SO discrimina;
3. o bloqueio nunca é na entrada, sempre no postback do CNPJ;
4. `hi32` constante em 4 IPs distintos;
5. resolução de tela não explica (R4.4);
6. coerência JS↔kernel não explica (R4.2);
7. a identidade JS é internamente consistente nas 8 (`divergencias: []`).

#### 9.3-R5 — Revisão (2026-09-03): 19 sessões agregadas, `hi32` no IP residencial, e a refutação do componente de fontes

> Não substitui nenhuma revisão anterior. Base: **as 19 sessões acumuladas**
> (8 locais + 11 na nuvem), reprocessadas de uma vez pelo agregador novo
> `forensic/matrix.py` — `python forensic_report.py matrix <base> --por-origem`.
> Três das sessões na nuvem são posteriores ao fechamento do §9.3-R4 e nunca
> tinham sido incorporadas; uma quarta evidência estava em disco mas ilegível.

---

##### R5.1 — Recuperação de evidência: o relatório do único bloqueio local `[FACT]`

O `report.txt` de `exp_1788346277` — a **única sessão local BLOCKED de todo o
estudo** — continha 82 bytes: uma mensagem de `AttributeError` do renderizador,
no lugar do relatório.

O defeito era do renderizador e foi corrigido ainda em 02-09; o artefato em
disco, porém, continuou sendo a mensagem de falha. Como o
`forensic_timeline.jsonl` é a evidência primária e nunca foi perdido, o
relatório foi **reconstruído** (82 → 21 731 B) pelo comando novo
`forensic_report.py regen`, que só regenera onde existe JSONL e preserva o
conteúdo anterior em `report.txt.prev`.

_A lição de método: um relatório derivado que falha ao ser gerado precisa ser
regenerável, senão a evidência fica viva no JSONL e morta na prática._

##### R5.2 — `hi32` é constante TAMBÉM no IP residencial `[FACT]`

O relatório recuperado trouxe o support ID que faltava:

```
exp_1788346277   IP <IP-RESIDENCIAL> (residencial, Brasil)
support ID raw = 13461926414059725184
hi32 = 3134348991      lo32 = 3464126848
```

Somado aos 5 bloqueios na AWS:

| bloqueio             | IP               | faixa          | `hi32`         |
| -------------------- | ---------------- | -------------- | -------------- |
| `exp_1788346277`     | <IP-RESIDENCIAL> | residencial BR | **3134348991** |
| `exp_cloud`          | <IP-AWS-1>       | AWS            | **3134348991** |
| `exp_cloud_06da684f` | <IP-AWS-2>       | AWS            | **3134348991** |
| `exp_cloud_648634e5` | <IP-AWS-3>       | AWS            | **3134348991** |
| `exp_cloud_90668181` | <IP-AWS-4>       | AWS            | **3134348991** |
| `exp_cloud_5cf5e2af` | <IP-AWS-9>       | AWS            | **3134348991** |

**Seis bloqueios, seis origens de rede, um único `hi32`.**

O §9.3-R4.5 dizia que `hi32` é "estável por origem mas não é o IP". Com o
bloqueio residencial incluído, a formulação precisa ser mais forte: `hi32` **não
depende da origem de forma alguma** — nem de faixa, nem de provedor, nem de
país de saída. Uma conexão doméstica brasileira e quatro faixas AWS distintas
produzem o mesmo valor.

A leitura que sobrevive é que `hi32` identifica algo do **lado do F5** — o
appliance, o virtual server ou a política que emitiu a rejeição — e não o
cliente. Isso encerra as leituras de `hi32` como IP e como identificador de
sessão. `[FACT]`

##### R5.3 — `lo32` como relógio: refutação confirmada com n=6 `[REFUTED]`

A hipótese já estava `REFUTED` desde o §9.3-R1.a e **não foi reaberta**; o dado
novo apenas a reforça. Ordenando os 6 bloqueios pelo `start_wall_ns` real:

```
19:46:54   lo32 = 1568764885
20:07:44   lo32 = 1565604807     ← 21 min DEPOIS, valor MENOR
```

Um contador temporal não anda para trás. Com n=6 e instantes medidos, a leitura
de `lo32` como relógio continua refutada.

##### R5.4 — O componente de fontes NÃO explica o desfecho `[REFUTED]`

Esta era a candidata mais forte que restava, e é a que cai.

Na nuvem, a lista de fontes separa os desfechos **perfeitamente** — o que a
tornaria a explicação óbvia. Mas o contra-exemplo já estava nos dados locais:

| sessão                     | fontes detectadas                                                                          | desfecho     |
| -------------------------- | ------------------------------------------------------------------------------------------ | ------------ |
| `exp_1788353297` (local)   | `Arial, Calibri, Segoe UI, Times New Roman, Courier New, Verdana, Georgia, Tahoma, Impact` | **ACCEPTED** |
| `exp_cloud_5cf5e2af` (AWS) | `Arial, Calibri, Segoe UI, Times New Roman, Courier New, Verdana, Georgia, Tahoma, Impact` | **BLOCKED**  |

Lista **byte-idêntica**, desfechos opostos. `exp_1788354306` (local, mesmas 9
fontes) também passou.

A hipótese H9 do briefing — "algum componente específico de fingerprint,
incluindo a informação de fontes disponível ao engine, explica a diferença" —
está **refutada na forma forte**. Por extensão, o mesmo contra-exemplo atinge
qualquer explicação puramente client-side: as duas sessões apresentaram o mesmo
conjunto de fontes, a mesma `platform`, o mesmo motor e a mesma identidade JS
internamente consistente, e mesmo assim divergiram.

##### R5.5 — A assimetria local × nuvem, agora medida `[CORRELATION]`

O §9.3-R4.7 afirmava a assimetria; o agregador a quantifica. Mesma variável,
mesmo teste, dentro de cada estrato:

```
── origem = cloud   (11 sessoes) ──
  os_observado   [SEPARACAO PERFEITA]
    linux      ACCEPTED=0  BLOCKED=1
    macos      ACCEPTED=6  BLOCKED=0
    windows    ACCEPTED=0  BLOCKED=4
    p = 0.0022

── origem = local   (8 sessoes) ──
  os_observado
    macos      ACCEPTED=3  BLOCKED=0  INCOMPLETE=1
    windows    ACCEPTED=3  BLOCKED=1
    p = 0.5714
```

Na nuvem, `p = 1/C(11,6) = 0,0022` — melhor que os 0,0143 do §9.3-R4.1, porque
as 3 sessões novas mantiveram a separação (macOS 6/6 passa, não-macOS 5/5
bloqueia). No local, `p = 0,57`: **nenhum efeito**.

A mesma variável discrimina fortemente num ambiente e nada no outro. Isso é uma
**interação**, não um efeito principal — e nenhuma explicação que trate o perfil
de SO como causa isolada pode estar certa.

_O tempo não é o confundidor:_ às 20:07 uma sessão Windows bloqueou e às 20:10
— 3 minutos depois, mesmo ambiente — uma sessão macOS passou. Não existe corte
temporal que separe os desfechos observados.

##### R5.6 — Variáveis eliminadas pelo agregado `[REFUTED]`

O agregador procura, antes de qualquer `p`, o **contra-exemplo**: duas sessões
com o mesmo valor da variável e desfechos opostos. Enquanto existir um par
desses, a variável sozinha não explica. Todas as testadas têm:

| variável               | contra-exemplo        | veredito            |
| ---------------------- | --------------------- | ------------------- |
| `origem`               | local A×B, cloud A×B  | `REFUTED`           |
| `os_observado`         | Windows local A×B     | `REFUTED` (isolada) |
| `fonts_key`            | idêntica, A×B (R5.4)  | `REFUTED`           |
| `fonts_total`          | 8 e 9 em ambos        | `REFUTED`           |
| `engine`               | camoufox A×B          | `REFUTED`           |
| `hardware_concurrency` | 8 e 16 em ambos       | `REFUTED`           |
| `public_ip`            | <IP-RESIDENCIAL> A×B  | `REFUTED`           |
| `renderer_class`       | DESKTOP e AUSENTE A×B | `REFUTED`           |

`public_ip` merece nota: com 12 categorias para 19 sessões ele "separaria" por
construção, e o agregador o **descarta explicitamente** em vez de reportar o `p`
minúsculo que sairia dali. Uma variável quase-única sempre separa; isso é
sobreajuste, não evidência.

##### R5.7 — Estado das hipóteses após R5

| hipótese                          | antes            | agora                                             |
| --------------------------------- | ---------------- | ------------------------------------------------- |
| H1 rotação de cookie              | `REFUTED` (R3.3) | `REFUTED`                                         |
| lo32 como relógio                 | `REFUTED` (R1.a) | `REFUTED` (n=6)                                   |
| H8 coerência interna              | aberta (R3.9)    | sem evidência nova                                |
| H9 coerência de rede              | `REFUTED` (R4.2) | `REFUTED`                                         |
| **componente de fontes**          | candidata        | **`REFUTED`** (R5.4)                              |
| perfil de SO isolado              | `CORRELATION`    | **`CONFOUNDED`** — interage com o ambiente (R5.5) |
| `hi32` = identificador do cliente | duvidosa (R4.5)  | **`REFUTED`** (R5.2)                              |

##### R5.8 — O que sobra, e o que falta observar

Depois de R5.4 e R5.6, **nenhuma variável client-side registrada explica o
desfecho** — todas têm contra-exemplo. O que diferencia os dois ambientes e
**não** é observado pelo instrumento atual:

1. **camada de rede** — TLS (JA3/JA4), ordem de extensões, `SETTINGS` do
   HTTP/2, ordem dos headers. O BIG-IP é um appliance de rede e enxerga isso;
   o baseline forense, que roda dentro da página, não.
2. **histórico da origem no servidor** — estado acumulado por faixa, invisível
   ao cliente por construção.

Estas são as duas candidatas restantes, e são **experimentalmente
distinguíveis**. A ordem correta é atacar (1) primeiro, porque tem um teste que
não custa nenhuma sessão nova contra o CADESP:

> **Predição falsificável.** Se a camada de rede for a variável causal, então
> sessões AWS com perfil macOS e com perfil Windows precisam apresentar
> **assinaturas TLS/HTTP2 distintas**. O Camoufox falsifica a camada JS; se ele
> **não** alterar a pilha TLS junto com o perfil de SO, as duas classes terão
> a mesma assinatura — e a camada de rede **não pode** explicar uma diferença
> de desfecho que acompanha perfeitamente o perfil de SO. `REFUTED`.
>
> Se as assinaturas diferirem, a hipótese sobrevive e passa a merecer um
> experimento de intervenção com controle.

Observar isso exige registrar o handshake — instrumentação nova. Fica
registrado como o próximo passo **proposto**, não executado.

##### R5.9 — Nota de instrumento

O agregado desta revisão veio de `forensic/matrix.py`, módulo novo e puramente
offline: lê `logs/**/forensic/<exp>/`, não abre browser, não toca a rede, não
executa teste. Ele lê o JSONL quando existe (10 sessões) e cai para
`session_summary.json` + `report.txt` quando o JSONL não foi recolhido da nuvem
(9 sessões) — sem esse recurso, 9 das 19 sessões e 4 dos 6 bloqueios ficariam
fora de qualquer estatística. Cada linha do relatório carrega a **procedência**,
para que a diferença de fonte fique visível em vez de escondida.

`python t.py` não foi modificado por esta revisão.

#### 9.3-R6 — Experimento (2026-09-03): a camada TLS não acompanha o perfil de SO — HR1 `REFUTED`

> Primeiro experimento **de intervenção** do estudo, e o primeiro que não custou
> nenhuma sessão contra o CADESP. Hipótese, predição e regra de decisão foram
> escritas **antes** da execução, em `exp_tls_profile.py`; o desfecho
> ACCEPTED/BLOCKED do F5 não participa e sequer é consultado.

---

##### R6.1 — O desenho

O §9.3-R5.8 deixou duas hipóteses de pé. A primeira:

> **HR1** — a camada de rede (assinatura TLS/HTTP2) é a variável causal por
> trás da separação perfeita entre perfis de SO observada na AWS (§9.3-R5.5).

A HR1 é atraente porque explicaria a assimetria local × nuvem sem apelar para
nada mágico: o BIG-IP é um appliance de rede e enxerga o handshake, que o
baseline forense — executado **dentro** da página — não alcança.

Ela também faz uma predição barata e falsificável:

```
se HR1 for verdadeira
  -> perfis macos e windows do Camoufox produzem ClientHello DISTINTOS
se produzirem ClientHello IDENTICOS
  -> a camada TLS nao acompanha o perfil de SO
  -> nao pode explicar uma diferenca de desfecho que acompanha
     o perfil de SO perfeitamente
  -> HR1 REFUTED
```

|                       |                                                                         |
| --------------------- | ----------------------------------------------------------------------- |
| variável independente | `CONFIG["camoufox"]["os"]` ∈ {macos, windows}                           |
| variável dependente   | estrutura do ClientHello (JA3 + campos crus)                            |
| N                     | 3 lançamentos independentes por perfil (browser sobe e desce a cada um) |
| alvo                  | `127.0.0.1`, servidor TCP local                                         |
| tráfego para o CADESP | **nenhum**                                                              |

O servidor local não fala TLS: lê o primeiro record e fecha. Basta, porque o
ClientHello é a primeira coisa que o cliente envia — antes de qualquer
validação de certificado. O browser reporta erro de TLS; é o esperado e não
afeta a medida.

##### R6.2 — O controle que torna o resultado interpretável `[FACT]`

Antes de comparar perfis, medimos a variação **dentro** de cada perfil. Sem
isso, uma diferença entre perfis não seria atribuível ao perfil:

```
CONTROLE — variacao DENTRO de cada perfil
  macos    n=3  assinaturas distintas=1  estavel
  windows  n=3  assinaturas distintas=1  estavel
```

Estável nos dois. A regra de decisão declarada previa reportar `CONFOUNDED` se
houvesse variação intra-perfil; não houve.

##### R6.3 — A manipulação de fato ocorreu `[FACT]`

Verificação de validade obrigatória: um ClientHello idêntico só significa algo
se a variável independente tiver realmente variado. Variou, e no lugar certo:

```
macos    #1 #2 #3   navigator.platform = MacIntel
windows  #1 #2 #3   navigator.platform = Win32
```

3 de 3 em cada perfil. O spoof funcionou na camada JS — a mesma camada em que o
`os_observado` do §9.3-R5.5 é medido.

##### R6.4 — O resultado `[REFUTED]`

```
macos    ja3 = dfc1768fa3cf4a239df894bbfbe05c3d
windows  ja3 = dfc1768fa3cf4a239df894bbfbe05c3d
```

Idênticos. E não só o JA3: a assinatura estendida — que inclui ALPN,
`supported_versions` e algoritmos de assinatura, campos que o JA3 clássico
ignora — também bate byte a byte (`075e4380894157fa` nos 6 lançamentos).

```
JA3 string (identica nos dois perfis):
771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49171-49172-156-157-47-53,
    23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,
    4588-29-23-24-25-256,0
ALPN: h2, http/1.1     supported_versions: TLS1.3, TLS1.2
```

**O perfil de SO do Camoufox é um spoof de camada JS e não alcança a pilha
TLS.** Declarar Windows ou macOS produz exatamente o mesmo handshake.

Portanto a assinatura TLS **não pode** explicar uma diferença de desfecho que
acompanha o perfil de SO com separação perfeita (§9.3-R5.5): a suposta causa é
constante justamente onde o efeito varia. `HR1 REFUTED`.

##### R6.5 — Escopo da refutação, e o que ela NÃO cobre

Registrar o limite importa tanto quanto o resultado:

1. Refuta a **camada TLS (ClientHello)** como a variável causal desta
   separação. **Não** mede `SETTINGS` do HTTP/2 nem ordem de headers, que
   viajam depois do handshake — o servidor local fecha antes. O ALPN idêntico
   (`h2, http/1.1`) é indício de que a camada H2 também não varia, mas é
   indício, não medida.
2. O binário testado é o **local** (Camoufox 152.0.4-beta.28); as sessões da
   nuvem rodaram 152.0.4-beta.29. O argumento é estrutural — o spoof de SO é
   de camada JS e não toca o NSS — mas a versão não é rigorosamente a mesma.
3. Refuta a HR1 **na forma que ela foi enunciada**: TLS como a variável que
   acompanha o perfil de SO. Não afirma que o F5 ignore fingerprint de rede;
   afirma que essa assinatura não é o que difere entre nossas sessões macOS e
   Windows.

##### R6.6 — Estado das hipóteses após R6

| hipótese                            | antes               | agora           |
| ----------------------------------- | ------------------- | --------------- |
| **HR1 camada de rede (TLS)**        | candidata (R5.8)    | **`REFUTED`**   |
| HR2 histórico da origem no servidor | candidata (R5.8)    | **única de pé** |
| perfil de SO isolado                | `CONFOUNDED` (R5.5) | `CONFOUNDED`    |
| componente de fontes                | `REFUTED` (R5.4)    | `REFUTED`       |
| `hi32` = identificador do cliente   | `REFUTED` (R5.2)    | `REFUTED`       |

Depois de R5.4, R5.6 e R6.4, **nenhuma variável observável do lado do cliente
explica o desfecho** — nem fingerprint, nem fontes, nem TLS. Todas ou têm
contra-exemplo direto, ou são constantes onde o efeito varia.

##### R6.7 — O que isso deixa, e por que é desconfortável

A HR2 fica sozinha, e ela é a hipótese mais difícil de testar do estudo: o
estado acumulado do servidor é **invisível ao cliente por construção**. Não há
nada a instrumentar no browser que o revele.

Restrição adicional que qualquer forma da HR2 precisa acomodar: ela tem de
explicar por que o desfecho acompanha o **perfil de SO** — uma variável de
camada JS — sem que nenhuma variável de camada de rede acompanhe. Um estado de
servidor indexado por faixa de IP não faria isso sozinho; precisaria estar
indexado por algo derivado do fingerprint enviado, o que reintroduz a camada
JS por outra porta.

Dito com honestidade: o espaço de hipóteses encolheu bastante e o que sobrou
não fecha. O §46 diz para não procurar a resposta conveniente — então o
registro correto aqui é **`UNKNOWN` com o campo reduzido**, e não uma HR2
promovida por eliminação.

Os próximos passos experimentalmente distinguíveis, em ordem de custo:

1. **HTTP/2 `SETTINGS` e ordem de headers** — fecha a lacuna do R6.5.1.
   Exige terminar TLS de verdade no servidor local (certificado + ALPN h2).
   Continua sem custar sessão contra o alvo.
2. **Contraste de faixa com perfil fixo** — na AWS, N sessões com o MESMO
   perfil (macOS) em faixas distintas. Se a faixa importa, o desfecho varia com
   o perfil constante. Custa sessões e precisa de desenho cuidadoso.

##### R6.8 — Nota de instrumento

`forensic/tlsfp.py` (parser puro de ClientHello + JA3) e `exp_tls_profile.py`
(runner). Nenhum dos dois toca `t.py`, o `f5monitor` ou o fluxo real.

Um defeito encontrado pelos testes antes da execução, e vale registrar porque
teria sido invisível no resultado: o `record_length` lia o tamanho do record
nos bytes `[1:3]`, que são a **versão** e não o tamanho — o servidor ficaria
esperando ~774 bytes que nunca chegariam. O teste que pegou isso monta um
ClientHello sintético e confere o tamanho anunciado contra o real.

Coberto também o tratamento de GREASE (RFC 8701): sem removê-lo, cada conexão
pareceria única e o experimento reportaria `SUPPORTED` **por defeito de
instrumento**, sustentando a HR1 falsamente. Há teste dedicado a isso.

Dados brutos: `logs/forensic/_exp_tls_profile/clienthello-*.json` (os 6
ClientHello completos, campo a campo).

#### 9.3-R7 — Revisão (2026-09-03): a camada de rede cai por inteiro, e uma hipótese morre antes de custar uma sessão

> Três resultados: o confundidor de configuração foi removido; a hipótese HR4
> (fontes fabricadas) foi refutada pelos dados que já tínhamos, antes de
> qualquer execução; e a lacuna que o §9.3-R6.5 deixou aberta foi fechada.
> Nenhuma sessão contra o CADESP foi consumida nesta revisão.

---

##### R7.1 — O `config.py` estava fixado no valor que passa `[nota de método]`

Enquanto o §9.3-R4 e o §9.3-R5 mediam o efeito do perfil de SO, o `config.py`
mantinha `camoufox.os = "macos"` — o **único valor associado a ACCEPTED** — sob
um comentário que afirmava o contrário do que os dados mostram:

```
"a hipotese de que o SO discrimina o desfecho foi REFUTADA
 (3 das 5 execucoes com perfil Windows passaram)"
```

Isso valia para as execuções **locais**. Na AWS o resultado é o oposto
(§9.3-R4.1, §9.3-R5.5). O comentário obsoleto mantinha fixada exatamente a
variável mais carregada do estudo, no valor que passa. Consequências:

1. nenhuma sessão nova conseguiria **testar** essa variável;
2. o estudo derivava para busca de configuração — contra os §8 e §46 do
   briefing.

O motivo original de fixar (tirar o confundidor do sorteio, §9.3-R3.7) já não se
aplica: o SO efetivamente apresentado é recuperável de **toda** sessão pelo
`navigator.platform` do fingerprint — é o `os_observado` do `forensic/matrix.py`.
Sortear não perde mais o registro.

O valor agora é declarado por execução, via `F5_CAMOUFOX_OS`, e sem a variável
definida o Camoufox volta a sortear:

```
F5_CAMOUFOX_OS=windows   python t.py
F5_CAMOUFOX_OS=sorteio   python t.py      (explicito; igual a nao definir)
```

_Registrar isto importa: por três revisões o estudo mediu uma variável que
estava presa. As conclusões de R4 e R5 continuam válidas — todas vieram de
execuções na nuvem com o SO declarado por variável de ambiente — mas qualquer
execução local nesse período carregava o perfil macOS sem que isso estivesse
explícito._

##### R7.2 — O Camoufox empacota as próprias fontes — HR4 `REFUTED`

**Hipótese proposta.** Falsificar a _ausência_ de uma fonte é trivial (basta não
reportá-la); falsificar a _presença_ exige que o navegador produza métricas de
glifo de uma fonte que o sistema não tem. Como o `Dockerfile` **não instala
nenhuma fonte**, o perfil Windows na AWS estaria afirmando Calibri e Segoe UI
num contêiner vazio — uma afirmação impossível de sustentar —, enquanto o perfil
macOS afirmaria menos e passaria.

A hipótese encaixava em 19 de 19 sessões, inclusive no contra-exemplo que matou
a hipótese das fontes no §9.3-R5.4.

**Refutação, pelos dados já existentes.** O perfil macOS também reporta 6–7
fontes no mesmo contêiner sem fontes. Se a HR4 estivesse certa, ele deveria
bloquear junto. Passou 6/6.

**A causa do erro, verificada.** O Camoufox não fabrica a afirmação — ele
**fornece os arquivos**:

```
camoufox/Cache/browsers/official/152.0.4-beta.28-386fc2f4/fonts/
  -> 439 arquivos de fonte
     Al Nile.ttc, AlBayan.ttc, Academy Engraved LET.ttf   (macOS)
     segmdl2.ttf, SegUIVar.ttf                            (Segoe/Windows)
```

A detecção por `offsetWidth` é **genuína** nos dois perfis: as fontes estão
mesmo lá, empacotadas com o navegador. O host nunca importou, e o contêuner
estar vazio de fontes de sistema é irrelevante. `HR4 REFUTED`.

_Consequência prática: o experimento que seria proposto — instalar fontes no
contêiner e rodar perfil Linux — não faz sentido e não foi executado. A
hipótese morreu sem custar uma sessão._

##### R7.3 — HTTP/2 e ordem de headers: idênticos entre perfis `[FACT]`

O §9.3-R6.5 declarou uma lacuna: o experimento do ClientHello mede o handshake,
mas o servidor local fechava antes de qualquer tráfego HTTP/2. Ficaram sem medir
os `SETTINGS`, a janela inicial, a ordem dos frames e a ordem dos headers — os
campos que um appliance usa para fingerprint de cliente **além** do JA3.

**HR1'** (resíduo da HR1): se a camada de rede é causal e o TLS já foi
descartado, a diferença tem de estar aí.

Desenho idêntico ao do §9.3-R6, com o servidor local agora **terminando TLS de
verdade** (certificado autoassinado, ALPN negociado) — sem isso o cliente nunca
envia o preface e os `SETTINGS` não chegam. N=3 por perfil, dois caminhos.

```
HTTP/2   (6 capturas, 6/6)
  macos    preface=1|settings=HEADER_TABLE_SIZE:65536,ENABLE_PUSH:0,
           INITIAL_WINDOW_SIZE:131072,MAX_FRAME_SIZE:16384|
           window=12517377|frames=SETTINGS>WINDOW_UPDATE>HEADERS>WINDOW_UPDATE
  windows  (idem, byte a byte)

HTTP/1.1 — ordem dos headers   (6 capturas, 6/6)
  macos    Host>User-Agent>Accept>Accept-Language>Accept-Encoding>Connection>
           Upgrade-Insecure-Requests>Sec-Fetch-Dest>Sec-Fetch-Mode>
           Sec-Fetch-Site>Sec-Fetch-User>Priority
  windows  (idem)
```

Controle: 1 assinatura distinta por perfil nos dois caminhos — **estável**.

**Verificação de validade, in-band.** A demonstração mais limpa possível está no
próprio HTTP/1.1: o **valor** do `User-Agent` difere entre os perfis
(`Macintosh; Intel Mac OS X` × `Windows NT 10.0; Win64`), provando que a
manipulação ocorreu — e mesmo assim a **ordem** dos headers é idêntica. No
caminho h2, `navigator.platform` confirma `MacIntel` × `Win32`, 3/3.

O perfil de SO muda o _conteúdo_ que o cliente declara e não muda **nada** da
estrutura com que ele fala na rede. `HR1' REFUTED`.

##### R7.4 — A camada de rede está descartada por inteiro `[REFUTED]`

Somando §9.3-R6 e este:

| camada                             | medida | acompanha o perfil de SO? |
| ---------------------------------- | ------ | ------------------------- |
| TLS ClientHello (JA3)              | R6.4   | **não**                   |
| ALPN, supported_versions, sig_algs | R6.4   | **não**                   |
| HTTP/2 `SETTINGS` + ordem          | R7.3   | **não**                   |
| janela inicial, ordem de frames    | R7.3   | **não**                   |
| ordem dos headers                  | R7.3   | **não**                   |

Não sobra camada de rede por medir entre o cliente e o appliance. A HR1, na
forma em que foi enunciada — a assinatura de rede como a variável que acompanha
o perfil de SO — está **refutada por completo**.

##### R7.5 — Estado das hipóteses após R7

| hipótese                          | status                                        |
| --------------------------------- | --------------------------------------------- |
| H1 rotação de cookie              | `REFUTED` (R3.3)                              |
| `lo32` = relógio                  | `REFUTED` (R1.a, n=6 em R5.3)                 |
| `hi32` = identificador do cliente | `REFUTED` (R5.2)                              |
| coerência JS↔kernel               | `REFUTED` (R4.2)                              |
| resolução de tela                 | `REFUTED` (R4.4)                              |
| lista de fontes                   | `REFUTED` (R5.4)                              |
| **fontes fabricadas (HR4)**       | **`REFUTED`** (R7.2)                          |
| **camada de rede (HR1, HR1')**    | **`REFUTED`** (R6.4, R7.3)                    |
| perfil de SO isolado              | `CONFOUNDED` — interage com o ambiente (R5.5) |
| HR2 histórico da origem           | `UNKNOWN` — não testada                       |

##### R7.6 — O que sobra, dito com honestidade

O quadro depois de R7 é desconfortável e deve ser registrado como é:

1. na AWS, o desfecho acompanha a **identidade de SO declarada** com separação
   perfeita (p = 0,0022);
2. as duas classes são **internamente coerentes** — fontes reais e empacotadas,
   `platform` coerente, `divergencias: []`;
3. são **indistinguíveis em toda camada de rede medida**;
4. localmente, a mesma variável não discrimina nada (p = 0,57).

Ou seja: o que difere entre uma sessão aceita e uma bloqueada, na AWS, é a
**identidade que o cliente declara** — e nada mais que tenhamos conseguido
medir. Como o `type=11` coleta o fingerprint JS e o envia ao servidor, uma
decisão baseada nessa identidade é perfeitamente possível; o que continua sem
explicação é por que a mesma identidade é aceita de um IP residencial e
rejeitada de faixas AWS.

Isso deixa a HR2 (histórico/reputação da origem) como única de pé — **por
eliminação, não por evidência**. Ela permanece `UNKNOWN`, e o §46 é explícito
quanto a não promover uma hipótese só porque as outras caíram.

Restrição para qualquer teste futuro da HR2: ela precisa explicar por que o
desfecho acompanha uma variável de **camada JS** sem que nenhuma variável de
camada de rede acompanhe. Um estado de servidor indexado por faixa de IP não faz
isso sozinho — precisaria estar indexado por algo derivado do fingerprint
enviado, o que reintroduz a camada JS por outra porta.

O experimento que resta é caro e exige desenho cuidadoso: **contraste de faixa
com perfil fixo** — N sessões na AWS com o MESMO perfil, em faixas distintas. Se
a origem importa, o desfecho varia com o perfil constante.

##### R7.7 — Nota de instrumento

`forensic/h2fp.py` (parser puro de frames HTTP/2 + ordem de headers) e
`exp_h2_profile.py` (runner). Como no R6, nenhum toca `t.py`, o `f5monitor` ou
o fluxo real.

O modo de falha perigoso deste desenho é o simétrico do GREASE no §9.3-R6.8: se
o parser aceitasse um frame **truncado**, a fragmentação de TCP viraria
"diferença entre perfis" e o experimento reportaria `SUPPORTED` por defeito de
instrumento. Há teste dedicado — `parse_frames` para no primeiro frame
incompleto e nunca devolve payload parcial.

Dados brutos: `logs/forensic/_exp_h2_profile/h2-*.json`.

#### 9.3-R8 — Experimento (2026-09-07): o confundidor origem ↔ ambiente foi quebrado — o ambiente basta

> Único experimento da série que gastou uma sessão real contra o CADESP. Uma
> sessão, sem retry, com hipótese, predições opostas e regra de parada
> registradas antes em `exp_origem_vs_ambiente.py`.

---

##### R8.1 — O confundidor que ninguém tinha quebrado `[FACT]`

Até aqui, em 19 de 19 sessões, "origem" e "ambiente" mudaram sempre **juntos**:

|                    | ambiente local<br>(GPU real, Windows real) | ambiente contêiner<br>(sem WebGL, Linux) |
| ------------------ | ------------------------------------------ | ---------------------------------------- |
| **IP residencial** | 6/6 ACCEPTED                               | _vazio_                                  |
| **IP AWS**         | _vazio_                                    | macOS 6/6 ✓, Windows 0/4 ✗               |

As duas células preenchidas estavam na **diagonal**. Por isso "a AWS bloqueia o
perfil Windows" era, até este experimento, **indistinguível** de "o contêiner
sem WebGL bloqueia o perfil Windows". Nenhuma atribuição era possível — e as
revisões R4 a R7 falavam de "origem" sem poder separá-la do ambiente.

##### R8.2 — O desenho

Rodar a **mesma imagem de contêiner**, com o **mesmo perfil `windows`**, na
máquina local — onde o egress é o IP residencial já validado 6/6.

Contra as 4 execuções AWS Windows que bloquearam, muda **uma** coisa:

```
mesma imagem . mesmo perfil windows . mesmo WebGL ausente . mesmo Camoufox
                              |
                      muda so o IP de saida
```

O IP residencial é o **controle**, não o tratamento: ele serve justamente
_porque_ já é conhecido como bom. O experimento não mede o IP — segura o IP no
valor bom para isolar o ambiente.

Predições registradas antes, e opostas:

```
hipotese "a ORIGEM pesa"    -> ACCEPTED   (o IP residencial salva)
hipotese "o AMBIENTE pesa"  -> BLOCKED    (a falta de WebGL continua la)
```

##### R8.3 — Verificação de validade `[FACT]`

Feita in-band, com o que o `t.py` já grava — nenhum instrumento novo:

```
public_ip = <IP-RESIDENCIAL>    OK — residencial, o mesmo das 8 locais
renderer  = None              OK — sem WebGL, ambiente do conteiner
platform  = Win32             perfil windows aplicado
fontes    = 9                 o conjunto Windows, como na AWS
```

O contraste pretendido ocorreu: ambiente de contêiner, origem residencial.

##### R8.4 — O resultado: `BLOCKED` `[FACT]`

```
T+21786  PRE_POST  (login)   -> entrada ACEITA
T+38433  PRE_POST  (CNPJ)    -> estado da maquina: ACCEPTED
T+38439  POST_RESPONSE       -> status=200   veredito=BLOCK
         support ID raw = 13461926412249179823
         hi32 = 3134348991    lo32 = 1653581487
```

Duas coisas a destacar:

1. **A assinatura do bloqueio é a da AWS.** A entrada passa (302 no
   `POST /Pages/Login.aspx`) e o bloqueio vem no **postback do CNPJ** — o
   padrão do §9.3-R4.6, não o do único bloqueio local anterior
   (`exp_1788346277`), que foi na entrada por identidade contraditória. É o
   mesmo fenômeno, reproduzido fora da AWS.
2. **`hi32` continua constante.** Sétimo bloqueio do estudo, mesmo
   `3134348991` — reforçando o §9.3-R5.2: `hi32` é do lado do F5, não do
   cliente.

##### R8.5 — O que isso estabelece, e o que não estabelece

**Estabelece:** o ambiente do contêiner é **suficiente** para produzir o
bloqueio com a origem fixada no valor bom. Logo a origem **não é necessária**
para explicar os 4 bloqueios AWS Windows. `[SUPPORTED]`

**Consequência para a HR2** (histórico/reputação da origem): ela perde a
posição de explicação principal. Não está refutada — a origem ainda pode
_contribuir_ num modelo de soma — mas deixou de ser necessária, e o §9.3-R7.6 a
mantinha de pé apenas por eliminação. `[UNKNOWN → enfraquecida]`

**Não estabelece:**

1. **Não mede a origem.** Para isso falta a outra célula vazia — máquina local
   com GPU real saindo por IP de datacenter —, que exige proxy e código novo.
   Este experimento manteve a origem constante de propósito.
2. **Não identifica qual componente do ambiente** pesa. "Contêiner sem WebGL
   sobre Linux" é um pacote: ausência de WebGL, host Linux, `cores=32`,
   ausência de GPU. O experimento trata o pacote inteiro como uma variável.
3. **Não diz se o perfil de SO ainda discrimina** com a origem fixa. Só o
   perfil `windows` foi rodado, por regra de parada.

##### R8.6 — Nota sobre a regra de parada

A tentação óbvia depois deste resultado é rodar de novo com o perfil `macos`
"para ver". A regra de parada, escrita antes, proíbe isso **dentro deste
experimento** — seria transformar um teste em busca.

O contraste `macos` no contêiner local é, ainda assim, uma pergunta legítima e
diferente: com a origem constante, o perfil de SO continua discriminando? Se
for feito, precisa ser um experimento **novo**, com pré-inscrição própria — não
uma continuação desta.

Estado atual da célula, para quem retomar:

|                  | ambiente contêiner, IP residencial |
| ---------------- | ---------------------------------- |
| perfil `windows` | **BLOCKED** (este experimento)     |
| perfil `macos`   | _não testado_                      |

##### R8.7 — Restrições atualizadas para qualquer hipótese futura

Substitui e estende o §9.3-R4.8. Qualquer explicação precisa acomodar:

1. macOS 6/6 passa e não-macOS 5/5 bloqueia **na AWS** (p = 0,0022);
2. no ambiente local com GPU real, nenhum SO discrimina (p = 0,57);
3. **o ambiente de contêiner bloqueia o perfil Windows mesmo do IP
   residencial** — a origem não é necessária;
4. o bloqueio é sempre no postback do CNPJ, nunca na entrada (exceto o caso de
   identidade contraditória do §9.3-R2.7);
5. `hi32` constante em 7 bloqueios e 6 origens de rede distintas;
6. camada de rede descartada por inteiro — TLS (R6.4), HTTP/2 e ordem de
   headers (R7.3);
7. fontes descartadas como lista (R5.4) e como fabricação (R7.2);
8. a identidade JS é internamente consistente em todas as sessões pós-R2.7.

O quadro que emerge é o de um **modelo de soma com limiar**: sinais
independentes somam, e o limiar cria a aparência de interação sem exigir
qualquer relação causal entre origem e perfil de SO. Isso é `HYPOTHESIS`, não
`FACT` — mas é a leitura compatível com os oito pontos acima, e explica por que
nenhuma variável isolada jamais separou os desfechos.

_Consequência metodológica que vale registrar:_ as refutações por
contra-exemplo do §9.3-R5.6 e do §9.3-R7 eliminam explicações de **variável
única**. Elas **não** eliminam a contribuição dessas variáveis dentro de uma
soma. Uma tabela de "todas refutadas" pode ser lida como "nada explica", quando
o correto é "nada explica sozinho".

##### R8.8 — Nota de instrumento

`exp_origem_vs_ambiente.py`. Não toca `t.py`, `f5monitor`, o fluxo real, nem
qualquer recurso da AWS — nem task definition, nem `deploy.ps1`, nem
`config_cloud.py`. Voltar ao macOS no Fargate continua sendo `.\deploy.ps1` com
os defaults (`$CamoufoxOs = "macos"`, gravado explicitamente na revisão da task
definition).

A verificação de validade não exigiu instrumento novo: `env.public_ip` e o
`renderer` já eram gravados pelo coletor forense desde o §9.3-R5.

Artefatos: `logs/forensic/exp_local_container_1788794650/`.

#### 9.3-R9 — Experimento (2026-09-07): o efeito do perfil se reproduz localmente, com a origem controlada

> Experimento novo, com pré-inscrição própria em `exp_perfil_no_conteiner.py`
> (não é continuação do §9.3-R8, que encerrou pela regra de parada dele). Uma
> sessão real, sem retry. É o contraste mais limpo de todo o estudo.

---

##### R9.1 — O par R8 / R9 `[FACT]`

Duas sessões na mesma máquina, mesma rede, mesma imagem, com 12 minutos de
diferença. **Uma variável muda:**

|                  | §9.3-R8                     | §9.3-R9      |
| ---------------- | --------------------------- | ------------ |
| perfil declarado | `windows`                   | **`macos`**  |
| ambiente         | contêiner, sem WebGL        | _idem_       |
| host             | o mesmo                     | _idem_       |
| origem           | <IP-RESIDENCIAL>            | _idem_       |
| imagem           | `f5-probe-local:exp-origem` | _idem_       |
| **desfecho**     | **BLOCKED**                 | **ACCEPTED** |

Verificação de validade, in-band nas duas:

```
R8   public_ip=<IP-RESIDENCIAL>   renderer=None   platform=Win32     cores=32  fontes=9
R9   public_ip=<IP-RESIDENCIAL>   renderer=None   platform=MacIntel  cores=8   fontes=6
```

O `POST /Pages/Login.aspx` passou nas duas; a R8 bloqueou no postback do CNPJ
com support ID `13461926412249179823`, a R9 completou.

##### R9.2 — O que isso estabelece `[SUPPORTED]`

O efeito do perfil de SO **é independente da origem** e **reproduzível fora da
AWS**. Até aqui o padrão só tinha sido observado em faixas AWS, onde origem e
ambiente eram indistinguíveis (§9.3-R8.1). Agora ele aparece com a origem
fixada num IP residencial validado 6/6.

Atualizando o agregado — todas as sessões em **ambiente de contêiner**, AWS e
local somadas:

```
macos       7/7  ACCEPTED
windows     5/5  BLOCKED
linux       1/1  BLOCKED

n = 13   separacao perfeita
p = 1/C(13,6) = 1/1716 = 5,8 x 10^-4
```

Antes era p = 0,0022 com n=11, só na AWS. Agora o mesmo padrão atravessa **duas
origens de rede completamente diferentes** — faixas AWS em três regiões e uma
conexão doméstica brasileira.

E o contraste vale nos dois sentidos:

| ambiente              | o perfil discrimina?           |
| --------------------- | ------------------------------ |
| contêiner (sem WebGL) | **sim** — 13/13, p = 5,8×10⁻⁴  |
| local com GPU real    | **não** — p = 0,57 (§9.3-R5.5) |

O efeito do perfil só aparece **no ambiente degradado**. É a interação do
§9.3-R5.5, agora com a origem eliminada como explicação alternativa.

##### R9.3 — Consequência de método: a investigação sai da nuvem

Esta é a parte prática, e era o motivo declarado de gastar a sessão.

Todo experimento futuro sobre este padrão pode rodar **localmente**, em
contêiner, em minutos, sem deploy na AWS e sem o confundidor de origem. Um
ciclo que custava um `deploy.ps1` + task Fargate + recuperação de CloudWatch
passa a custar um `docker run`.

Isso não torna as sessões gratuitas — cada uma continua sendo uma requisição
real a um serviço público, e o escopo do projeto (README: "uma única sessão,
com você presente… não é uma ferramenta de volume") continua valendo. Mas
remove o custo de infraestrutura e, mais importante, **remove uma variável**.

##### R9.4 — Limites, declarados antes do resultado

1. **Não isola nenhum campo.** O perfil é um **pacote de 18 campos** que o
   Camoufox move juntos — UA, `platform`, `oscpu`, 11 campos de tela, fontes,
   `hardwareConcurrency`, `canvas.hash`. A conclusão é sobre o pacote.
2. **n=1 por célula localmente.** O par R8/R9 é uma única observação de cada
   lado. O que lhe dá peso não é o n, e sim a concordância com 11 sessões
   independentes na AWS: 13/13 no total.
3. **Diferença residual não controlada:** a execução R8 reportou `cores=32`
   (o host local tem 32 lógicos) contra 8/16 nas execuções AWS Windows. Como
   aquelas também bloquearam, `cores=32` não é necessário para o bloqueio —
   mas o campo variou e fica registrado.

##### R9.5 — Estado consolidado do estudo após R9

**Refutado, com evidência:**

| hipótese                             | onde                                             |
| ------------------------------------ | ------------------------------------------------ |
| rotação de cookie                    | R3.3                                             |
| `lo32` como relógio                  | R1.a, confirmado n=6 em R5.3                     |
| `hi32` como identificador do cliente | R5.2 — constante em 7 bloqueios, 6 origens       |
| coerência JS↔kernel                  | R4.2                                             |
| resolução de tela isolada            | R4.4                                             |
| lista de fontes                      | R5.4 — lista byte-idêntica, desfechos opostos    |
| fontes fabricadas (HR4)              | R7.2 — o Camoufox empacota 439 arquivos de fonte |
| camada TLS                           | R6.4 — JA3 idêntico entre perfis                 |
| HTTP/2 e ordem de headers            | R7.3 — assinatura idêntica                       |
| origem como condição necessária      | R8 — bloqueia do IP residencial                  |

**Estabelecido:**

- o desfecho acompanha o **pacote de perfil de SO**, mas **só em ambiente
  degradado** (sem WebGL): 13/13, p = 5,8×10⁻⁴;
- em ambiente com GPU real, nenhum perfil discrimina: 8 sessões, p = 0,57;
- o bloqueio é sempre no **postback do CNPJ**, nunca na entrada — exceto o caso
  de identidade internamente contraditória (§9.3-R2.7), que é outra classe;
- `hi32` é constante do lado do F5.

**Em aberto (`UNKNOWN`):**

Qual dos 18 campos do pacote carrega o efeito — ou se nenhum carrega sozinho.
A leitura compatível com tudo continua sendo um **modelo de soma com limiar**:
a ausência de WebGL é uma penalidade compartilhada que consome a folga, e a
diferença entre os pacotes decide. Isso é `HYPOTHESIS`, não `FACT`.

##### R9.6 — Por que o estudo para aqui, e não na próxima sessão

O passo seguinte natural seria isolar os 18 campos. Ele esbarra em três muros,
verificados e não especulados:

1. **O instrumento avisa contra.** O Camoufox expõe 42 chaves de configuração e
   aceita override por propriedade, no nível do navegador (sem
   `add_init_script`, portanto sem o confundidor de `isNative`). Mas emite
   `LeakWarning: Manually setting navigator properties is not recommended` —
   variar um campo isolado quebra a coerência que ele constrói. E incoerência
   interna **é, ela mesma, um bloqueador conhecido** (§9.3-R2.7). Cada teste de
   campo isolado carregaria um confundidor do tipo que já sabemos que bloqueia.
2. **O subconjunto seguro já foi refutado.** Os campos que variam sem criar
   incoerência — `hardwareConcurrency`, `screen.*`, fontes — já têm
   contra-exemplo no corpus (R4.4, R5.4, e cores 8/16 nos dois desfechos). Os
   que ainda não foram testados isoladamente — `platform`, `oscpu`, UA — são
   exatamente os que **não podem** ser variados sem recriar a incoerência.
3. **Um bit por sessão.** Cada execução devolve `ACCEPTED` ou `BLOCKED`.
   Reconstruir uma função de soma com múltiplos termos por sondagem binária
   exigiria dezenas de sessões contra um serviço público — fora do escopo que
   o próprio projeto declara.

Não é que falte curiosidade: é que o **desenho** — saída binária, variáveis
empacotadas, sessões contra um alvo real — atingiu o limite do que consegue
distinguir. Registrar isso é um resultado, não uma desistência. O §46 pede a
explicação que sobrevive aos experimentos, não uma explicação a qualquer custo.

##### R9.7 — Nota de instrumento

`exp_perfil_no_conteiner.py`. Não toca `t.py`, `f5monitor`, o fluxo real, nem
recurso algum da AWS. Voltar ao macOS no Fargate continua sendo `.\deploy.ps1`
com os defaults.

O corpus passa a ter **21 sessões**. As duas novas ficam em
`logs/forensic/exp_local_container_*`; as 19 anteriores em
`logs/history/forensic/`. O agregado de qualquer conjunto sai com:

```
python forensic_report.py matrix <base> --por-origem
```

#### 9.3-R10 — Observação (2026-09-07): o bloqueio acompanha o REUSO da sessão, não a 1ª consulta

Ao capturar cookies com o `teste.py` (hook de `document.cookie` sobre Camoufox),
surgiu um padrão comportamental novo, **ortogonal** ao eixo perfil-de-SO das R4–R9:

- **1ª consulta numa sessão nova → PASSA.** **2ª ação na mesma sessão** (reload, ou
  limpar e pesquisar outro CNPJ) → **BLOQUEIA**. Observado em duas execuções manuais.
- Com **uma instância nova do Camoufox por pesquisa** (contexto/cookies frescos, mesmo
  fingerprint), **as consultas passam** — inclusive uma que retornou dados e outra que
  não retornou. Reproduzido em 3 pesquisas seguidas.

Isso **refina o R4.6** ("bloqueio no postback do CNPJ"): não é o postback em si — é o
**postback subsequente na mesma sessão**. Aponta para um sinal de **reuso/rate de
sessão**, carregado pela "teia" de cookies (§8), não pelo fingerprint.

**Atualização (2026-09-07, 17:48): bloqueio-por-reuso LIMPO no caminho injetado.**
Numa sessão com o Camoufox **injetado** (não o `new_context()` quebrado), a consulta
passou e o bloqueio veio ao clicar **"voltar"** — uma 2ª ação na mesma sessão. Isto
**remove a ressalva** de que só tínhamos bloqueios-artefato: o reuso bloqueia de
verdade, no caminho legítimo.

**Ressalvas de honestidade.** (1) n pequeno, sessões manuais. (2) Um contexto novo
**não troca o IP** — se o sinal fosse rate por IP, contexto novo não resolveria; como
resolveu (3/3), o IP fica **menos** provável, mas não descartado. (3) **Não conseguimos
diffar o fingerprint** para isolar reuso × comportamento × estado-de-cookie: o cookie
client-sealed que deciframos (`TS6695b38b077`) carrega **estado de sessão**, não o
fingerprint (§12.7.a); os cookies de fingerprint são server-sealed. O contador de
rotação avança mais rápido na sessão bloqueada (mais ações), mas isso é consequência,
não causa. Isolar o gatilho do reuso fica como experimento de **caixa-preta** (variar a
ação, observar o bit), não de leitura de conteúdo.

#### 9.3-R11 — Experimento (2026-09-07): a variável dependente vira uma CONTAGEM, e o `hi32` deixa de ser constante

> Pré-inscrição em `exp_reuso.py`, escrita antes da execução. Duas sessões
> declaradas (`windows`, `macos`) + a verificação do controle. Roda no contêiner
> local, sem CAPTCHA e sem interação manual.

---

##### R11.1 — Reconciliação obrigatória: o §9.3-R10 **não** derruba R4–R9 `[FACT]`

O R10 mostrou que o bloqueio acompanha o **reuso** da sessão. Isso poderia ser
lido como "era reuso o tempo todo, não perfil". **Não era**, e a verificação é
direta — contando os POSTs das duas sessões do par R8/R9:

```
R8 (windows) → 2 POSTs → BLOQUEOU no 2º
R9 (macos)   → 2 POSTs → PASSOU
```

Mesmo nível de reuso, mesmo ambiente, mesma origem, 12 minutos de diferença. O
reuso estava **constante** entre as duas e por isso não explica o contraste. Os
dois fatores são independentes:

> o **reuso** determina ONDE o bloqueio pode ocorrer;
> o **perfil** determina SE ele ocorre.

_Registrar isto importa: sem a contagem de POSTs, um leitor futuro concluiria
que o R10 invalida cinco revisões._

##### R11.2 — O desenho: de um bit para um número

Se reuso e perfil são termos de uma soma com limiar, o perfil não decide
"bloqueia ou não" — decide **em qual ação** bloqueia. Isso transforma a variável
dependente de binária em **contagem**, que era o gargalo declarado no §13.4.

|           |                                                                          |
| --------- | ------------------------------------------------------------------------ |
| ação 1    | clique de entrada (`POST /Pages/Login.aspx`)                             |
| ação 2    | seleção do dropdown (postback — foi aqui que a R8 bloqueou)              |
| ações 3–8 | laço: postback do dropdown, alternando entre valores reais do `<select>` |
| teto      | 8, declarado antes                                                       |

Nenhuma ação exige CAPTCHA: o R10 produziu bloqueio com reload e "voltar", nunca
com consulta completa.

##### R11.3 — Resultado `[FACT]`

```
windows   bloqueou na ACAO 2      support ID 5687071027833365820
macos     8 ACOES, sem bloqueio   (chegou ao teto)
```

**Os postbacks são reais** — verificado no log, cada ação do laço produziu o
ciclo completo:

```
[21:18:45] ACAO 3 — dropdown -> 0
[21:18:46] POST /…/ConsultaPublica.aspx    ← 200
[21:18:46] GET type=17  ← 200     (motor comportamental)
[21:18:46] GET type=22  ← 200     (beacon de validação)
```

8 POSTs no total na sessão macOS, cada um com reavaliação do F5. Não foram
no-ops.

Validade in-band nas duas: `public_ip=<IP-RESIDENCIAL>`, `renderer=null`
(ambiente contêiner), `platform` coerente com o perfil pedido (`Win32` /
`MacIntel`).

##### R11.4 — Interpretação, pela regra declarada ANTES `[UNKNOWN]`

A pré-inscrição fixou a regra para não haver reinterpretação conveniente:

> `macos` não bloqueia até o teto → **NÃO** será chamado de "categórico".
> Registrar como `UNKNOWN`, limiar > 8, exigindo o desenho maior.

**É o que se aplica.** O experimento caiu no lado **inconclusivo**: um
não-evento com n=1 é a evidência mais fraca possível. Os dois modelos seguem
vivos:

| modelo                              | compatível?                               |
| ----------------------------------- | ----------------------------------------- |
| soma com limiar (macOS tolera mais) | sim — limiar de macOS > 8, de windows = 2 |
| categórico (macOS nunca bloqueia)   | sim                                       |

O que **mudou** é que o contraste agora é quantitativo: `windows = 2`,
`macos > 8`. Uma diferença de tolerância de pelo menos **4×**, onde antes havia
só "bloqueou / não bloqueou". A variável dependente deixou de ser um bit — este
é o ganho do experimento, mesmo sem resolver a pergunta.

##### R11.5 — Limitação do desenho, declarada `[OBSERVATION]`

As ações 1→2 ficaram ~10 s apart nas duas sessões; as ações 3–8 da sessão macOS
ficaram ~1,5 s apart. **Se o sinal de reuso for por taxa numa janela de tempo, e
não por contagem**, ações rápidas podem não somar como ações espaçadas. O
desenho não distingue as duas leituras.

É um confundidor real e não foi previsto na pré-inscrição. Qualquer repetição
deve espaçar as ações do laço com a mesma cadência de 1→2.

##### R11.6 — O `hi32` NÃO é constante `[FACT — corrige R5.2 e R8.4]`

Achado inesperado e, provavelmente, o mais importante desta rodada.

```
5687071027833365820   hi32 = 1324124407     ← NOVO (este experimento)
1346192641…           hi32 = 3134348991     ← os 8 bloqueios anteriores
```

O §9.3-R5.2 estabeleceu `hi32` como constante em 7 bloqueios e 6 origens de rede,
concluindo que identifica algo **do lado do F5**. A conclusão sobre o _lado_
continua de pé — mas "constante" era uma afirmação sobre a amostra, não uma lei.

Este bloqueio veio do **mesmo IP residencial**, no **mesmo dia**, minutos depois
de outro bloqueio que trouxe `3134348991`. Duas origens idênticas, dois `hi32`
diferentes.

**Consequência:** existe mais de um valor, e ele varia sem que o cliente mude.
Isso é evidência direta para a **H4 do briefing (§28) — "backend/pool: sessões
semelhantes apresentam comportamento diferente em diferentes backends?"** — que
estava listada e **nunca havia sido testada**. `hi32` como identificador de
appliance/nó/política dentro de um pool passa de especulação a leitura
sustentada por observação.

Reformulação honesta do R5.2: _`hi32` não depende da origem do cliente e
identifica algo do lado do F5; assume pelo menos dois valores, e pode variar
entre requisições da mesma origem._

##### R11.7 — O controle não foi queimado `[FACT]`

Havia a preocupação legítima de que gerar bloqueios deliberados degradasse o IP
residencial — que é o **controle** de R8/R9. Não degradou:

```
21:18:02  windows  BLOQUEOU
21:18:31  macos    passou a entrada, e completou 8 ações sem bloqueio
```

Meia hora depois de dois bloqueios no mesmo IP, uma sessão completa passou. Soma-se
a `exp_1788346277` (02-09) e ao par R8/R9: em nenhuma ocasião observada um
bloqueio contaminou a origem.

##### R11.8 — Próximos passos que este resultado abre

1. **Repetir o laço com cadência espaçada** (mesma pausa de 1→2 entre todas as
   ações), para separar "contagem" de "taxa" — o confundidor do R11.5.
2. **Elevar o teto** no braço macOS. Com `windows = 2`, um teto de 20 ainda é
   tráfego modesto e daria o desfecho conclusivo se o limiar existir.
3. **`hi32` como variável observada.** Registrar o `hi32` de todo bloqueio e
   testar se ele correlaciona com o desfecho ou com a latência — a porta de
   entrada para a H4, agora que se sabe que ele varia.

##### R11.9 — Nota de instrumento

`exp_reuso.py`, rodando na imagem derivada `f5-probe-local:exp-reuso`. Não toca
`t.py`, `f5monitor.py`, `browser.py` nem o `Dockerfile` original — importa as
peças de `t.py` e acrescenta o laço.

Dois defeitos encontrados e corrigidos **antes** do resultado valer:

1. `_navega_ate_cnpj` **lê** `r["bloqueado"]`; passar um dict incompleto
   levantava `KeyError` e abortava antes da ação 1.
2. Sem `freeze_on_block`, o retry interno de `_navega_ate_cnpj` (`MAX_ENTRADAS=4`)
   rodava ao levar bloqueio na entrada — a primeira execução gerou **4 support
   IDs**, zerou `monitor.blocked` a cada tentativa e chegou ao laço sem
   formulário na tela. O retry é confundidor reconhecido (§9.3-R1) e aqui
   destruiria a própria contagem.

Artefatos: `logs/forensic/_exp_reuso/{windows,macos}.log`.

---

#### 9.3-R12 — Consolidação (2026-09-07): a exposição acumulada e a hipótese conjuntiva

> Revisão de **método**, não de experimento: nenhuma sessão nova foi executada.
> Cruza o corpus inteiro (R1–R11) para responder o que cada revisão isolada não
> respondia. A afirmação resultante vive no §13.1; esta seção é a auditoria dela.

---

##### R12.1 — Por que existe

O §9.3-R11 registrou a sessão macOS de 8 ações como `UNKNOWN` — correto para a
pergunta estreita que ela testava ("bloqueia em k ≤ 8?"). Mas avaliar aquela
sessão **isolada** subestima o corpus: somada às demais, a exposição do macOS
sem um único bloqueio deixa de ser um não-evento de n=1.

##### R12.2 — Corpus e critério de inclusão `[FACT]`

Entram as sessões com desfecho terminal (`ACCEPTED`/`BLOCKED`) e ambiente
identificável pelo `renderer` do fingerprint — `null` = contêiner (sem WebGL),
valor presente = GPU real. Ações = POSTs `.aspx` da sessão.

| ambiente  | perfil    | sessões | ações | bloqueios |
| --------- | --------- | ------- | ----- | --------- |
| contêiner | não-macOS | 7       | 14    | **7**     |
| contêiner | macOS     | 8       | 22    | 0         |
| GPU real  | não-macOS | 3       | 6     | 0         |
| GPU real  | macOS     | 3       | 6     | 0         |

**Exclusão declarada:** `exp_1788346277` (windows, GPU real, BLOQUEADO) fica de
fora. É o único contra-exemplo e está documentado desde a §9.3-R2.7 como classe
distinta — identidade internamente contraditória (UA de Chrome sobre motor
Gecko, `outerWidth` sobrescrito), bloqueio na **entrada** e não no postback, e a
configuração que o produzia foi corrigida em seguida.

_A conclusão não depende da exclusão:_ incluindo-o, a conjunção fica 7/7 × 1/15
e o Fisher exato dá **p = 4,7×10⁻⁵** em vez de 8,6×10⁻⁶.

##### R12.3 — O teto de risco do macOS `[FACT]`

Zero bloqueios em **22 ações** não prova "nunca bloqueia" — não se prova uma
negativa com exposição limitada. Mas limita o risco. Pela **regra dos três**
(zero eventos em n ensaios → limite superior ≈ 3/n a 95%):

```
risco por ação, macOS      <= 3/22 = 0,136   (IC 95%)
risco por ação, nao-macOS  >= ~0,5           (7/7 bloqueiam ate a acao 2)
razao de risco             >= 3,7x
```

É uma afirmação quantitativa onde antes havia só "bloqueou / não bloqueou".

##### R12.4 — A conjunção `[CORRELATION, p = 8,6×10⁻⁶]`

Cruzando os dois eixos que revisões independentes já haviam estabelecido — o
ambiente (R5.5) e o perfil com a origem controlada (R8/R9):

```
com AS DUAS condicoes (conteiner E nao-macOS) : 7/7  bloquearam
sem uma delas                                  : 0/14
Fisher exato, n=21                             : p = 8,6 x 10^-6
```

**Nenhuma das duas condições basta sozinha.** Ambiente degradado sozinho: 22
ações de macOS sem um bloqueio. Perfil não-macOS sozinho: 3/3 passam com GPU
real. Juntas: 7/7 bloqueiam.

> **H-CONJ** — o bloqueio ocorre quando, e somente quando, coincidem
> **(a)** ambiente sem WebGL **e** **(b)** perfil declarado não-macOS.

**Relação com o modelo de soma (R8.7):** não o contradiz. Uma conjunção é a
forma empírica que uma soma com limiar assume quando dois termos contribuem,
cada um, com cerca de metade do necessário para cruzar. A conjunção é o que se
**observa**; a soma continua sendo um mecanismo **possível**, não verificado.

##### R12.5 — Ressalva epistemológica, e ela é decisiva `[HYPOTHESIS — pós-hoc]`

A H-CONJ foi construída **olhando** as 21 sessões. O `p` diz que o arranjo é
improvável sob a hipótese nula; **não** diz que a regra prevê bem fora da
amostra. É a mesma armadilha que matou a HR4 (§9.3-R7.2): encaixar nos dados que
a geraram é o mínimo esperado de uma hipótese, não evidência a favor dela.

O que a salva **parcialmente**: os dois eixos não foram pescados no corpus. O
ambiente veio da R5.5 e o perfil da R8/R9 — cada um estabelecido antes, por
experimento próprio e independente. A **conjunção** é nova; os **fatores** não.

Ainda assim, a H-CONJ só sobe de status quando acertar uma predição ainda não
feita. Ela faz duas, ambas falsificáveis:

| predição                                   | estado        |
| ------------------------------------------ | ------------- |
| toda sessão contêiner + não-macOS bloqueia | 7/7 até aqui  |
| toda sessão com só uma das condições passa | 0/14 até aqui |

A próxima sessão de qualquer dos dois tipos confirma ou quebra. Enquanto isso,
**`HYPOTHESIS`, não achado.**

##### R12.6 — O que continua fora de alcance

"Ambiente degradado" é operacionalizado como _renderer ausente_, que é proxy do
**pacote inteiro** do contêiner — sem GPU, host Linux, `cores`, contêinerização.
A H-CONJ não isola qual componente do pacote participa, e o §9.3-R9.6 registra
por que isolar os 18 campos do perfil esbarra no desenho.

Nenhuma sessão foi executada para esta revisão.

---

#### 9.3-R13 — Experimento (2026-09-08): a antecedente da H-CONJ está ERRADA — não é o WebGL

> Pré-inscrição em `exp_webgl.py`, escrita antes da execução. Uma sessão real,
> local (Windows real, GPU real, IP residencial), fora do contêiner. É o
> primeiro teste do estudo que **falsificou** a hipótese que o motivou.

---

##### R13.1 — Por que este teste, e não outro

A §9.3-R12.4 propôs a **H-CONJ**: _bloqueia ⟺ (ambiente sem WebGL) ∧ (perfil
não-macOS)_, com 7/7 × 0/14 e Fisher p = 8,6×10⁻⁶.

O problema: **"sem WebGL" era um proxy.** Nas 7 sessões que bloquearam, o que
estava presente era o **pacote inteiro** do contêiner — sem GPU, host Linux,
`cores`, conteinerização. As duas coisas nunca haviam sido separadas
(§9.3-R12.6).

E as quatro células do corpus já estavam ocupadas: uma sessão "contêiner +
não-macOS" só poderia **confirmar** o que já era 7/7. Para testar uma hipótese
pós-hoc é preciso criar uma célula onde ela possa **falhar**.

```
                        não-macOS      macOS
contêiner                7 bloqueiam   8 passam
GPU real                 3 passam      3 passam
GPU real, WebGL off       ← VAZIA
```

##### R13.2 — O desenho e o resultado `[FACT]`

Partir da linha que passa 3/3 — Windows real, GPU real, IP residencial, perfil
`windows`, sem contêiner — e mudar **uma** coisa: desligar o WebGL.

```
renderer  = None             OK — block_webgl pegou
platform  = Win32            OK — perfil aplicado
public_ip = <IP-RESIDENCIAL>   OK — residencial
desfecho  = ACCEPTED
```

A sessão **passou**. Entrada e postback do CNPJ completaram normalmente
(`postback=200`, 3 rotações de cookie).

_Mecanismo do desligamento, verificado:_ `block_webgl=True` remove as chaves
`webGl:*` e `webGl2:*` da config e liga o pref **nativo** do Firefox
`webgl.disabled`. Não há override de API nativa — o confundidor de `isNative`
que o `browser.py` proíbe não foi introduzido. O Camoufox emite
`LeakWarning: Disabling WebGL is not recommended. Many WAFs will check if WebGL
is enabled` — que é precisamente o que o experimento testa.

##### R13.3 — A H-CONJ cai na antecedente `[REFUTED]`

Predição registrada antes: se a antecedente estivesse correta, a sessão
bloquearia. **Não bloqueou.**

> **Ausência de WebGL não basta** para produzir bloqueio, mesmo com perfil
> `windows`, que é a metade "culpada" da conjunção.

A H-CONJ precisa ser reescrita:

> **H-CONJ′** — o bloqueio ocorre quando coincidem **(a)** o _ambiente de
> contêiner_ e **(b)** perfil declarado não-macOS.
>
> `HYPOTHESIS`. A conjunção segue suportada por 7/7 × 0/15 (com esta sessão), mas
> a antecedente volta a ser um **pacote não decomposto** — o que a R13.4 começa
> a decompor.

Registrar a falsificação importa tanto quanto registrar a confirmação. A H-CONJ
tinha p = 8,6×10⁻⁶ e mesmo assim sua leitura mecanicista estava errada: o `p`
media a improbabilidade do arranjo sob H0, nunca a validade da explicação.

##### R13.4 — O que sobra do pacote, agora que o WebGL saiu `[OBSERVATION]`

Diff dos fingerprints de duas sessões **do mesmo perfil `windows`** — uma local
com GPU real que passou, uma em contêiner que bloqueou:

| campo                           | local (passou) | contêiner (bloqueou) | estado                                     |
| ------------------------------- | -------------- | -------------------- | ------------------------------------------ |
| `webgl.*` (10 campos)           | presentes      | ausentes             | **ELIMINADO** — R13.2                      |
| `audio.hash`                    | `230db48a`     | **`err`**            | **candidato**                              |
| `canvas.hash`                   | `fffa0162`     | `da386ebe`           | derivado do render                         |
| `navigator.hardwareConcurrency` | 2              | 32                   | eliminado — 8 e 16 nos dois desfechos      |
| `screen.*` (11 campos)          | 3440×1440      | 1600×900             | eliminado — varia dentro do desfecho (R12) |

Depois de riscar o WebGL, **`audio.hash = err` é o único sinal observável no
fingerprint que ainda distingue os dois ambientes e não foi eliminado.**

É estruturalmente paralelo ao WebGL: o contêiner não tem dispositivo de áudio, o
`OfflineAudioContext` falha, e o cliente entrega `err` onde um desktop real
entrega um hash. Dois "sinais de capacidade degradada" no mesmo pacote — testamos
um, sobrou o outro.

**Não observável no fingerprint**, e portanto fora deste diff: host/kernel
(WSL2 e Fargate são Linux; o local é Windows) e a conteinerização em si.

##### R13.5 — Defeito de instrumento, corrigir antes da próxima

`exp_webgl.py` capturou o fingerprint por `page.evaluate(FULL_FP_JS)` mas **não
chamou `fx.record_fingerprint()`** — a timeline forense da sessão ficou sem o
`full`, e o diff previsto contra ela veio todo `None`. Contornei usando o corpus
histórico (`exp_1788353297`), que tem o fingerprint completo, mas a comparação
direta com **esta** sessão ficou impossível.

Qualquer experimento novo que capture fingerprint precisa gravá-lo na timeline,
senão a sessão não entra em nenhum diff futuro.

##### R13.6 — O próximo teste que este resultado desenha

Exatamente o mesmo desenho, trocando a capacidade desligada:

> Windows real, GPU real, IP residencial, perfil `windows`, **com o Web Audio
> desligado** (`firefox_user_prefs={"dom.webaudio.enabled": False}` — pref
> nativo do Firefox, mesmo mecanismo limpo do `webgl.disabled`; o Camoufox não
> expõe um `block_audio`, mas aceita `firefox_user_prefs`).

| resultado    | consequência                                                                                                                                               |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **BLOQUEIA** | `audio` é o ingrediente ativo do pacote — um mecanismo específico, não um proxy                                                                            |
| **PASSA**    | nem WebGL nem áudio isolados bastam; o que resta é host/conteinerização, **não observável pelo fingerprint** — e a decomposição por esse caminho se esgota |

Os dois desfechos fecham uma porta. E o segundo seria, ele mesmo, um resultado:
diria que a explicação não está em nenhuma capacidade JS degradada, e sim em
algo que o cliente não consegue ver de dentro.

Não executado. Fica como proposta.

---

#### 9.3-R14 — Experimento (2026-09-08): o áudio também não basta — e o espaço observável se fecha em uma única hipótese

> Pré-inscrição em `exp_audio.py`. Uma sessão real, local (Windows real, GPU
> real, IP residencial). Mesmo desenho do §9.3-R13, trocando a capacidade
> desligada. Corrige o defeito de instrumento do §9.3-R13.5.

---

##### R14.1 — O desenho

O §9.3-R13 riscou o WebGL. O diff de fingerprint deixou **`audio.hash = err`**
como único candidato observável de pé: o contêiner não tem dispositivo de áudio,
o `OfflineAudioContext` falha, e um desktop real entrega um hash.

Mesmo desenho, capacidade trocada: partir da linha que passa 3/3 e desligar
**só o Web Audio**, mantendo o WebGL.

_Viabilidade verificada offline **antes** de gastar a sessão:_

```
sem pref -> OfflineAudioContext = True   webgl = ANGLE (NVIDIA ...)
com pref -> OfflineAudioContext = False  webgl = ANGLE (Intel ...)
```

`dom.webaudio.enabled` é pref **nativo** do Firefox — sem override de API, sem o
confundidor de `isNative`. O Camoufox não expõe `block_audio`, mas aceita
`firefox_user_prefs`.

##### R14.2 — Resultado `[FACT]`

```
audio     = None                  OK — pref pegou
renderer  = ANGLE (Intel, ...)    OK — WebGL PRESERVADO (contraste com R13)
platform  = Win32                 OK
public_ip = <IP-RESIDENCIAL>        OK — residencial
desfecho  = ACCEPTED
```

Passou. Entrada e postback do CNPJ completaram (`postback=200`, 3 rotações).

##### R14.3 — Nem WebGL, nem áudio `[REFUTED]`

| experimento | capacidade desligada | desfecho |
| ----------- | -------------------- | -------- |
| §9.3-R13    | WebGL (áudio ON)     | ACCEPTED |
| §9.3-R14    | áudio (WebGL ON)     | ACCEPTED |

> **Nenhuma capacidade JS degradada, isoladamente, produz o bloqueio** — mesmo
> com o perfil `windows`, que é a metade "culpada" da conjunção.

##### R14.4 — O que sobrou: uma única hipótese observável `[OBSERVATION]`

Com o defeito do R13.5 corrigido, esta sessão gravou o fingerprint e o diff
contra a sessão de contêiner que bloqueou saiu completo. Ambas perfil `windows`:

| campo                  | A: local, áudio off (passou) | B: contêiner (bloqueou) | estado                                     |
| ---------------------- | ---------------------------- | ----------------------- | ------------------------------------------ |
| `webgl.*` (10 campos)  | presentes                    | ausentes                | testado isolado → não basta (R13)          |
| `audio.hash`           | `None` (API desligada)       | `err` (API falha)       | testado isolado → não basta (R14)          |
| `canvas.hash`          | `da745874`                   | `da386ebe`              | derivado do render                         |
| `hardwareConcurrency`  | 12                           | 32                      | eliminado — 8 e 16 nos dois desfechos      |
| `screen.*` (11 campos) | —                            | —                       | eliminado — varia dentro do desfecho (R12) |

Depois de R13 e R14, **as duas capacidades degradadas são exatamente o que
resta** no fingerprint. Logo o espaço de hipóteses observáveis se reduz a uma:

> **H-CAP** — o bloqueio exige as **duas** capacidades degradadas
> simultaneamente (WebGL ausente **e** áudio sem fingerprint), não cada uma
> isolada.
>
> `HYPOTHESIS` — não testada. É a **última** hipótese que o fingerprint ainda
> permite formular.

Isso é compatível com o modelo de soma (§9.3-R8.7): dois termos que, sozinhos,
não cruzam o limiar, e juntos cruzam.

##### R14.5 — Limite declarado antes, e ele importa aqui

Desligar a API **não é idêntico** à API que falha. Em A o `OfflineAudioContext`
não existe; em B ele existe e a renderização retorna `err`. Ambos representam
"sem fingerprint de áudio", mas um detector pode distinguir "API ausente" de
"API que erra" — e as duas coisas podem pontuar diferente.

O mesmo vale para o WebGL no R13: `webgl.disabled` remove a API; no contêiner o
contexto existe e retorna `null` (`TypeError: can't access property "getExtension"`).

Isto **não invalida** R13 nem R14 — em ambos a capacidade ficou indisponível ao
engine, que é a condição sob teste. Mas significa que uma reprodução mais fiel
do contêiner exigiria fazer a API **falhar**, não sumir.

##### R14.6 — O próximo teste, e por que ele é o último desta via

Mesmo desenho, as duas capacidades desligadas juntas:

```
firefox_user_prefs = {"dom.webaudio.enabled": False}
block_webgl        = True
perfil             = windows,  GPU real,  IP residencial
```

| resultado    | consequência                                                                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **BLOQUEIA** | H-CAP `SUPPORTED`. O mecanismo é a **conjunção** de capacidades degradadas — um resultado específico, e o primeiro do estudo a identificar uma condição suficiente reproduzível fora do contêiner |
| **PASSA**    | o fingerprint **não contém** a explicação. O que resta — host/kernel, conteinerização — é invisível ao cliente por construção, e a decomposição por observação se encerra                         |

Os dois desfechos fecham a via. É o último passo barato disponível: depois dele,
avançar exigiria observar algo que o cliente não consegue ver de dentro.

Não executado. Experimento novo, com pré-inscrição própria — a regra de
ramificação do `exp_audio.py` proíbe rodá-lo na sequência desta sessão.

---

#### 9.3-R15 — Experimento (2026-09-08): nem juntas — a decomposição pelo nosso fingerprint se encerra

> Pré-inscrição em `exp_ambas.py`. Uma sessão real, local. Fecha a trinca
> R13/R14/R15 e encerra a via de decomposição por observação do fingerprint.

---

##### R15.1 — O desenho mais controlado do estudo

Três níveis de controle já rodados, cada um com **uma** variável de diferença:

| controle                     | capacidades desligadas | desfecho |
| ---------------------------- | ---------------------- | -------- |
| 3 sessões locais (corpus R5) | nenhuma                | ACCEPTED |
| §9.3-R13                     | WebGL                  | ACCEPTED |
| §9.3-R14                     | áudio                  | ACCEPTED |
| **§9.3-R15 (este)**          | **WebGL + áudio**      | **?**    |

Todos com perfil `windows`, GPU real, IP residencial, fora do contêiner.

##### R15.2 — Resultado `[FACT]`

```
renderer  = None             OK — block_webgl pegou
audio     = None             OK — dom.webaudio.enabled=false pegou
platform  = Win32            OK
public_ip = <IP-RESIDENCIAL>   OK — residencial
desfecho  = ACCEPTED
```

Passou. Entrada e postback completaram (`postback=200`, 3 rotações).

##### R15.3 — H-CAP `REFUTED`

| experimento | WebGL   | áudio   | desfecho          |
| ----------- | ------- | ------- | ----------------- |
| R13         | **off** | on      | ACCEPTED          |
| R14         | on      | **off** | ACCEPTED          |
| R15         | **off** | **off** | ACCEPTED          |
| contêiner   | ausente | `err`   | **BLOCKED** (7/7) |

> Nem isoladas, nem em conjunto. A H-CAP, que era a **última** hipótese que o
> nosso fingerprint permitia formular, está refutada.

##### R15.4 — O que isso encerra — e o escopo exato da afirmação

A decomposição do "pacote contêiner" **pelos campos que o nosso probe mede**
está esgotada:

| campo                              | estado                                                 |
| ---------------------------------- | ------------------------------------------------------ |
| `webgl.*`                          | testado isolado e em conjunto → não explica (R13, R15) |
| `audio.hash`                       | testado isolado e em conjunto → não explica (R14, R15) |
| `hardwareConcurrency`              | eliminado — 8 e 16 nos dois desfechos                  |
| `screen.*` (11 campos)             | eliminado — varia dentro do desfecho (R12)             |
| `canvas.hash`                      | derivado do render, não manipulável isoladamente       |
| identidade (`platform`/`oscpu`/UA) | não variável sem recriar incoerência (R9.6)            |

**Escopo — e a distinção importa.** O correto é _"a explicação não está nos ~40
campos que o `FULL_FP_JS` captura"_, **não** _"a explicação não é observável"_.
São coisas diferentes. O `type=11` do F5 coleta bem mais do que o nosso probe: o
§7 documenta a renderização da textura ISO 12233 com `readPixels`, o
`UNMASKED_RENDERER_WEBGL` e ~30 verificações de `isNative`. Nosso probe cobre
parte disso, não tudo.

Sobram, portanto, três possibilidades — e só a primeira é atacável sem sessões:

1. **campos que o F5 lê e nós não medimos** — atacável offline (R15.6);
2. **host/kernel/conteinerização** — não visível em JS por construção;
3. **"API ausente" ≠ "API presente que falha"** — a limitação do §9.3-R14.5.

##### R15.5 — A possibilidade 3 é a fresta que fica aberta

No contêiner o contexto WebGL **existe** e a chamada falha
(`TypeError: can't access property "getExtension", gl is null`); o
`OfflineAudioContext` **existe** e a renderização retorna `err`. Nas nossas três
sessões as APIs **sumiram**.

Ambos deixam a capacidade indisponível ao engine — a condição sob teste — mas um
detector pode pontuar "ausente" de forma diferente de "presente e falhando". Uma
reprodução fiel exigiria fazer a API **falhar**, não desaparecer, e não achamos
uma forma limpa de produzir isso num host com GPU real.

Registrar isto impede que R13–R15 sejam lidos como mais fortes do que são.

##### R15.6 — O próximo passo, e ele não custa sessão nenhuma

O §7 já documenta o que o `type=11` lê. Nosso `FULL_FP_JS` não replica tudo —
em particular a **renderização de shaders + `readPixels` da textura ISO 12233**,
que é justamente o que um ambiente sem GPU degradaria de forma peculiar.

> **Estender o probe para cobrir o que o `type=11` de fato coleta, rodá-lo
> localmente e no contêiner, e diffar.** Sem tocar o CADESP.

Isso responde à possibilidade 1 do R15.4 com **zero sessões** contra o alvo: se
aparecer um campo que difere e que ainda não foi testado, a decomposição
recomeça com um candidato novo. Se não aparecer nada além do que já sabemos, a
possibilidade 1 cai e sobram apenas host/conteinerização — invisíveis por
construção.

É o passo de melhor custo/benefício disponível e deveria vir antes de qualquer
sessão nova.

##### R15.7 — Nota anti-busca

O desfecho `ACCEPTED` aqui é um **resultado**, não um convite para desligar mais
uma capacidade até bloquear. A regra estava escrita na pré-inscrição
(`exp_ambas.py`, REGRA ANTI-BUSCA) antes de a sessão rodar. Prosseguir por
tentativa-e-erro até obter bloqueio transformaria o experimento em busca de
configuração — exatamente o que os §8 e §46 do briefing proíbem.

---

#### 9.3-R16 — Observação (2026-09-08): o bloqueio tem janela de recuperação — e duas leituras minhas foram erradas em sequência

> Revisão **observacional**, não experimental. Nenhuma sessão automatizada foi
> executada. Registra um fenômeno nunca visto — a recuperação — e documenta dois
> erros de inferência meus, porque o modo como errei é reutilizável.

---

##### R16.1 — A sequência observada `[FACT]`

Depois de uma manhã de carga concentrada (as sessões §9.3-R8/R11/R13/R14/R15 e
seis sessões manuais do `teste.py` entre 07:41 e 07:49), o alvo passou a recusar
acesso **de forma ampla**:

```
1. navegador NORMAL do operador (sem automação)  -> bloqueado
2. celular na mesma rede wi-fi                    -> bloqueado
3. aba anônima na mesma máquina                   -> FUNCIONOU
4. (minutos depois) navegador normal              -> voltou a funcionar sozinho
```

O passo 4 é o decisivo: **recuperou sem limpar cookies, sem trocar de rede,
sem qualquer intervenção.**

##### R16.2 — O achado: existe janela de recuperação `[FACT]`

O bloqueio expirou por conta própria, em ordem de dezenas de minutos.

Isso **nunca havia sido observado**, e a razão é de instrumento: o
`freeze_on_block=True` encerra a sessão no primeiro bloqueio, e nas sessões
manuais o operador fechava o navegador. O estudo media o bloqueio e nunca o via
terminar.

Reconcilia uma tensão antiga: o §9.3 chamava o fenômeno de **transiente**; o
§9.3-R1 revisou para **persistente** ao ver bloqueios que não recuperavam dentro
da sessão. As duas leituras estavam parcialmente certas — é transiente, com
janela mais longa do que a duração de uma sessão, que foi o que a R1 conseguiu
observar.

##### R16.3 — O que NÃO ficou estabelecido `[UNKNOWN]`

A aba anônima ter funcionado **não** prova que o estado do cliente carrega o
bloqueio. Os dois testes — navegador normal e aba anônima — **não foram
simultâneos**. A aba anônima pode ter funcionado porque a janela já havia
fechado, não porque estava com estado limpo.

Enquanto os dois não forem testados lado a lado na mesma janela de segundos,
"estado do cliente" e "tempo decorrido" permanecem indistinguíveis.

Também fica refutada a leitura de **origem contaminada**: a recuperação foi
rápida demais e não exigiu troca de rede. O IP residencial não foi queimado.

##### R16.4 — Dois erros meus, em sequência — e o padrão comum

Registrar isto é parte do método (§46), porque o **modo** de errar se repete:

| momento                               | minha leitura                                   | o que a derrubou                            |
| ------------------------------------- | ----------------------------------------------- | ------------------------------------------- |
| navegador normal + celular bloqueados | "o IP residencial foi contaminado"              | recuperação rápida sem trocar de rede       |
| aba anônima funcionou                 | "o bloqueio é carregado pelo estado do cliente" | o normal recuperou sozinho, sem limpar nada |

**O padrão comum:** nas duas vezes eu concluí a partir de observações **não
simultâneas**, tratando uma diferença temporal como se o tempo estivesse
controlado. É exatamente o que o §26 do briefing proíbe — transformar
correlação temporal em atribuição — e eu o fiz duas vezes seguidas, com
confiança, em menos de meia hora.

Vale registrar também um erro de avaliação de risco anterior: quando perguntado
se gerar bloqueios danificaria a origem, respondi que a evidência dizia que não,
citando R8 (bloqueou) → R9 (passou 12 min depois). A resposta estava correta
para os dados de então e **subestimou o acúmulo**: naquela manhã produzimos mais
bloqueios do que em toda a semana anterior — só a primeira execução do
`exp_reuso` gerou 4 support IDs — e o efeito agregado foi um bloqueio amplo,
ainda que reversível.

##### R16.5 — O teste limpo, para a próxima ocorrência

Custa zero e resolve a ambiguidade da R16.3:

> No momento do bloqueio, recarregar **navegador normal e aba anônima lado a
> lado**, na mesma janela de segundos.

| resultado                 | leitura                                                  |
| ------------------------- | -------------------------------------------------------- |
| anônima passa, normal não | o **estado do cliente** carrega o bloqueio               |
| ambas bloqueiam           | é **temporal/origem**; o estado do cliente não participa |
| ambas passam              | a janela já fechou — repetir                             |

Registrar o horário de cada leitura é obrigatório: sem ele, o teste não vale.

##### R16.6 — Consequências

1. **A origem não foi perdida** — o estudo mantém sua linha de base residencial.
2. **O ritmo importa.** A carga concentrada produziu um efeito observável mesmo
   sendo reversível. Qualquer plano futuro deve espaçar sessões, e o teto de
   ações pós-bloqueio proposto (5) continua valendo.
3. **Uma variável nova, e controlável.** A janela de recuperação é mensurável:
   bloquear, esperar, medir quando volta. É a primeira grandeza contínua que o
   estudo pode observar sem depender do desfecho binário — mas exige provocar
   bloqueios, e por isso não é proposta aqui, apenas registrada como
   possibilidade.
4. **As sessões R13/R14/R15 rodaram numa origem sob carga crescente.** Não
   invalida os vereditos (todas passaram, e passar sob carga é o desfecho
   conservador), mas era uma variável mudando sob os pés dos três experimentos,
   e nenhum a controlou.

---

#### 9.3-R17 — Descoberta (2026-09-08): o nosso hook truncava o pipeline — e o cookie de fingerprint É decifrável

> Revisão dupla: identifica um **efeito-observador** que contaminou todas as
> capturas manuais anteriores, e **refuta o §12.7.a** — a conclusão de que o
> fingerprint seria inalcançável offline vinha de uma ausência que nós mesmos
> provocávamos.

---

##### R17.1 — O hook de `document.cookie` truncava o pipeline `[FACT]`

O `teste.py` injetava um `Object.defineProperty(document, 'cookie', {set: …})`
para capturar os cookies no momento da escrita. Comparando sessões com e sem
essa injeção, pelo **mesmo caminho** (raiz → Bézier → entrada → CNPJ):

| hook          | sessões | `type=13/14/22`      | desfecho    |
| ------------- | ------- | -------------------- | ----------- |
| **ligado**    | 8       | **ausentes em 8/8**  | 6 bloqueios |
| **desligado** | 2       | **presentes em 2/2** | 0 bloqueios |

Com o hook, o pipeline parava um nível antes do fim: o `11` rodava sem produzir
`13/14`, o `17` rodava sem disparar `22`. O grafo do §9.1 ficava decapitado nos
dois nós-folha.

O mecanismo é o que o próprio estudo previa: o §7.2 documenta que o `type=11`
roda `isNative` sobre ~30 funções nativas para detectar sobrescrita, e o §9.6
mostra que o F5 grava seus cookies selados **exatamente por `document.cookie`**
(`z_.sZ`). Nosso instrumento sobrescrevia o caminho de escrita do alvo.

_Consequência para o §9.3-R10:_ aquela revisão — "o bloqueio acompanha o reuso
da sessão" — foi derivada **inteiramente** de sessões do `teste.py` com o hook
ligado. Fica sob suspeita de artefato e precisa ser refeita sem a injeção antes
de valer.

##### R17.2 — O cookie de fingerprint só existe se o pipeline concluir `[FACT]`

```
hook ON  : TS01ec2f54(202B) TS0eaa6361027(192B) TS6695b38b077(176B) TS6695b38b029(96B)
hook OFF : TS00000000076(528B)  TS6695b38b071(401B)  TSPD_101_DID(224B)  + os acima
```

O `TS00000000076` de ~528 B — o cookie grande da §8 — **nasce só quando a
captura completa**. Com o hook, ele nunca chegava a ser criado.

##### R17.3 — Decifrado `[FACT]`

Com a chave extraída **automaticamente** do `live_type11` do mesmo deploy
(`<chave-F5-D>`), quatro cookies abrem com padding F5
válido:

```
TS00000000076   528B -> 264B decifrados
TS6695b38b071   401B -> 200B decifrados
TSPD_101_DID    224B -> 112B decifrados
TS6695b38b077   176B ->  88B decifrados
```

A prova de que não é coincidência está no conteúdo do `TS6695b38b071`:

```
en-USPMozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0
```

O **User-Agent literal**, mais o locale `en-US` no `TSPD_101_DID`. Decifração
malsucedida produz ruído de alta entropia, não strings estruturadas.

O `TS00000000076` traz uma cadeia hexadecimal longa e repetida
(`<hash-fingerprint>`), compatível com hashes de fingerprint
concatenados — o conteúdo campo-a-campo ainda **não** foi desempacotado.

Não abrem com esta chave: `TSPD_101`, `TS0eaa6361027`, `TS6695b38b029`,
`TS01ec2f54` — consistente com o §12.7.a (server-sealed ou chave derivada por
frame).

##### R17.4 — O §12.7.a está REFUTADO na conclusão principal

Aquela seção concluiu:

> _"O cookie que plausivelmente carrega o fingerprint não decifra com nenhuma
> das duas chaves… O cookie grande (~528 B) não apareceu em nenhuma das
> capturas deste fluxo… a decifração alcança session-state, NÃO o fingerprint…
> o conteúdo decisivo fica atrás da chave do servidor, inalcançável offline."_

As duas premissas caem:

1. o cookie grande **não aparecia** porque o hook impedia sua criação — não
   porque fosse server-sealed;
2. ele **decifra** com a chave do script, e o conteúdo inclui identidade do
   cliente em texto claro.

_A lição de método é a mais cara desta revisão:_ concluímos "está fora de
alcance" a partir de uma **ausência**, sem verificar se a ausência era causada
pelo nosso próprio instrumento. Ausência de evidência foi tratada como evidência
de ausência, e o instrumento era a causa.

##### R17.5 — Um bug meu, no validador, que quase virou resultado falso

A primeira tentativa reportou 4 cookies "abertos" com plaintexts de alta
entropia e sem estrutura. O validador era:

```python
n = pt[-1]
return 0 <= n < 8 and all(b == 0xFF for b in pt[len(pt)-1-n:len(pt)-1])
```

Com `n == 0` o `all()` percorre uma fatia **vazia** e devolve `True` — logo
qualquer plaintext terminado em `0x00` passava por "padding válido". Exigindo
`n >= 1` os falsos positivos somem e os quatro verdadeiros permanecem, agora com
caudas coerentes (`…ffffffffffffff07`, `…ffffffff04`).

O que separou o falso do verdadeiro não foi a estatística — foi o **conteúdo**:
padding válido _mais_ string legível. `forensic/decifrar_jar.py` carrega o
comentário para o defeito não voltar.

##### R17.6 — O que isto abre

Passa a ser possível **ler o que o cliente envia**, no deploy corrente:

1. desempacotar o `TS00000000076` campo a campo — responde o §13.4-Q3 ("os 18
   campos estão num blob único ou espalhados?");
2. **diffar o payload entre uma sessão que passa e uma que bloqueia**, do mesmo
   deploy — é o §13.4-Q2, e nunca foi possível antes;
3. verificar se os campos de SO viajam em claro ou derivados — o §13.4-Q4.

Restrição operacional: a chave **rotaciona por deploy**, então captura e script
precisam vir da mesma sessão. O `teste.py` já salva os dois, e o
`forensic/decifrar_jar.py` casa os dois automaticamente.

Nenhuma sessão nova foi executada para esta análise além da própria captura sem
hook.

---

#### 9.3-R18 — Revisão (2026-09-08): o payload é parseável, e o §9.3-R10 era artefato do nosso hook

> Duas partes. A primeira abre o conteúdo do que o cliente envia; a segunda
> retira uma revisão inteira do estudo, porque ela media o nosso instrumento e
> não o alvo.

---

##### R18.1 — O payload usa campos com prefixo de tamanho `[FACT]`

O §9.3-R17 mostrou que os cookies decifram. O conteúdo não é um blob opaco: é
uma sequência de campos `len(1 byte) + valor`. Duas correspondências exatas
estabelecem o formato sem margem para dúvida:

```
\x05 en-US                                   -> 0x05 = 5, e "en-US" tem 5 chars
\x50 Mozilla/5.0 (Windows NT 10.0; ...)      -> 0x50 = 80, e o UA tem 80 chars
```

Layout do `TS6695b38b071` (200 B decifrados), lido por `forensic/payload.py`:

```
[000-071]  72B  cabecalho de layout fixo, significado NAO estabelecido
                (os primeiros 32B sao identicos entre cookies da mesma sessao)
[072-191]  regiao TLV, 19 campos — 16 vazios e 3 com conteudo:
             #11  len=5   'en-US'
             #12  len=80  'Mozilla/5.0 (Windows NT 10.0; ... Firefox/152.0'
             #13  len=16  ffbfdcfffbf6fdfbfebef7ffffffffff
[192-199]  ff x7 + 07     padding F5 (§12.7)
```

O campo `#13` — 16 bytes com bits altos predominando — **parece** um bitmask, e
o §6 documenta que o `type=17` usa bitmasks (`oZ_`, `OO_`). É semelhança, não
identificação: fica como fio a puxar, não como achado.

##### R18.2 — Limite honesto: o cookie grande NÃO está validado `[UNKNOWN]`

O parse do `TS6695b38b071` é confiável porque está **ancorado** em duas
coincidências exatas de comprimento. O do `TS00000000076` (264 B) **não está**:
produz dois campos de texto que são pedaços de uma cadeia hexadecimal repetida,
cortados em pontos sem justificativa independente.

Com **uma** amostra por cookie não é possível validar heurística nenhuma —
qualquer regra ajustada cabe no único caso disponível. Registrar o parse do
cookie grande como resultado seria o mesmo erro da H-CONJ (§9.3-R12.5): ajustar
aos dados que geraram a hipótese e chamar de confirmação.

O que resolve: **mais amostras**. Cada sessão produz uma; campos que variam
entre sessões, contra os que permanecem fixos, revelam as fronteiras reais.

##### R18.3 — Três defeitos do parser, achados por teste e não por sorte

Vale registrar porque os dois primeiros só apareceram com payload sintético — a
análise sobre os dados reais teria passado por eles:

1. a detecção aceitava o **primeiro** offset cuja caminhada fechasse, e engolia
   72 B de cabeçalho como se fossem um campo (offset 4 em vez de 72);
2. `melhor_p = -1` como piso inicial **descartava todo parse com score
   negativo**, devolvendo "sem estrutura" para payloads válidos;
3. a penalidade "campo maior que metade do corpo" disparava em payload pequeno,
   onde um campo legítimo naturalmente domina, e rejeitava o parse correto.

`tests/test_payload.py` cobre os três, mais o caso do padding `n == 0` do
§9.3-R17.5.

##### R18.4 — O §9.3-R10 media o nosso hook `[REFUTADO]`

O §9.3-R10 concluiu que **o bloqueio acompanha o reuso da sessão**: a 1ª
consulta passa, a 2ª ação bloqueia; com instância nova a cada pesquisa, passa
3/3. Foi derivado **inteiramente** de sessões do `teste.py` com o hook de
`document.cookie` ligado.

Com o hook desligado, mesmo caminho e mesmo operador:

| hook          | sessões | pipeline servido                               | ciclos `17/22` | bloqueios |
| ------------- | ------- | ---------------------------------------------- | -------------- | --------- |
| **ligado**    | 2       | `11,12,17,18,20` **×2–3 cada**, sem `13/14/22` | —              | **2**     |
| **desligado** | 4       | `11,12,13,14,18,20` **×1**, completo           | 4, 4, 4, **7** | **0**     |

A sessão de 7 pares incluiu **voltar e pesquisar de novo** — exatamente a ação
que o §9.3-R10 identificou como gatilho. Não bloqueou.

**O que o R10 mediu:** com o hook, as contagens de todos os types são _iguais
entre si_ dentro da sessão (2,2,2,2,2 / 3,3,3,3,3) — o F5 **re-servia o pipeline
inteiro** a cada carga, porque a coleta nunca concluía. Cada nova ação
recarregava, o `type=11` rodava de novo, o `isNative` (§7.2) detectava a
sobrescrita de novo, e o bloqueio vinha na 2ª ou 3ª repetição. A "curva de
reuso" era a nossa injeção sendo detectada repetidamente.

Sem o hook, o pipeline roda **uma vez** e fecha com o `14`; só o par
comportamental `17/22` se repete por ação — e a repetição, sozinha, não bloqueia.

_O §9.3-R3.4 ("`17` e `22` sempre em par") sai reforçado: 4/4, 4/4, 4/4, 7/7._

##### R18.5 — O que sobrevive do que o R10 gerou

O §9.3-R11 nasceu da motivação do R10 ("existe um eixo de reuso") mas rodou no
fluxo **automatizado** (`t.py`, sem hook algum). Seus números permanecem
válidos: `windows` bloqueia na ação 2, `macos` sobrevive a 8. O que cai é a
_interpretação_ de que aquilo media um acumulador de reuso — com o R18.4, a
leitura mais simples é que o `windows` em contêiner bloqueia no primeiro
postback avaliado, e não que exista uma contagem se acumulando.

O §9.3-R11.6 (o `hi32` assume ≥2 valores) é independente do hook e continua de pé.

##### R18.6 — Nota de método

Duas revisões consecutivas — R17 e R18 — foram correções de **efeito
observador**. Em ambas, a conclusão anterior descrevia o comportamento do nosso
instrumento e era atribuída ao alvo:

- §12.7.a: "o fingerprint é inalcançável" ← o hook impedia o cookie de existir;
- §9.3-R10: "o bloqueio acompanha o reuso" ← o hook era redetectado a cada carga.

O padrão comum é o mesmo do §9.3-R16.4: concluir a partir de uma **ausência** ou
de uma **repetição** sem verificar se o instrumento a produzia. Toda ferramenta
de captura que **modifica** a página precisa de um braço de controle sem a
modificação — e o `teste.py` só ganhou o seu (`--sem-hook`) depois de oito
sessões contaminadas.

##### R18.7 — EMENDA (2026-09-08, mesma tarde): o R18.4 exagerou, e o gatilho é mais específico

Uma sessão posterior, **sem hook e com pipeline completo**, bloqueou:

```
capture_s2_b_08-56   hook=OFF   Win32   BLOQUEIO 08:55:41
types: {11:1, 12:1, 13:1, 14:1, 17:5, 18:1, 20:1, 22:5}
ultima resposta /TSPD/: 08:55:35  ->  bloqueio: 08:55:41
```

O §9.3-R18.4 declarou o §9.3-R10 `REFUTADO` com base em 4 sessões sem bloqueio.
**Foi forte demais.** Bloqueio sem hook existe.

O que os dados sustentam agora é mais preciso do que o R10 _e_ do que a minha
correção:

| sessão | perfil    | pares `17/22` | reload  | desfecho     |
| ------ | --------- | ------------- | ------- | ------------ |
| 08:47  | MacIntel  | 7             | não     | passou       |
| 08:54  | **Win32** | **7**         | não     | passou       |
| 08:56  | **Win32** | **5**         | **sim** | **BLOQUEOU** |

**Não é contagem de ações:** 7 ciclos passaram, 5 bloquearam. E o par 08:54 ×
08:56 mantém o perfil constante (`Win32`), deixando o **reload** como a
diferença.

**Refinamento adicional, pela ausência de tráfego:** se o reload tivesse
recarregado normalmente, o pipeline seria re-servido (`11×2`, como nas sessões
com hook). As contagens mostram `11×1` — nenhum pipeline novo —, e o bloqueio
veio 6 s após a última resposta do F5, sem `/TSPD/` no intervalo. A leitura é
que **a própria requisição do reload foi recusada**, na porta.

**Estado corrigido:**

| afirmação                                                           | status                                         |
| ------------------------------------------------------------------- | ---------------------------------------------- |
| o hook inflava o efeito (bloqueio em 2–3 cargas, pipeline truncado) | `FACT` (R18.4)                                 |
| repetir **consultas** na mesma sessão bloqueia                      | `REFUTADO` — 7 ciclos × 2 sessões, 0 bloqueios |
| o **reload** é o gatilho                                            | `HYPOTHESIS` — n=1                             |

**Nota sobre o autor.** É a terceira oscilação minha numa conclusão com n
pequeno: §9.3-R16 (IP → estado do cliente → tempo) e agora R18.4 (reuso → não
bloqueia → reload). Em todas concluí cedo, com uma ou poucas observações, e
corrigi na observação seguinte. O padrão não é do alvo — é meu, e a mitigação é
declarar `n` junto de toda conclusão e não escrever `REFUTADO` sobre 4 sessões
sem evento.

**Experimento que sai disto:** manter perfil e caminho constantes, variar só a
ação final — uma consulta seguida de **reload** (tratamento) contra uma consulta
seguida de **nova consulta pela página** (controle, já com 2 sessões passando).
Uma repetição do braço de tratamento tira o n=1.

---

#### 9.3-R19 — Experimento (2026-09-08): a tela não explica, e o desfecho local NÃO é determinístico

> Pré-inscrição em `exp_tela.py`. Três braços automatizados, perfil `Win32`
> fixo, tela controlada. O resultado refuta a hipótese que o motivou — e expõe
> algo estrutural que enfraquece vários experimentos anteriores, inclusive os
> meus.

---

##### R19.1 — A geometria de tela está refutada `[REFUTED]`

Motivação: duas sessões `Win32` sem hook saíram idênticas em 16 campos
capturados e divergiram no desfecho; a **tela** era o único campo diferente
(`5120×1440` bloqueou, `2560×1440` passou).

Desenho: três braços, tela fixada e **verificada in-band** (a reportada pelo
navegador bateu com a pedida nos três).

```
A  5120x1440 (ultrawide, 3.56)  -> passou   (6 acoes)
B  2560x1440 (comum, 1.78)      -> passou   (6 acoes)
C  2560x1440 (identico ao B)    -> passou   (6 acoes)
```

O contra-exemplo é direto e não depende de interpretação:

```
5120x1440   BLOQUEOU   (sessao de 08:56)
5120x1440   passou     (braco A)
```

**A mesma geometria produziu os dois desfechos.** `REFUTED`.

##### R19.2 — Quatro candidatos, quatro refutações — o padrão é o achado `[FACT]`

Em uma única jornada, quatro hipóteses foram levantadas a partir de **n=1** e
todas caíram no teste seguinte:

| candidato             | origem                                | como caiu                                     |
| --------------------- | ------------------------------------- | --------------------------------------------- |
| origem/IP contaminado | navegador normal + celular bloqueados | recuperou sozinho, sem trocar de rede (R16.3) |
| estado do cliente     | aba anônima funcionou                 | o normal recuperou sem limpar nada (R16.3)    |
| reload como gatilho   | 1 sessão bloqueou após reload         | reload seguinte não bloqueou (R18.7)          |
| geometria de tela     | 1 sessão ultrawide bloqueou           | a mesma tela passou (R19.1)                   |

Quatro de quatro. Isso deixou de ser azar e passou a ser **informação sobre a
estrutura do problema**.

##### R19.3 — O desfecho local não é função do que observamos `[FACT]`

Todas as sessões locais, perfil `Win32`, sem hook, mesmo caminho:

| tela          | ações | desfecho     |
| ------------- | ----- | ------------ |
| 3072×1728     | 4     | passou       |
| 3072×1728     | 7     | passou       |
| **5120×1440** | **5** | **BLOQUEOU** |
| 2560×1440     | 5     | passou       |
| 5120×1440     | 6     | passou       |
| 2560×1440     | 6     | passou       |
| 2560×1440     | 6     | passou       |

**6 passaram, 1 bloqueou — taxa de ~14%** numa configuração nominalmente
idêntica, e **nenhuma variável capturada** distingue a que bloqueou. Os braços B
e C do experimento são a demonstração mínima: idênticos em toda variável
controlada, mesmo desfecho — mas o par 08:56 × 09:02 já havia mostrado o
contrário com a mesma igualdade.

A leitura: no ambiente local existe **estado oculto ou componente estocástico**.
Pode ser estado de servidor invisível ao cliente, pode ser temporal, pode ser
amostragem do próprio detector. O que se pode afirmar é o negativo: **não é
função determinística de nada que capturamos.**

##### R19.4 — A consequência mais cara: sessões únicas são de baixa potência

Se a taxa de bloqueio basal é ~14% numa configuração fixa, então **observar uma
única sessão passar quase não informa** sobre o efeito de uma manipulação —
86% das sessões passam de qualquer forma.

Isso enfraquece, retroativamente, os experimentos locais de n=1 desta jornada:

| experimento          | conclusão registrada          | força real                                   |
| -------------------- | ----------------------------- | -------------------------------------------- |
| §9.3-R13 (WebGL off) | "ausência de WebGL não basta" | 1 sessão passou; P(passar sem efeito) ≈ 0,86 |
| §9.3-R14 (áudio off) | "áudio não basta"             | idem                                         |
| §9.3-R15 (ambos off) | "H-CAP refutada"              | idem                                         |

As três conclusões **continuam plausíveis**, mas a evidência é bem mais fraca do
que o texto delas sugere. Um único "passou" contra uma base de 86% de passagem
não distingue "a manipulação não teve efeito" de "a manipulação teve efeito e
tivemos sorte".

_Não vale o mesmo para os experimentos em contêiner:_ ali `windows` bloqueou em
6/6 e `macos` passou em 8/8, com 22 ações sem um único bloqueio. Aquele ambiente
se comporta de forma determinística; o local, não.

##### R19.5 — O que isso corrige no método daqui para frente

1. **Toda afirmação sobre configuração local exige replicação.** Um n=1 que
   passa não sustenta "não tem efeito". Com base de 14%, seriam necessárias
   várias sessões para detectar uma mudança modesta.
2. **Parar de promover observação de n=1 a hipótese nomeada.** As quatro da
   R19.2 consumiram sessões e atenção; nenhuma sobreviveu. O filtro correto é:
   uma diferença observada em n=1 é _ruído até prova em contrário_, sobretudo
   quando encontrada olhando os dados depois do fato.
3. **O ambiente de contêiner é o instrumento mais confiável do estudo** —
   determinístico nos dois perfis, e foi onde os resultados sobreviveram
   (§9.3-R8, R9, R11).

##### R19.6 — O braço C não conseguiu testar determinismo

O braço C existia para responder "o desfecho é determinístico?" comparando dois
controles idênticos. Ambos passaram, então **concordaram** — o que é compatível
com determinismo e também com 86% de chance de passar cada um
(0,86² ≈ 0,74 de concordarem por acaso). O braço não discriminou.

Quem respondeu a pergunta foi o **agregado** da R19.3, com 7 sessões: é ali que
o 1 bloqueio sem explicação aparece. Um teste dedicado exigiria repetir a mesma
configuração ~10 vezes e medir a taxa — o que custa sessões contra um serviço
público e não é proposto aqui.

---

#### 9.3-R20 — Experimento (2026-09-08): o diff de payload entre bloqueio e passagem — §13.4-Q2 respondido

> Pré-inscrição em `exp_payload.py`. Duas sessões **em contêiner** — o ambiente
> determinístico (§9.3-R19) — capturando o jar de cookies e as chaves do deploy.
> Primeira vez que o estudo compara **o que é efetivamente enviado** entre uma
> sessão que bloqueia e uma que passa.

---

##### R20.1 — O desenho funcionou, e o risco declarado não se materializou `[FACT]`

```
windows  -> BLOQUEOU na acao 2   pipeline COMPLETO {18,20,11,12,13,14,17x2,22x2}
macos    -> passou, 4 acoes      pipeline COMPLETO {18,20,11,12,13,14,17x5,22x5}
```

O risco registrado antes era que a sessão `windows` bloqueasse **antes** de
gravar o cookie de fingerprint, deixando nada para comparar. Não aconteceu: o
`TS00000000076` de 528 B está presente nos dois braços. O snapshot do jar
tirado logo após o pipeline — antes de qualquer postback — foi o que garantiu
isso.

**As duas sessões usaram a MESMA chave** (`<chave-F5-F>`),
extraída de cada uma independentemente. Mesmo deploy, comparação limpa — a
condição que o §12.7 exige.

##### R20.2 — O que difere no payload legível: **apenas o User-Agent** `[FACT]`

`TS6695b38b071` (401 B → 200 B decifrados), três campos não-vazios:

| campo | windows (bloqueou)                             | macos (passou)                                     |            |
| ----- | ---------------------------------------------- | -------------------------------------------------- | ---------- |
| #0    | —                                              | —                                                  | **IGUAL**  |
| #1    | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; …)` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; …)` | **DIFERE** |
| #2    | 16 B binários                                  | 16 B binários                                      | **IGUAL**  |

`TSPD_101_DID` (224 B → 112 B): campo único, **IGUAL** nos dois.

Ou seja: entre uma sessão que bloqueou e uma que passou, o único campo legível
que difere é **exatamente a variável que manipulamos**. Nenhum sinal extra
discriminante aparece nos campos legíveis.

##### R20.3 — A identidade de SO viaja em CLARO — §13.4-Q4 respondido `[FACT]`

A pergunta §13.4-Q4 era se os campos de SO chegam ao servidor **em claro ou
derivados**. A resposta é direta: o User-Agent está no payload como texto ASCII
literal, sem hash nem transformação.

O servidor não precisa inferir o SO declarado — ele o recebe verbatim.

##### R20.4 — Uma especulação minha, morta antes de virar hipótese `[REFUTED]`

O §9.3-R18.1 registrou que o campo #2 (16 B com bits altos predominando,
`ffbfdcfffbf6fdfbfebef7ffffffffff`) **parecia** um bitmask, e que o §6 documenta
bitmasks de detecção no `type=17`. Deixei explícito que era semelhança, não
identificação.

O diff mata a leitura: o campo é **byte-idêntico** entre a sessão que bloqueou e
a que passou. Se fosse veredito ou máscara de detecção, seria o primeiro lugar
onde a diferença apareceria. Não é campo de decisão.

##### R20.5 — O cookie grande difere, mas isso não isola nada `[OBSERVATION]`

`TS00000000076` (264 B decifrados nos dois):

```
bytes iguais na mesma posicao : 45/264 (17%)
prefixo comum                 : 8 bytes
maior trecho ASCII comum      : 8 chars ('016aa017')
```

O conteúdo é uma cadeia hexadecimal em ASCII. No braço `windows` ela **repete
com período de 66 caracteres**; no `macos` não se achou período limpo.

A diferença é grande — mas **esperada e não informativa**: é o cookie de
fingerprint, e os dois perfis têm fingerprints inteiramente diferentes (tela,
`hardwareConcurrency`, fontes, canvas). Que ele difira não isola qual campo
pesa. E o parse dele continua **não validado** (§9.3-R18.2), então não se deve
ler significado nas fronteiras de campo que o parser propõe ali.

##### R20.6 — O que o §13.4-Q2 ganhou, e o que continua aberto

**Respondido:** _o que difere no que é efetivamente enviado?_ Nos campos
legíveis, **só a identidade de SO declarada** — que é o que mudamos. Não há
sinal adicional escondido no payload legível que acompanhe o desfecho.

**Continua aberto:** o `TS00000000076` e os 72 B de cabeçalho não estão
desempacotados. Se houver um discriminante ali, este experimento não o veria.
Para isolá-lo seria preciso variar **um** campo do fingerprint mantendo o resto
— e o §9.3-R9.6 já registra por que isso esbarra no instrumento (o Camoufox
avisa contra override por propriedade, e a incoerência resultante é ela mesma um
bloqueador).

**Leitura mais simples compatível com tudo:** o servidor recebe a identidade de
SO em claro e decide com base nela — no ambiente degradado do contêiner, e não
no local (§9.3-R5.5, §9.3-R19.3). Continua sendo `CORRELATION` com mecanismo
desconhecido: nada aqui mostra o servidor _usando_ o campo, só que ele o
**recebe**.

##### R20.7 — Nota de instrumento

`exp_payload.py` roda no contêiner e extrai as chaves de 16 B **dentro** dele,
do próprio script vivo, despejando apenas as chaves e o jar — em vez de
transportar 432 KB de JavaScript. Garante que captura e chave venham do mesmo
deploy sem custo de transporte.

Falha de operação a registrar: a primeira execução dos dois braços foi feita sem
redirecionar a saída, e o JSON ficou só no terminal. As sessões não se perderam
— o operador salvou o console em `logs/saida_terminal_container.log` — mas o
script deveria gravar em disco por conta própria quando roda localmente, já que
ali o filesystem não morre com o contêiner. Corrigir antes do próximo uso.

---

#### 9.3-R21 — Análise (2026-09-08): a estrutura do cookie de fingerprint, validada entre amostras

> Puramente offline, **zero sessões**. Usa os payloads que R17/R20 já
> produziram. Responde o §13.4-Q3 e fecha o limite que o §9.3-R18.2 registrou.

---

##### R21.1 — O método: invariância entre amostras, não heurística

O §9.3-R18.2 registrou que o parse do `TS00000000076` **não estava validado**:
com uma única amostra, qualquer regra ajustada cabe. A correção não é uma
heurística melhor — é mais amostra.

Quatro payloads independentes do `TS00000000076`, todos decifrados com a chave
do respectivo deploy:

| amostra             | deploy         | desfecho |
| ------------------- | -------------- | -------- |
| contêiner `windows` | `<chave-F5-F>` | BLOQUEOU |
| contêiner `macos`   | `<chave-F5-F>` | passou   |
| local (teste.py)    | `<chave-F5-D>` | passou   |
| local (teste.py)    | `<chave-F5-D>` | BLOQUEOU |

**Dois deploys, dois desfechos.** O que for igual em todas as quatro é estrutura;
o que variar é conteúdo.

##### R21.2 — A estrutura `[FACT]`

Todos os payloads têm **264 bytes** decifrados. Apenas 14 de 264 bytes são
invariantes — e eles não estão espalhados:

```
[ 80.. 83]  30 31 36 61   = ASCII "016a"
[146..149]  30 31 36 61   = ASCII "016a"
[212..215]  30 31 36 61   = ASCII "016a"
[262..263]  ff 01         = padding F5

espacamento entre marcadores: 66, 66
```

> O payload contém **três registros de 66 bytes**, cada um iniciado pelo
> marcador ASCII `"016a"`, precedidos por um cabeçalho de 80 bytes.

O conteúdo dos registros é hexadecimal em ASCII. No braço `windows` a região
repete **exatamente** com período 66 — os três registros são idênticos entre si;
no `macos` não há repetição limpa. A diferença é observação, não explicação.

##### R21.3 — O §13.4-Q3 respondido, e não como se esperava `[FACT]`

A pergunta era: _os 18 campos estão num blob único ou espalhados por vários
cookies?_

**Nenhum dos dois.** O cookie de fingerprint **não contém 18 campos discretos**.
Contém três registros uniformes de 66 bytes de conteúdo hexadecimal — a forma de
um valor já **condensado**, não de uma lista de atributos.

Somando ao §9.3-R20.3:

| o que viaja            | onde            | forma                       |
| ---------------------- | --------------- | --------------------------- |
| User-Agent, locale     | `TS6695b38b071` | **texto claro**             |
| o resto do fingerprint | `TS00000000076` | **3 registros condensados** |

Ou seja: tela, `hardwareConcurrency`, fontes e canvas **não viajam
individualmente**. Só a identidade declarada (UA/locale) chega em claro; o resto
chega agregado.

##### R21.4 — Consequência para a decomposição

Isto explica, retrospectivamente, por que a decomposição campo a campo nunca
avançou (§9.3-R9.6, §9.3-R12): **os campos individuais não existem como campos
no que é enviado.** Não há "campo da resolução" para o servidor ler — há um
condensado que muda quando qualquer entrada muda.

Consequência prática: variar um campo do fingerprint altera o condensado inteiro,
e nenhuma leitura do payload consegue dizer _qual_ entrada mudou. A via de
"isolar o campo causal lendo o que é enviado" está **fechada** — não por falta de
acesso, mas pela forma do dado.

O que **continua** possível é o contraste comportamental: variar uma entrada e
observar o desfecho no ambiente determinístico (contêiner). Mas isso é o que já
fazíamos, e o §9.3-R19.4 mostrou o custo em replicação.

##### R21.5 — Limites

1. Quatro amostras estabelecem a **estrutura** (marcador e período), não o
   **significado** dos registros. O que os 66 bytes codificam permanece
   desconhecido.
2. O cabeçalho de 80 bytes não foi decomposto.
3. `"016a"` é o prefixo invariante; nas amostras aparece dentro da sequência
   maior `016aa017`, cujo restante varia. Não se estabeleceu se é marcador de
   registro, versão de schema, ou início de um campo maior.

---

#### 9.3-R22 — Experimento (2026-09-08): UA em claro × condensado — resultado AMBÍGUO, como previsto

> Pré-inscrição em `exp_ua.py`, com a assimetria de leitura declarada **antes**:
> passar seria conclusivo, bloquear seria ambíguo. Bloqueou.

---

##### R22.1 — O desenho

O §9.3-R20 e o §9.3-R21 mostraram que a identidade de SO chega ao servidor por
dois caminhos: o **UA em claro** (`TS6695b38b071`) e o **condensado**
(`TS00000000076`). A pergunta: por qual deles o servidor decide?

Perfil `macos` (que passa 8/8 no contêiner) com **apenas** o
`navigator.userAgent` trocado pelo do Windows, via override do próprio Camoufox.

Verificado offline antes de gastar a sessão: o override muda **JS e header HTTP
juntos** (`navigator.userAgent` e `User-Agent` batem), sem recriar a contradição
Playwright-vs-motor do §9.3-R2.7.

##### R22.2 — Resultado: BLOQUEOU — e isso não conclui `[UNKNOWN]`

```
UA       : Mozilla/5.0 (Windows NT 10.0; Win64; x64; ...)   forcado
platform : MacIntel        oscpu: Intel Mac OS X 10.15      preservados
desfecho : BLOQUEOU na acao 2
```

A regra de leitura estava escrita antes:

> **PASSA** → conclusivo: o UA em claro não é o discriminante.
> **BLOQUEIA** → ambíguo: pode ser "leu o UA" ou "detectou a incoerência"
> (`platform=MacIntel` com UA de Windows).

Bloqueou, portanto **não se conclui nada** sobre qual caminho o servidor lê. O
§9.3-R2.7 já documentou que identidade internamente contraditória bloqueia por
si — e esta sessão é, por construção, contraditória.

Para separar as leituras seria preciso trocar `platform`/`oscpu` **junto** com o
UA, tornando a identidade coerente com o Windows. Isso é experimento novo, com
pré-inscrição própria, e a regra de parada do `exp_ua.py` proíbe emendá-lo aqui.

##### R22.3 — A verificação in-band funcionou `[FACT]`

Pela primeira vez foi possível confirmar **o que de fato foi enviado**, e não
apenas o que o navegador reportava. Decifrando o payload da própria sessão:

```
#0  len=5   'pt-BR'
#1  len=80  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) ...'
#2  len=16  ffbfdcfffbf6fdfbfebef6ffffffffff
```

O UA forçado **chegou ao servidor** exatamente como configurado. Sem esta
verificação, a manipulação seria ato de fé — é o ganho concreto que o §9.3-R20 e
o §9.3-R21 trouxeram.

##### R22.4 — O campo de 16 bytes acompanha o AMBIENTE, não o desfecho `[FACT]`

Comparando o campo em **dez** amostras:

| ambiente          | identidade     | desfecho | campo (byte 10) |
| ----------------- | -------------- | -------- | --------------- |
| contêiner         | coerente       | BLOQUEOU | `f6`            |
| contêiner         | coerente       | passou   | `f6`            |
| contêiner         | **incoerente** | BLOQUEOU | `f6`            |
| local (6 sessões) | coerente       | ambos    | `f7`            |

O bit separa **contêiner × local** — e nada mais. Não acompanha o desfecho, não
acompanha a coerência da identidade, não acompanha o perfil de SO.

Leitura compatível: é uma **máscara de capacidades** do ambiente. No contêiner
falta WebGL e falha o áudio (§9.3-R15), e um bit a menos fica setado. Reforça o
§9.3-R20.4: o campo não é veredito.

##### R22.5 — Um erro meu, evitado por ampliar a amostra

Ao ver o campo da sessão nova (`f6`) contra o registrado no §9.3-R18.1 (`f7`),
concluí por um instante que **um bit havia virado por causa da incoerência** —
o que seria um achado forte, e casaria bem demais com a hipótese em teste.

Estava errado: comparei a sessão nova (contêiner) contra amostras **locais**. As
amostras de contêiner do §9.3-R20 já traziam `f6`. Ampliar de 2 para 10 amostras
derrubou a leitura em segundos.

Registrar isto importa porque é o **contra-exemplo** do padrão do §9.3-R19.2:
ali, quatro hipóteses nasceram de n=1 e morreram no teste seguinte. Aqui a
verificação veio **antes** da conclusão. A diferença não foi sorte — foi checar
todas as amostras disponíveis em vez das duas mais convenientes.

##### R22.6 — Onde isso deixa a pergunta

Continua aberta: **o servidor decide pelo UA em claro ou pelo condensado?**

O experimento que a responderia é o braço coerente — `platform`, `oscpu` e UA
todos trocados para Windows, sobre base `macos` — mas ele tem um problema
próprio: com todos os campos de identidade trocados, o perfil resultante é
funcionalmente o `windows`, e já se sabe que ele bloqueia. O teste degenera.

A pergunta pode ser **estruturalmente indecidível** com este instrumento: os
dois caminhos carregam a mesma informação, e não há como variar um sem o outro
sem produzir incoerência — que é, ela própria, um bloqueador.

---

#### 9.3-R23 — Medição (2026-09-08): o probe estava incompleto, e `speechSynthesis` nunca foi medido

> Zero sessões contra o alvo. Sobe o navegador em `about:blank`, mede e sai.
> Corrige uma premissa que sustentava várias eliminações anteriores.

---

##### R23.1 — A lacuna: comparávamos o que a página reporta, nunca o que o perfil configura

Todas as eliminações do estudo (§9.3-R12, R15, R21) apoiaram-se no `FULL_FP_JS`,
que mede ~40 campos. Nunca comparamos as **configurações** que o Camoufox
aplica — são 42 chaves.

Comparando-as, **20 campos diferem entre `macos` e `windows` e estão FORA do
nosso probe**. O §9.3-R15.4 concluiu que "a explicação não está nos campos que o
nosso probe captura" e registrou explicitamente que isso **não** equivalia a
"não é observável". Esta seção mede o que ficou de fora.

##### R23.2 — O que de fato se manifesta no contêiner `[FACT]`

| campo                             | macos                               | windows                               | manifesta?                 |
| --------------------------------- | ----------------------------------- | ------------------------------------- | -------------------------- |
| **`speechSynthesis.getVoices()`** | **111 vozes** (Alex, Daniel, Fred…) | **53 vozes** (Microsoft David, Zira…) | **SIM**                    |
| `screen.availTop`                 | 25                                  | 0                                     | sim                        |
| `screen.pixelDepth`               | 30                                  | 24                                    | sim                        |
| `navigator.appVersion`            | `5.0 (Macintosh)`                   | `5.0 (Windows)`                       | sim (derivado do UA)       |
| `webgl` / `webgl2` contexto       | **null**                            | **null**                              | **NÃO**                    |
| `mediaDevices`                    | indisponível                        | indisponível                          | **NÃO** (em `about:blank`) |

**Duas eliminações de graça:**

- os `webGl:parameters`, `supportedExtensions` e `shaderPrecisionFormats`
  diferem na config, mas **não há contexto WebGL no contêiner** — nunca são
  consultados, logo não podem participar da decisão ali;
- `mediaDevices` não se manifesta em `about:blank` (exige contexto seguro).
  Continua **não testado** numa página https.

##### R23.3 — O achado: `speechSynthesis` `[FACT]`

Num contêiner Linux sem _speech engine_, um Firefox real devolveria **zero**
vozes. O Camoufox fabrica **111** (macOS) ou **53** (Windows), com nomes de
vozes reais de cada sistema.

É superfície clássica de fingerprint, difere enormemente entre os perfis, e
**nunca foi medida em nenhuma revisão deste estudo**.

##### R23.4 — Uma pista testada e descartada na mesma sessão `[REFUTED]`

Ao ver `screen.availLeft=1920` com `window.screenX=1912` no perfil Windows,
levantei a hipótese de **geometria de janela internamente inconsistente** — o
que casaria com o §9.3-R2.7 (identidade contraditória bloqueia).

Medindo 3 lançamentos de cada perfil, a "inconsistência" aparece em **macOS 3/3**
e **Windows 2/3**. O perfil que passa 8/8 é o que mais a exibe. Além disso, meu
critério (`screenX >= availLeft`) era arbitrário: uma janela pode legitimamente
estar sobre a barra de menu.

Descartada antes de virar hipótese nomeada — aplicando a regra que o §9.3-R19.5
estabeleceu depois de quatro candidatos de n=1 terem morrido.

##### R23.5 — O que isto muda, e o que não muda

**Muda:** a afirmação "esgotamos a superfície observável" era falsa. Havia 20
campos fora do probe, e um deles (`voices`) é uma superfície real que difere por
um fator de 2 entre os perfis.

**Não muda:** `voices` herda o mesmo problema estrutural do §9.3-R21.4 — os
campos viajam **condensados**, e trocar a lista de vozes de um perfil pelo outro
produz identidade contraditória (macOS com vozes da Microsoft), que é ela própria
um bloqueador conhecido. O mesmo beco do §9.3-R22.

**Fica em aberto e é testável sem contradição:** `mediaDevices` numa página
https. É a única superfície identificada que ainda não se manifestou e que não
foi medida.

##### R23.6 — Nota de método

O erro foi de sequência: comparar as **configurações** dos perfis é grátis e
deveria ter vindo **antes** de qualquer sessão. Teria enquadrado desde o início
o que existe para observar, em vez de eliminarmos campos um a um assumindo que a
lista estava completa.

---

#### 9.3-R24 — Análise (2026-09-08): o `TS00000000076` **não** carrega o fingerprint — é tempo + valor por sessão

> Zero sessões. Reanálise dos payloads já capturados, a partir de um
> reenquadramento do operador: usar **o payload como oráculo** em vez do
> desfecho. Derruba uma dedução que o estudo carregava desde o §8.

---

##### R24.1 — O reenquadramento que produziu isto

Até aqui o oráculo era o **desfecho**: um bit por sessão, contra um serviço
público. O operador apontou o óbvio que eu não estava usando: o **payload
capturado lista o que eles coletam**, e o que _não_ está nele também informa —
dá para mapear os atributos a olhar em vez de testá-los um a um às cegas.

##### R24.2 — Os três "registros" são um valor espelhado `[FACT]`

O §9.3-R21.2 identificou três registros de 66 bytes nos offsets 80, 146 e 212.
Comparando-os dentro de cada amostra:

```
R1 == R2  em 8 de 8 amostras
R3        e o mesmo valor, truncado pelo fim do buffer
```

Não são três campos — é **um valor repetido**. Corrobora a linha do §8 sobre
"valores espelhados = consistência cruzada", que o §13 listava como dedução.

##### R24.3 — O prefixo é temporal `[FACT]`

Ordenando as amostras locais por hora de captura, os primeiros 12 caracteres do
registro crescem **monotonicamente**:

```
08:16:51   016a9fef8796
08:23:48   016a9ff1246d
08:45:06   016a9ff62444
08:47:08   016a9ff68cec
08:54:23   016a9ff814c0
08:56:18   016a9ff8a122
```

Razão entre o incremento e o tempo decorrido: **218 a 312 unidades por segundo**
(média ~254), em cinco intervalos independentes. É relógio ou contador
guiado por tempo — **não** um hash.

##### R24.4 — A cauda muda a cada sessão `[FACT]` — e isso derruba a dedução do §8

Os 54 caracteres restantes do registro, para sessões com **perfil e tela
idênticos**:

| perfil   | tela     | cauda                                        |
| -------- | -------- | -------------------------------------------- |
| MacIntel | 1512×982 | `3bbc6d305420093de156050aa3f4504a9741f581b0` |
| MacIntel | 1512×982 | `530b5e60097940a05bd9a79fa6869a0b02b5d0fe54` |

**Mesma configuração, caudas diferentes.** Em 3 sessões `MacIntel` → 3 caudas
distintas; em 3 `Win32` → 3 distintas.

Um hash de fingerprint é **determinístico**: mesma entrada, mesma saída. Este
valor não é.

> **O `TS00000000076` não carrega um digest estável do fingerprint.** Carrega um
> componente temporal mais um valor que varia por sessão — nonce, id de sessão,
> ou um hash que inclui um nonce.

O §13 listava _"o cookie TS…076 carrega o fingerprint"_ como **DEDUÇÃO**
("é o maior e nasce após a coleta"). A dedução foi agora testada e **não se
sustenta na forma simples**.

##### R24.5 — Retratação parcial do §9.3-R17.4

O §9.3-R17.4 declarou o §12.7.a **refutado**, com o argumento de que o cookie
grande decifra — logo o fingerprint não estaria "fora de alcance".

O argumento estava certo no fato e errado na conclusão: **decifrar o cookie não
entrega o fingerprint**, porque o fingerprint não está lá. A afirmação
substantiva do §12.7.a — _"o conteúdo decisivo fica atrás da chave do servidor"_
— volta a ser plausível.

Estado corrigido:

| afirmação                                     | status                          |
| --------------------------------------------- | ------------------------------- |
| o cookie grande decifra com a chave do script | `FACT` (R17.3)                  |
| o conteúdo decifrado é o fingerprint          | **`REFUTADO`** (R24.4)          |
| o fingerprint está fora de alcance offline    | **`PLAUSÍVEL`** — volta a valer |

##### R24.6 — O inventário do que É enviado, em claro

Somando R20, R21 e esta análise, o que conseguimos ler dos cookies
client-sealed:

| conteúdo                           | cookie          | forma                                     |
| ---------------------------------- | --------------- | ----------------------------------------- |
| locale (`en-US`, `pt-BR`)          | `TS6695b38b071` | **texto claro**                           |
| User-Agent completo                | `TS6695b38b071` | **texto claro**                           |
| máscara de capacidades do ambiente | `TS6695b38b071` | 16 B; `f6` contêiner / `f7` local (R22.4) |
| tempo + valor por sessão           | `TS00000000076` | espelhado 3×                              |

**Não aparece em lugar nenhum do que lemos:** tela, `hardwareConcurrency`,
fontes, vozes, canvas, audio. Nem em claro, nem como digest estável.

Os cookies que **não** abrem com a chave do script — `TSPD_101`,
`TS0eaa6361027`, `TS6695b38b029`, `TS01ec2f54` — permanecem os candidatos a
portador do fingerprint, e são server-sealed (§12.7.a).

##### R24.7 — O que isto orienta

O mapa que o reenquadramento pedia:

1. **Não** adianta procurar atributos no `TS00000000076` — ele é tempo + nonce.
2. O que temos em claro é **locale + UA + capacidades do ambiente**. Se a decisão
   usasse só isso, seria explicável — e é compatível com o §9.3-R20.2, onde o
   único campo legível que diferia entre bloqueio e passagem era o UA.
3. O resto do fingerprint viaja nos cookies server-sealed, fora de alcance.

_Isto não prova que a decisão usa o UA_ — o §9.3-R22 mostrou que não dá para
separar UA de condensado sem criar incoerência. Mas estreita o que está
disponível ao servidor **por este caminho** a três coisas, e duas delas
(locale, capacidades) não acompanham o desfecho.

---

#### 9.3-R25 — Descoberta (2026-09-08): existe um segundo cookie grande, `TS00000000074`, e o nosso método de captura sempre o perdeu

> Zero sessões. Reanálise das timelines já gravadas, seguindo o fio de "onde o
> fingerprint efetivamente sai". A resposta estava no corpus desde a primeira
> sessão.

---

##### R25.1 — O fingerprint não sai pela URL `[FACT]`

Antes de qualquer engenharia reversa de script, a checagem empírica. Em uma
sessão completa do `t.py`, todas as 12 requisições `/TSPD/`:

```
metodo    : GET em 12/12   (nenhum POST, nenhum post_data)
len(URL)  : min 50, max 146 caracteres
```

146 caracteres não carregam WebGL, canvas, fontes e áudio. Confirma
empiricamente o §9.5 — o token da URL é **roteamento**, não payload — e torna
desnecessário seguir `SS.I_ → z_.ol → z_.lzz`, que a própria §9.4 apontava como
"o próximo fio".

##### R25.2 — Os cookies crescem ao longo do pipeline `[FACT]`

O tamanho total dos cookies **enviados** em cada requisição, na ordem do
pipeline:

| type               | total    | novidade                                                                    |
| ------------------ | -------- | --------------------------------------------------------------------------- |
| 18, 17, 20, 11, 12 | 426      | `TS0eaa6361027`, `TS01ec2f54`, `TS6695b38b029`                              |
| 22                 | 602      | `+TS6695b38b077` (176 B)                                                    |
| **13**             | **1162** | **`+TS00000000074` (560 B)**                                                |
| 14                 | 1755     | `+TS00000000076` (528 B), `+TS6695b38b071` (401 B), `+TSPD_101_DID` (224 B) |
| 17, 22             | 1578     | `+TSPD_101`; **`TS00000000074` DESAPARECE**                                 |

É aqui que o fingerprint entra no canal: entre o `type=12` (coleta) e o
`type=14` (clntcap_success), os cookies passam de 426 para 1755 bytes.

##### R25.3 — `TS00000000074`: o cookie que nunca vimos `[FACT]`

```
tamanho    : 560 bytes
nasce      : no type=13 (o frame clntcap — a captura)
morre      : depois do type=14 (clntcap_success)
presente em: 12 de 12 timelines do corpus
capturado  : em NENHUM cookie_jar
```

É **transiente**. Nossa captura sempre tirou o snapshot do jar ao final da
sessão — momento em que o `074` já não existe.

E o próprio `f5monitor.py` sempre soube: sua tabela de significados diz
`TS00000000076, TS00000000074 -> "payload do fingerprint (o grande)"`. O nome
estava no código desde o início; nunca olhamos o cookie.

##### R25.4 — Por que isto reabre a questão

O §9.3-R24 mostrou que o `TS00000000076` **não** carrega o fingerprint — é
tempo + nonce. Isso deixava a pergunta "então onde o fingerprint sai?" sem
resposta, e apontava para os cookies server-sealed como único candidato.

Havia um terceiro caminho, e é o mais simples: **o `074`**. Ele nasce
exatamente no frame de captura, tem 560 bytes — o maior de todos — e some assim
que a captura conclui. O perfil de um payload **consumido e substituído**.

O `076` (528 B) aparece no mesmo instante em que o `074` desaparece. Leitura
compatível, e ainda não verificada: o `074` é o payload da captura, o `076` é o
recibo que o substitui.

##### R25.5 — O que isto diz sobre o método, e não é confortável

Vinte e cinco revisões, e o cookie mais plausível como portador do fingerprint
nunca foi examinado — não por estar cifrado, escondido ou protegido, mas porque
**o nosso instrumento tirava a foto depois de ele já ter ido embora.**

O padrão é o mesmo do §9.3-R17 e do §9.3-R18: a conclusão descrevia o
instrumento, não o alvo. Ali era o hook truncando o pipeline; aqui é o
_momento_ do snapshot. Em ambos, o que faltava não era acesso — era olhar na
hora certa.

##### R25.6 — O próximo passo, e ele é barato

Capturar o jar **durante a janela**, disparado pela resposta do `type=13` em vez
de ao final da sessão. Uma sessão, no contêiner determinístico.

Se o `074` abrir com a chave do script — como o `076`, o `071` e o `DID` abriram
(§9.3-R17.3) — teremos, pela primeira vez, **o fingerprint como o servidor o
recebe**.

Se não abrir, ele é server-sealed, e aí a conclusão do §12.7.a vale em definitivo
— mas por evidência direta, e não por ausência causada por nós.

---

#### 9.3-R26 — Captura (2026-09-08): o `TS00000000074` foi capturado e **decifra**

> Uma sessão, no contêiner. O objetivo era a **captura**, não o desfecho — o
> bloqueio/passagem não foi interpretado.

---

##### R26.1 — A captura `[FACT]`

O §9.3-R25 mostrou que o `TS00000000074` (560 B) nasce no `type=13` e some
depois do `type=14`, e que todo snapshot nosso era tarde demais.

Instrumentação: **amostragem contínua** do jar a cada 150 ms desde antes do
`goto`, mais disparo por evento nas respostas do `type=13` e `type=14`.

```
[CAPTURADO] TS00000000074 (560 B) via amostragem
```

A redundância foi necessária: quem pegou foi a **amostragem**, não o disparo por
evento — que chegou tarde. A janela é mais curta que a latência entre a resposta
do `type=13` e a leitura do jar.

##### R26.2 — Decifra com a chave do script `[FACT]`

```
560 hex -> 280 bytes de plaintext
padding F5: 00 00 00 00 00 00 00 ff ff 02   (n=2, valido)
chave: <chave-F5-G>  (do type=11 do mesmo deploy)
```

**É client-sealed.** Não está atrás da chave do servidor.

##### R26.3 — O que há dentro, e como difere do `076` `[FACT]`

|                      | `TS00000000074`                                        | `TS00000000076` |
| -------------------- | ------------------------------------------------------ | --------------- |
| plaintext            | 280 B                                                  | 264 B           |
| ASCII imprimível     | **17%**                                                | 80%             |
| diversidade de bytes | 0,39                                                   | 0,30            |
| conteúdo legível     | **nenhum**                                             | UA, locale, hex |
| primeiros 48 bytes   | **idênticos entre si** — token de sessão compartilhado |                 |

O `074` é **binário**; o `076` é majoritariamente texto. São coisas diferentes,
e o §9.3-R24 já havia mostrado que o `076` é tempo + nonce.

##### R26.4 — Interpretação preliminar, NÃO validada `[HYPOTHESIS]`

Lendo a região a partir do offset 64 como inteiros de 32 bits big-endian, sai uma
mistura característica:

```
pequenos : 1, 7, 40, 43, 172, 200, 215, 231
grandes  : 2497836995, 3552080153, 1811026439, 1449348852, ...
mascaras : 33554432 (0x02000000), 100663296 (0x06000000)
```

62% dos valores são < 10.000. O perfil — contadores pequenos, hashes de 32 bits
e máscaras — é o que se esperaria de um **vetor de features de fingerprint
empacotado**.

**Mas isto é n=1, e o alinhamento dos u32 é uma escolha minha, não uma
observação.** É exatamente a armadilha do §9.3-R18.2 (parse ajustado a uma
amostra) e do §9.3-R21 (que só se resolveu com validação cruzada). Registrar
esta leitura como achado repetiria o erro.

##### R26.5 — O que valida, e custa uma sessão

**Duas capturas do mesmo perfil.** Valores que se repetirem entre elas são
estrutura ou fingerprint; valores que mudarem são nonce ou tempo. Foi assim que
o §9.3-R21 achou o período de 66 bytes e o §9.3-R24 derrubou a dedução do §8.

Com dois perfis diferentes (`macos` × `windows`), os valores que mudarem **junto
com o perfil** são os candidatos a campo de identidade — e aí o §13.4-Q2 e o Q4
se fecham para o fingerprint inteiro, não só para o UA.

##### R26.6 — O que já está estabelecido, independente da validação

1. O fingerprint **não** está fora de alcance: o cookie que o carrega é
   client-sealed e abre com a chave do script.
2. A conclusão do §12.7.a — _"o conteúdo decisivo fica atrás da chave do
   servidor"_ — está **refutada**, agora por evidência direta e não por
   ausência. (A retratação parcial do §9.3-R24.5 fica, ela própria, retratada:
   ela dizia que o §12.7.a "volta a ser plausível". Não volta.)
3. O que nos separava do conteúdo não era criptografia nem chave do servidor —
   era o **instante do snapshot**.

---

#### 9.3-R27 — Validação cruzada (2026-09-08): **6 bytes** do payload codificam a identidade de SO

> Quatro capturas do `TS00000000074`, duas por perfil, no contêiner. Valida (e
> corrige) a leitura preliminar do §9.3-R26.4.

---

##### R27.1 — O desenho

O §9.3-R26 capturou o cookie transiente mas registrou a interpretação como
`HYPOTHESIS`: n=1 e alinhamento escolhido por mim. A validação exige separar o
que varia **por sessão** do que varia **por perfil**:

```
macos#1, macos#2      -> o que difere entre elas varia por SESSAO
windows#1, windows#2  -> idem
macos x windows       -> o que difere e candidato a PERFIL
```

Detalhe que dá força ao desenho: o Camoufox **sorteia a tela a cada launch**, então
as duas sessões de um mesmo perfil têm telas e horários diferentes. Um byte
estável entre elas é estável _apesar_ disso.

##### R27.2 — O resultado `[FACT]`

```
             macos#1   macos#2   windows#1  windows#2
[ 91.. 94]   ac511f0c  ac511f0c  eeb6dc1b   eeb6dc1b
[145..146]   467f      467f      8068       8068
```

De 280 bytes de plaintext:

| classe                                          | bytes |
| ----------------------------------------------- | ----- |
| variam por sessão (nonce, tempo, tela)          | ~80   |
| invariantes (estrutura)                         | ~194  |
| **variam por PERFIL e são estáveis por sessão** | **6** |

E são **exatamente** esses 6 — offsets 91, 92, 93, 94, 145 e 146. Nenhum outro
byte satisfaz o critério nas duas comparações.

> A identidade de SO está no payload de fingerprint, condensada em
> **um valor de 32 bits (offset 91) e um de 16 bits (offset 145)**.

##### R27.3 — O que isto fecha

O §13.4-Q4 perguntava se os campos de SO viajam **em claro ou derivados**. A
resposta agora é completa, e são as duas coisas por caminhos diferentes:

| caminho         | forma                                         |
| --------------- | --------------------------------------------- |
| `TS6695b38b071` | UA e locale em **texto claro** (§9.3-R20.3)   |
| `TS00000000074` | identidade **derivada**, 6 bytes (esta seção) |

E responde onde o fingerprint entra no canal: no `TS00000000074`, o cookie
transiente que nasce no `type=13` e morre depois do `type=14` (§9.3-R25).

##### R27.4 — Correção de uma leitura minha, três parágrafos antes

Ao ver que `macos#1 × macos#2` batiam em 71% dos bytes e `macos × windows` em
69%, escrevi que "praticamente igual — se o cookie codificasse o perfil, duas
sessões do mesmo perfil seriam muito mais parecidas".

**Errado.** A similaridade agregada é uma métrica grosseira demais: 6 bytes em
280 movem o percentual em 2 pontos e desaparecem no ruído dos ~80 bytes de
nonce. Só a diferença de conjuntos (`P − S`) localizou o sinal.

Fica a regra: quando o sinal esperado é pequeno e localizado, **medir
similaridade agregada esconde**; é preciso perguntar _quais_ posições, não
_quantas_.

##### R27.5 — Limites

1. **Dois perfis.** `linux` não foi capturado; não se sabe se ele produz um
   terceiro valor ou colide com um dos dois.
2. **Não sabemos a função.** Sabemos _onde_ a identidade é codificada, não _como_
   — `ac511f0c` não foi derivado de nenhuma entrada conhecida.
3. **Não prova que o servidor usa esses bytes.** Mostra que ele os recebe. O
   §9.3-R22 já registrou que separar "recebe" de "usa" pode ser estruturalmente
   indecidível com este instrumento.
4. O resto do vetor — os ~194 bytes invariantes e os ~80 de nonce — continua sem
   mapeamento campo a campo.

##### R27.6 — Nota de instrumento

Quatro sessões no contêiner determinístico. O objetivo era **captura e
validação**, não desfecho: bloqueio/passagem não foi interpretado em nenhuma
das quatro.

A amostragem contínua a 150 ms pegou o cookie em 4 de 4 tentativas; o disparo
por evento não pegou em nenhuma. Se o experimento dependesse só do evento, as
quatro sessões teriam sido perdidas.

---

#### 9.3-R28 — Experimento (2026-09-08): o payload é **diferenciável** — mapeando entrada por entrada

> Três sessões no contêiner, com a tela **fixada** para reduzir o ruído. Prova
> que o método de localização funciona, e corrige uma avaliação minha feita
> antes de rodar.

---

##### R28.1 — Uma avaliação minha, corrigida antes do experimento

Classifiquei este teste como **"baixa expectativa"**, citando o §9.3-R21.4:
_"variar uma entrada altera o condensado inteiro"_.

Aquilo valia para o `TS00000000076` — que o §9.3-R24 mostrou ser tempo + nonce,
sem estrutura de campos. O §9.3-R27 já havia mostrado o oposto para o
`TS00000000074`: a identidade de SO em **6 bytes localizados**.

Eu havia generalizado de um cookie para o outro. O payload de fingerprint **não
tem avalanche** — é vetor estruturado, e portanto diferenciável.

##### R28.2 — O desenho, com uma melhoria sobre o §9.3-R27

```
A1, A2 : base identica — tela FIXA 2560x1440, cores=8   -> ruido de sessao
B      : mesma base, cores=16                            -> candidatos
```

Fixar a tela é a melhoria: no §9.3-R27 o Camoufox a sorteava por launch, e ela
sozinha injetava boa parte do ruído. Aqui o ruído de sessão caiu de ~80 para
**75 bytes**.

Validade in-band: as três sessões reportaram a tela pedida e o `cores` pedido.

##### R28.3 — O resultado `[FACT]`

```
75 bytes variam por SESSAO (A1 x A2, configuracao identica)
77 bytes diferem entre cores=8 e cores=16
 2 bytes diferem por CORES e sao estaveis entre sessoes

   [127..128]   cores=8: f406      cores=16: a7be
```

> `navigator.hardwareConcurrency` é codificado em **2 bytes no offset 127**.

Como no §9.3-R27, o conjunto que difere é dominado por ruído de sessão (75 dos
77), e o sinal atribuível é minúsculo e **localizado**.

##### R28.4 — O que isto estabelece

**Um método, não só um campo.** Duas entradas já foram localizadas, em posições
distintas e não sobrepostas:

| entrada               | offsets         | tamanho   |
| --------------------- | --------------- | --------- |
| identidade de SO      | 91–94 e 145–146 | 4 B + 2 B |
| `hardwareConcurrency` | 127–128         | 2 B       |

O payload é um **vetor de campos com posições fixas**. Qualquer entrada
controlável pelo Camoufox pode ser localizada com o mesmo procedimento: três
sessões, duas de base e uma variada.

**O valor é derivado, não bruto.** `cores=8` produz `f406` e `cores=16` produz
`a7be` — não são 0x0008 e 0x0010. Cada campo passa por alguma transformação
antes de entrar no vetor. Sabemos _onde_, não _como_.

##### R28.5 — Limites

1. **Uma entrada mapeada por 3 sessões.** Mapear as demais (tela, fontes, vozes,
   canvas, áudio) custa 3 sessões cada — ou menos, reusando A1/A2 como base
   comum e gastando 1 por variável. Não foi feito.
2. **Não estabelece causalidade.** Saber que `cores` ocupa o offset 127 não diz
   que o servidor o lê ou pondera. O limite do §9.3-R22.6 permanece.
3. `cores` foi escolhido justamente por **já ter sido eliminado** como
   discriminante do desfecho (§9.3-R12): variar não muda o resultado, só o
   payload. É o teste mais limpo do método, e o menos informativo sobre a
   decisão.

##### R28.6 — Nota de método

A avaliação "baixa expectativa" veio de generalizar o comportamento de um cookie
para outro sem verificar. O operador propôs testar mesmo assim; o teste
funcionou. Registrar isto importa porque o custo de uma previsão pessimista
errada é o mesmo de uma otimista errada — deixa de fazer o experimento que
funcionaria.

---

#### 9.3-R29 — Mapeamento (2026-09-08): fontes **não** estão no payload; vozes não são superfície estável

> Duas sessões, reusando A1/A2 do §9.3-R28 como base. Um resultado negativo
> válido, um braço invalidado, e uma correção ao §9.3-R23.

---

##### R29.1 — O que foi variado

Alteração **mínima** em cada caso — um elemento a menos na lista — para produzir
o menor conjunto de bytes candidatos:

```
C : fonts   = lista do macOS menos 1 elemento
D : voices  = lista do macOS menos 1 elemento
base = A1/A2 do §9.3-R28 (tela fixa 2560x1440, cores=8, macos)
```

##### R29.2 — Verificação da manipulação, feita DEPOIS (e deveria ter sido antes)

```
base          vozes=118   fontes detectadas=10
fonts[:-1]    vozes= 83   fontes detectadas= 9   <- mudou
voices[:-1]   vozes= 88   fontes detectadas=10
```

| braço      | manipulação pegou?                                                           |
| ---------- | ---------------------------------------------------------------------------- |
| **fontes** | **SIM** — 10 → 9 detectadas, e a contagem é estável na base                  |
| **vozes**  | **INDETERMINADO** — a contagem varia sozinha entre lançamentos (118, 83, 88) |

Rodei os dois braços **antes** de verificar. Sem a verificação, o "0 candidatos"
das fontes seria indistinguível de "a manipulação não aplicou" — o mesmo erro do
`F5_SEM_HOOK` (§9.3-R17), e a segunda vez nesta investigação.

##### R29.3 — Fontes: resultado negativo VÁLIDO `[FACT]`

```
ruido de sessao (A1 x A2)      : 75 bytes
cores  (8 -> 16)               :  2 bytes  [127..128]
fontes (uma a menos, verificado):  0 bytes
```

Com a manipulação confirmada, **remover uma fonte não move nenhum byte** fora do
ruído de sessão.

Se as fontes fossem condensadas num campo do vetor, remover um elemento mudaria
esse campo — um hash muda por inteiro com qualquer alteração de entrada. Não
mudou nada.

> A lista de fontes **não é codificada** no `TS00000000074`, ao menos não de
> forma localizada e sensível a um elemento.

_Ressalva de tamanho de efeito:_ se o campo ocupasse 2 bytes e ambos caíssem por
acaso dentro dos 75 de ruído, o negativo seria falso — probabilidade ≈ 7%. Não é
desprezível, mas é baixa.

##### R29.4 — Vozes: braço inválido, e uma correção ao §9.3-R23 `[REFUTADO]`

O §9.3-R23.3 destacou `speechSynthesis` como achado: 111 vozes (macOS) × 53
(Windows), superfície clássica nunca medida.

A verificação mostra que a contagem **varia entre lançamentos com a mesma
configuração**: 118, 83, 88. Não é valor estável.

Duas consequências:

1. o braço D é **inválido** — não dá para atribuir ausência de efeito a uma
   manipulação cuja aplicação não se distingue do ruído;
2. o entusiasmo do §9.3-R23.3 estava **mal calibrado**. Uma superfície que varia
   sozinha em ±30% entre lançamentos idênticos é ruim como fingerprint, e o
   detector teria o mesmo problema que nós ao usá-la.

##### R29.5 — O mapa até aqui

| entrada               | offsets        | status                          |
| --------------------- | -------------- | ------------------------------- |
| identidade de SO      | 91–94, 145–146 | localizada (§9.3-R27)           |
| `hardwareConcurrency` | 127–128        | localizada (§9.3-R28)           |
| **fontes**            | —              | **não localizada** (esta seção) |
| vozes                 | —              | não testável (instável)         |
| tela, canvas, áudio   | —              | não testados                    |

Dos ~280 bytes, 8 estão atribuídos, ~75 são ruído de sessão e ~197 permanecem
sem mapa.

##### R29.6 — Nota de método, pela segunda vez

A verificação da manipulação tem de vir **antes** do experimento, não depois.
Nesta investigação isso já custou uma sessão inteira no §9.3-R17 (o
`F5_SEM_HOOK` que não pegou no PowerShell) e agora custou o braço D.

O padrão: quando a variável independente é aplicada por uma camada que não
controlamos (shell, config do Camoufox), aplicá-la e **medir que aplicou** são
dois atos distintos, e o segundo não é opcional.

---

### 9.4 Montagem e envio da telemetria (type*11 / módulo `z*`) — VERIFICADO

Esta subseção documenta o **lado de saída** — como os sinais coletados viram uma
requisição de rede. Foi lida direto de `portal/type_11.js` (52.642 linhas),
resolvendo a ofuscação com três regras confirmadas na fonte:
`L(x) = (368 > x)` (predicado opaco — todo `L(x)?a:b` é determinístico; **atenção: nome e constante são desta cópia. Ambos rotacionam a cada poucos minutos — sete valores já observados, §9.3-R35.8. Releia-os em cada arquivo; herdar a constante inverte ternarios**),
`z(off,n…) / s(off,n…) = String.fromCharCode(n − off)` e
`S(n,off) = (n+off).toString(36)` (nomes de propriedade em base-36).

**Divisão de arquitetura (refina §3):** `type_17.js` é o motor `ii` (cripto +
comportamento, §12); `type_11.js` é o **coletor/orquestrador**, com módulo próprio
`z_`, e é ele que detém a rede. **Cuidado com colisão de nome:** `ii.Jl` (type*17)
é a cifra/seal; `z*.Jl` (type_11, linha 8328) é um **wrapper de callback** — não
têm relação.

**O transporte (função `I(O,I,J)`, linhas ~26186–26264, offset local `l=98`):**

- É um **XHR `GET`, sem corpo**: `iL.open("GET", Ll); …; iL.send()`
  (`z(l,169,167,182)` = `"GET"`; `S(1152573,l)` = `open`; `S(1325255,l)` = `send`).
- A URL é `Ll = base + I + "?type=" + O[9]` — onde `s(l,161,214,219,210,199,159)`
  decodifica **`"?type="`**. Ou seja: o `type=11/12/17` que nomeia todo o estudo é
  **literalmente um parâmetro de query na URL**. Corrobora a §4 (`/TSPD/`).
- O `base` vem de **`window.bobcmn`** (`S(705968205,l)` = `"bobcmn"`) — o objeto de
  configuração global do **F5 Shape**, uma assinatura inconfundível — via `z_.oZ(...)`.
- **Resposta**: no `readyState === 4` (`z(l,212,199,…)` = `"readyState"`), o corpo é
  decodificado por `lz.Os(responseText, ll)` conforme um schema `ll`, persistido em
  `localStorage[O[12]]` e então dispara o callback `J`.

**Registro de config `lz` (nomes recuperados por base-36):** `lz.methods`,
`lz.escape`, `lz.types`. O **manifesto `ZZ`** (linhas ~26315) é um array **ordenado**
de descritores `{ type: lz.types.X }` — a lista declarativa de quais coletores rodam
e em que ordem. (Ressalva: os números por trás de `lz.types.l/._Z/.si` estão atrás de
predicados e não foram fixados estaticamente.)

**Schema de armazenamento `s5`** (linhas ~26345): resultados persistidos em múltiplos
backends — `local` (localStorage), `cookie`, `Ii` e **`Jz` = o cookie-semente
`TSX010AAA`** (o mesmo da chave 2, §12.5). Fecha o elo com a "teia" da §8.

**Limite honesto:** como é `GET` sem corpo, o payload cifrado viaja no **caminho/token
`I` da URL** (e/ou nos cookies da teia), não num corpo POST. Reconstruir o conteúdo
exato de `I` exige seguir `SS.I_` → `z_.ol` → `z_.lzz` — o próximo fio. O ferramental
de deofuscação usado aqui (regras `L(x)=368>x`, `z/s(off,n)=chr(n−off)`,
`S(n,off)=base36(n+off)`) está salvo em `forensic/deobf_f5.py`, reaproveitável.

### 9.5 Anatomia da URL e a linhagem do token de rota — VERIFICADO

A §9.4 mostrou que o envio é `GET … ?type=N`. Esta subseção detalha **como a URL é
montada** e prova que o token no caminho **não** é o payload — é roteamento.

A URL montada pelo emissor `iJ` (`type_11.js`, módulo `iJ` na linha 26136) é:

```
GET  <base>/<token I>?type=<N>
     base    = window.bobcmn            (config injetada pelo F5 → z_.oZ)
     token I = round-trip de window.Li.io   (ver linhagem abaixo)
     N       = descritor[9], de window.blobfp (via lz.Os)
```

**Linhagem do token `I`** (rastreada de `iJ.i_` até a origem, linha 25689):

```
window.Li.io            ← global injetado pelo F5 Shape
  → sz.iZ(·, z5)         decodifica
  → sz.ls(·, sz._i, …)   parseia em objeto
  → .iI                   campo iI
  → sz.Sz(·)  [= sz.map]  re-codifica
  = token I
```

Ou seja, o token é um **round-trip de um valor que o próprio F5 injetou**: o servidor
planta (`window.Li.io`), o cliente decodifica e devolve na URL. É um **token de
sessão/liveness** (prova de que o script rodou), **não** o fingerprint. Os três
insumos da requisição são todos globais injetados: `bobcmn` (base), `Li.io` (token),
`blobfp` (descritor com `type` e chave de storage).

Peças auxiliares (todas verificadas): `SS.I_(len, val, radix)` = conversão radix com
zero-padding (codificador de IDs); `SL = z_.lSz() + SS.I_(8,·,16) + z_.o_(74)` = um
**ID de requisição** (correlação/anti-replay) guardado por `z_.lzz`; `z_.ol(url)` só
acrescenta `?k=v;…` quando há estado dinâmico em `z_.lz`.

### 9.6 O cookie de dados: onde a cripto da §12 entra — VERIFICADO

Se a URL só leva roteamento, **onde viajam os dados cifrados?** Nos **cookies** — e
aqui está a prova na fonte de que eles usam exatamente a cripto da §12.

O módulo `sz` do `type_11.js` tem **sua própria XTEA** (delta `2654435769`, linhas
1025/1034) — a mesma primitiva de §12, num segundo script. A gravação do cookie
(`s5.osz`, linha 27748) faz:

```
s5.osz(nome, valor, ttl):
  ll     = sz.seal(valor, tag)                 // ENCRYPT-THEN-MAC (§12), tag 0x09/0x10
  cookie = nome + "=" + sz.Sz(J.iI)            // token ecoado (mesmo de §9.5)
                 + ll                          // + payload SELADO
                 + "; expires=…; path=/"
  z_.sZ(cookie)                                // document.cookie = cookie
```

O `sz.seal(valor, …)` é o wrapper de cifra+MAC (o método decodifica literalmente como
`"seal"`), e `z_.sZ` (linha 7887) termina em `document.cookie = …` (ou, quando existe o
"pote virtual" `z_.lz`, grava nele — o mecanismo dos cookies do frame **TS_Injection**
da §3/§8). As tags `0x09`/`0x10` distinguem variantes de cookie.

**O que isto fecha:** confirma na fonte a linha da §13 _"o cookie TS…076 carrega o
fingerprint"_ — o valor coletado é **selado (Encrypt-then-MAC, §12) e escrito como
cookie**, e é isso que o navegador reanexa ao `GET` da §9.4. A "teia" da §8 é, portanto,
a camada de dados; a URL é só transporte/roteamento. Encerra o item 2 ponta a ponta.

**Ressalva honesta (inalterada):** provamos a _mecânica_ (seal→cookie→reenvio); não
deciframos um cookie de produção. E nada disso muda a POC (§12.4) — o navegador real
executa toda essa cadeia sozinho.

---

#### §9.3-R30 — Tela localizada no payload; e dois braços anteriores anulados (2026-09-08)

Continuação do mapeamento do `TS00000000074` (§9.3-R27, §9.3-R29). Objeto: o
braço restante (**tela**). Resultado colateral: **a revogação do §9.3-R29.3**.

##### R30.1 — O primeiro braço da tela foi nulo, e a validade in-band pegou

O braço `E` foi rodado e reportou `0 candidatos` — "tela não localizada". A linha
de validade dizia:

```
A1 tela=[2560, 1440]    E tela=[2560, 1440]
```

Idênticas. A manipulação **não aplicou**. Causa: `exp_diff.py` aplicava a
variação sob `if braco.startswith("B") or braco in ("C", "D")` — uma lista
enumerada, à qual `E` nunca foi acrescentado. O braço rodou com a config base.

Não era um resultado negativo; era um **braço vazio**. Teria entrado no estudo
como "a tela não está no payload" se a verificação in-band não existisse.

A correção não foi acrescentar `E` à lista — foi trocar a enumeração por uma
regra estrutural (`if not braco.startswith("A")`), porque a enumeração é
justamente o que falha ao se acrescentar um braço.

##### R30.2 — Tela: 1 byte, offset 182 `[FACT]`

Braço `E2`, com a validade in-band confirmando `A1 tela=[2560,1440]` contra
`E2 tela=[1920,1080]`:

```
ruído de sessão (A1 x A2) : 75 bytes, faixas 8-71, 139-142, 179-181, 191-194
candidatos para TELA      :  1 byte  [182]
     off 182:  2560x1440 = 0x19     1920x1080 = 0x06
```

**Controle de seis pontos.** O offset 182 vale `0x19` em A1, A2, B, C, D **e E**
— seis sessões, incluindo três baselines distintas (A1, A2, e o braço `E`
acidentalmente-baseline do R30.1) — e só muda em `E2`, a única sessão em que a
tela mudou.

**A adjacência ao ruído não confunde.** 179-181 variam livremente entre sessões;
182 fica travado. São campos distintos, não uma faixa só:

```
A1  91 e4 5b | 19        E   2b 46 5c | 19
A2  2f 55 5c | 19        E2  df 45 d8 | 06
```

**O byte não é o valor.** Um byte não codifica 2560x1440. `0x19`/`0x06` são
condensado ou índice, não geometria literal — o mesmo vale para `cores`, onde
8 → `f4 06` e 16 → `a7 be` (§9.3-R29). O payload guarda _derivados_ por campo,
em posições fixas.

**Reconfirma a ausência de avalanche (§9.3-R27) com uma terceira variável
independente:** mudar a tela move 1 byte; mudar `cores` move 2. Um condensado
global mudaria os 280.

##### R30.3 — §9.3-R29.3 REVOGADO: fontes é braço nulo, não negativo `[REFUTADO]`

O §9.3-R29.3 registrou como `[FACT]` que "a lista de fontes não é codificada no
`TS00000000074`", apoiado na verificação "10 → 9 fontes detectadas".

**Aquela verificação não media o que dizia medir.** A sonda contava quantas de 14
fontes genéricas (Arial, Helvetica, Times New Roman…) eram detectáveis. A fonte
efetivamente removida da config era `Party LET` — **que não está entre as 14**.
Remover `Party LET` não podia mover aquele contador. O "10 → 9" foi ruído do
próprio contador, e foi lido como confirmação.

Medindo a fonte removida diretamente, por `measureText`:

```
                  Party LET detectável?   largura alvo / fallback
base                     SIM                  309.0 / 473.0
base2 (config idêntica)  NÃO                  473.0 / 473.0
fonts[:-1]               SIM                  308.0 / 472.0
```

Duas coisas de uma vez: a manipulação **não pegou** (`Party LET` sobrevive à
própria remoção), e a métrica **oscila entre baselines idênticas** (base x base2).

Consequência: o braço `C` do §9.3-R29 é **nulo**. Não sabemos se a lista de
fontes está no payload. Volta a `UNKNOWN`.

##### R30.4 — Fontes e vozes não são variáveis controláveis neste ambiente `[FACT]`

Quatro lançamentos no contêiner, `speechSynthesis.getVoices()` lido só depois de
a contagem estabilizar (três leituras iguais, não um timeout fixo):

```
base    131      base2   96      fonts-1  142      voices-1  123
```

Duas dessas configs são **idênticas** (base, base2) e diferem em 35 vozes. A
config do Camoufox declara 135. A variância entre baselines idênticas excede em
uma ordem de grandeza a manipulação pretendida (um elemento).

Isto **confirma e generaliza** o §9.3-R29.4 (que já dava as vozes por
indeterminadas, com 118/83/88) e **estende às fontes** por R30.3.

> Nem `fonts` nem `voices` podem ser usadas como variável independente neste
> contêiner. Não é que a manipulação falhe às vezes — é que o valor observado
> não é função da config. Sem controle, não há experimento.

Isto não diz nada sobre o payload. Diz que **este instrumento não consegue
perguntar** sobre esses dois campos.

##### R30.5 — O mapa do `TS00000000074` (280 bytes decifrados)

| campo                 | offsets                         | bytes    | como foi estabelecido                        |
| --------------------- | ------------------------------- | -------- | -------------------------------------------- |
| identidade de SO      | 91-94, 145-146                  | 6        | §9.3-R27, estável entre sessões              |
| `hardwareConcurrency` | 127-128                         | 2        | §9.3-R29, validade in-band                   |
| geometria de tela     | 182                             | 1        | **R30.2**, validade in-band, controle 6x     |
| ruído de sessão       | 8-71, 139-142, 179-181, 191-194 | 75       | A1 x A2 x E (três baselines)                 |
| **não mapeado**       | —                               | **~195** | —                                            |
| fontes                | ?                               | ?        | **UNKNOWN** — braço nulo (R30.3)             |
| vozes                 | ?                               | ?        | **UNKNOWN** — variável incontrolável (R30.4) |

**9 bytes de 280 localizados (3%).** Os 6 do SO são os únicos que correlacionam
com o desfecho, e essa correlação vem do §9.3-R9.2, não daqui: este mapeamento
localiza _onde_ os campos estão, e em momento nenhum mostra o servidor lendo-os.
A pergunta 2 do §13.4 continua aberta.

##### R30.6 — Nota de método, pela terceira vez

§9.3-R17 (`F5_SEM_HOOK`), §9.3-R29.6 (fontes/vozes) e agora R30.1 (tela) e R30.3
(fontes de novo, e desta vez a verificação existia e estava errada). O padrão
não é esquecer de verificar — é **verificar com uma sonda que não mede a
variável manipulada**.

A regra registrada em R29.6 era: _aplicar a variável e medir que aplicou são dois
atos distintos_. Ela é necessária mas não suficiente. A forma corrigida:

> A sonda de validade tem de medir **o elemento exato que foi alterado** — não um
> agregado que o contém, não um proxy correlacionado. E tem de ser rodada em duas
> baselines idênticas primeiro: se a sonda distingue duas baselines iguais, ela
> não pode atestar coisa alguma.

Implementada em `exp_diff.py` como porte que **aborta a sessão** quando a leitura
in-band não bate com a config, e como dicionário `SONDA` que **recusa rodar** uma
variável sem sonda declarada — `fonts` e `voices` estão deliberadamente fora dele.

---

#### §9.3-R31 — Caçada ao construtor da máscara de ambiente: critério NÃO atingido, três fatos colaterais (2026-09-09)

Análise estática dos `type_11.js`, `type_12.js` e `type_17.js` salvos, atrás do
código que produz o campo de 16 bytes do §9.3-R22.4 — o único sinal do lado do
cliente que rastreia o **ambiente**, metade não decomposta do H-CONJ′.

**Zero sessões CADESP.** Tudo offline, sobre scripts já capturados.

##### R31.1 — O orçamento, pré-registrado antes de abrir o arquivo

Seis estratégias declaradas, com critério de sucesso ("achar o código que produz
os 16 bytes") e de fracasso ("esgotar as seis sem isso") fixados antes.

| #   | estratégia                                     | resultado                                                |
| --- | ---------------------------------------------- | -------------------------------------------------------- |
| 1   | localizar o serializador e a emissão do tag    | **parcial** — achado o prefixo no payload, não o emissor |
| 2   | init com `0xFF` + limpeza de bits              | **nada**                                                 |
| 3   | `&= ~(1 << n)` / `^=` / subtração de potências | **nada**                                                 |
| 4   | array construído perto de feature-detection    | **ACERTOU** — R31.3                                      |
| 5   | diferencial entre os 4 deploys                 | parcial — R31.3                                          |
| 6   | âncora pelos valores literais da máscara       | **nada**                                                 |

> **Critério não atingido.** O construtor não foi localizado. Registrado como
> tentativa fracassada, sem sétima estratégia improvisada.

##### R31.2 — A máscara remedida, e a correção de um número meu `[FACT]`

Eu havia anunciado "15 bytes / 120 bits" a partir de um dump truncado. Medindo
os limites no payload completo:

```
174: 10                                              <- prefixo de comprimento (16)
175: ff bf dc ff fb f6 fd fb fe be f7 ff ff ff ff ff <- MASCARA: 16 B = 128 bits
191: 00 00 00 00 00                                  <- campo seguinte, todo zero
196: ff ff ff 03                                     <- padding F5 (§12)
```

São **16 bytes**, confirmando o §9.3-R22.4 e corrigindo o meu 15. O `0x10` é
comprimento, não conteúdo.

**13 bits zerados em 128**, todos concentrados nos bytes 1–10; os bytes 0 e
11–15 são `0xFF` puro.

> Essa forma **exclui digest**. Um hash de 16 bytes tem ~64 bits zerados, não 13.
> O campo é vetor de flags, não condensado — e isso vale independentemente de
> acharmos o construtor.

**Achado lateral:** os 5 bytes zerados em 191–195 são um campo que nunca foi
examinado por ninguém neste estudo.

##### R31.3 — O `type_11.js` embute um registro de feature-tests Modernizr `[FACT]`

A ofuscação foi vencida: strings são `z(off, n…)` com `chr(n − off)`, e o offset
é **literal** dentro de cada função (`var l=NN`), o que permite decodificação
exata — sem força bruta.

A forma do registro, idêntica dezenas de vezes:

```js
JOI={l:function(I){var l=31; I.I( "sharedworkers",  "SharedWorker" in …createElement… )}}
SLI={l:function(I){var l=25; I.I( "localstorage",   function(){…localStorage.setItem(…,"modernizr")…} )}}
```

`I.I(nome, valor)` é a chamada de registro. Extraindo estruturalmente (casando a
_forma_ `function(P){var V=N; … P.M(dec(V,…))`, não os nomes sorteados pelo
ofuscador, que mudam por deploy):

| deploy                      | registros |
| --------------------------- | --------- |
| `live_type11_1614fc8cb5.js` | 60        |
| `live_type11_a2e5e7c7ed.js` | 55        |
| `live_type11_b4210163b0.js` | 53        |
| `live_type11_f1abef9231.js` | 52        |

Comuns aos quatro: **38**. A palavra `modernizr` aparece literalmente no script
(usada como chave de teste do `localStorage`). Nomes recuperados incluem
`applicationcache`, `csstransforms3d`, `cssvminunit`, `csspointerevents`,
`sharedworkers`, `svgfilters`, `websqldatabase`, `touchevents`, `getusermedia`,
`webgl`, `indexeddb`, `geolocation`.

_Ressalva de cobertura:_ meu extrator pega **a primeira** chamada por função,
numa janela fixa. Os números são **piso**, e a variação entre deploys é
provavelmente artefato meu, não remoção de testes pela F5. Não afirmo que a
lista muda por deploy.

##### R31.4 — Não há empacotamento de bits em nenhum dos scripts `[FACT]`

| operador | `type_11` | `type_12` | `type_17` |
| -------- | --------- | --------- | --------- |
| `1<<`    | 0         | 0         | 0         |
| `\|=`    | 1         | 0         | 1         |
| `&=`     | 1         | 0         | 2         |
| `%8`     | 0         | 0         | 0         |

Os poucos `<<` existentes são todos identificados: XTEA (`s<<4^s>>>5`), troca de
endianness (`OJ`), hash djb2 (`s=(s<<5)-s+S`) e montagem de inteiro big-endian.
**Nenhum é empacotamento de flags.**

> Refuta a leitura mais natural: os ~57 booleanos **não** são empacotados
> 1-bit-por-feature por estes scripts. Ou o empacotamento usa aritmética que não
> reconheci, ou acontece fora deles, ou a máscara não é o vetor de features.

##### R31.5 — Onde a hipótese fica

`HYPOTHESIS`, **não confirmada e agora sob pressão**: que a máscara de 16 bytes
codifique o vetor de feature-tests.

A favor: o script mede dezenas de capacidades de ambiente; a máscara é vetor de
flags (R31.2) e acompanha o ambiente (R22.4); um bit separa contêiner de local.

Contra: a aritmética não fecha (≈57 testes × 128 bits) e **não existe
empacotador** (R31.4).

O teste que decidiria, ainda offline: medir quantos dos ~57 testes são falsos no
nosso ambiente. Se forem **13**, casa; se forem 3 ou 30, cai. Não foi feito —
está fora do orçamento declarado desta revisão e exige reimplementar as detecções,
o que traz risco próprio de erro de medida (§9.3-R30.6).

##### R31.6 — Nota de método

Esta é a primeira revisão do estudo em que o orçamento foi fixado **antes** de
abrir o material e **respeitado no fracasso**. As §9.3-R17/R29/R30 registraram
falhas de verificação; esta registra o oposto — uma caçada que não achou o alvo
e parou onde disse que pararia, em vez de virar busca aberta.

Os três fatos colaterais (R31.2, R31.3, R31.4) valem por si e não dependem da
hipótese que motivou a caçada.

---

#### §9.3-R32 — As capacidades que a F5 mede não discriminam o perfil, e separam os ambientes só por `webgl` (2026-09-09)

Sequência do §9.3-R31.3: com a lista de feature-tests extraída do `type_11.js`,
mediu-se o que a **própria F5** mede, nas quatro células. `exp_capacidades.py`,
**zero sessões CADESP** — roda em `about:blank` e sai.

##### R32.1 — O cruzamento que motivou o experimento `[FACT]`

```
campos medidos pelo NOSSO probe (FULL_FP_JS) : 48
capacidades medidas pela F5 (type_11.js)     : 74
INTERSEÇÃO                                   :  2
```

E as duas são frágeis: `time` é casamento espúrio de substring, e `webgl` nós
medimos como _identidade_ (renderer, vendor, extensões) enquanto a F5 testa
_presença_.

Os inventários medem eixos quase disjuntos: o nosso mede **atributos de
identidade** (quem o navegador diz ser), o da F5 mede **superfície de API** (o
que ele sabe fazer). Isso reenquadra §9.3-R12, §9.3-R15.4 e §9.3-R23.1 — as três
concluíram "a explicação não está nos campos do probe", e agora se vê que o
probe nunca olhou o eixo do ambiente.

##### R32.2 — Fidelidade das detecções

Não foram escritas de memória. Após a desofuscação (§9.3-R31.3), os corpos foram
renderizados e transcritos. Verbatim do script:

```
applicationcache   "applicationCache" in window
cors               "XMLHttpRequest" in window && "withCredentials" in new XMLHttpRequest
contextmenu        "contextMenu" in <el> && "HTMLMenuItemElement" in window
borderradius       zZ("borderRadius", "0px")
scriptasync        "async" in createElement("script")
```

Helpers reimplementados: `s1.Oi` → `prefixado()`, `s1.zZ` → `propCss()`,
`s1.SS` → elemento de teste.

##### R32.3 — Instrumento validado antes de medir `[FACT]`

Duas baselines idênticas, em cada ambiente, antes de qualquer comparação
(§9.3-R30.6):

```
capacidades medidas   : 80
INSTÁVEIS (excluídas) :  0
```

Nenhuma capacidade variou entre baselines idênticas — em contraste direto com
`fonts` e `voices` (§9.3-R30.4), que variavam mais que a manipulação. **Este
instrumento mede o que diz medir.**

##### R32.4 — Resultado: o perfil de SO não muda a superfície de API `[FACT]`

|             | local          | contêiner      |
| ----------- | -------------- | -------------- |
| **macos**   | 11 falsas / 80 | 12 falsas / 80 |
| **windows** | 11 falsas / 80 | 12 falsas / 80 |

```
capacidades que diferem macos x windows, no local     : 0
capacidades que diferem macos x windows, no contêiner : 0
```

> Das 80 capacidades que a F5 mede, **nenhuma** distingue os perfis `macos` e
> `windows`, em nenhum dos dois ambientes.

Isto **fecha este eixo para a metade "perfil" do H-CONJ′**. O que separa os
perfis é identidade declarada (UA, §9.3-R20.3), não capacidade.

##### R32.5 — Ambiente: uma única capacidade separa, e é a já refutada `[FACT]`

As listas de falsas são idênticas item a item, exceto por um elemento:

```
local     : applicationcache, contentsecuritypolicy, contextmenu, cssgradients,
            cssreflections, getusermedia, localstorage, regions, stylescoped,
            time, websqldatabase                                        (11)
contêiner : as mesmas 11  +  webgl                                      (12)
```

> `webgl` é a **única** das 80 capacidades que separa contêiner de local.

E o §13.1 já registra, por experimento direto: _"Ausência de WebGL **não** basta
para bloquear — GPU real + `webgl.disabled` + perfil windows → ACCEPTED (R13.2)"_.

**Consequência dura:** o eixo que eu apontei como o de maior rendimento devolve,
sobre o desfecho, exatamente nada de novo. A única capacidade discriminante já
estava eliminada desde o §9.3-R13.

##### R32.6 — Mas a hipótese da máscara ficou MAIS forte, não menos `[HYPOTHESIS]`

O §9.3-R31.5 deixou a hipótese sob pressão. Este experimento a reforça:

|           | bits zerados na máscara          | capacidades falsas medidas |
| --------- | -------------------------------- | -------------------------- |
| local     | 13                               | 11                         |
| contêiner | **14** (`f7`→`f6`, 1 bit a mais) | **12** (1 a mais)          |
| delta     | **+1**                           | **+1**                     |

O **delta bate exatamente**, e os valores absolutos ficam a 2 de distância —
compatível com a minha sonda medir 80 itens contra os ~74 do deploy, e com os
artefatos do `about:blank` (R32.7).

Predição concreta e falsificável que isso gera:

> O bit que separa contêiner de local — **byte 10, bit 0** da máscara — é a flag
> de **`webgl`**.

Se confirmado, a máscara é o vetor de capacidades e está **explicada**. E é uma
explicação que a encerra como linha: o bit é `webgl`, e `webgl` já foi refutado.

##### R32.7 — Limite honesto: `about:blank` não é contexto seguro

`localstorage` e `getusermedia` aparecem como falsas, e provavelmente são
**artefato**: origem opaca e contexto inseguro. O §9.3-R23.5 já havia barrado o
`mediaDevices` por esta mesma razão e o registrou como `NÃO TESTADO`.

Isto não afeta R32.4 (a comparação entre perfis é feita no mesmo contexto, e deu
zero dos dois lados) nem R32.5 (idem para os ambientes). Afeta a contagem
absoluta do R32.6 — 11 e 12 são pisos.

**Refazer sobre um servidor https local fecharia a lacuna**, ainda sem gastar
sessão. Fica declarado como o passo pendente deste eixo, não como feito.

---

#### §9.3-R33 — A máscara É o vetor de capacidades, e ele é permissivo por construção (2026-09-09)

O §9.3-R31 encerrou a caçada ao construtor sem achá-lo, sob orçamento. A
pergunta _"a telemetria é satisfeita 1:1 ou é tolerante?"_ reabriu o arquivo com
alvo diferente — o **tratamento de falha**, não o empacotamento — e o construtor
apareceu. Análise estática, **zero sessões CADESP**.

##### R33.1 — O registrador é fila, não acumulador `[FACT]`

```js
I: function(I, l, O) { jI.push({ "name": I, o$j: l, "options": O }) }
```

`.I(nome, valor, opções)` empilha. O valor pode ser função — avaliação
preguiçosa. Nenhum peso, nenhuma soma neste ponto.

O laço que drena a fila avalia e guarda:

```js
for (_ in jI) {
  l = jI[_];
  I = [l.name.toLowerCase()]; // + aliases de options.Jlj
  l = tipo(l.o$j) === "function" ? l.o$j() : l.o$j; // avalia aqui
  for (O = 0; O < I.length; O++) {
    s[I[O]] = l;
    oI.push((s[I[O]] ? "" : "no-") + I[O]);
  }
}
```

Padrão Modernizr clássico: mapa `nome → booleano` mais a lista de classes CSS
`nome` / `no-nome`.

##### R33.2 — O serializador, e a resposta à pergunta `[FACT]`

```js
I2J: function(){
  var l = [], O = [], s = Z1._IJ /*resultados*/, S = Z1.Z2J /*mapa nome→índice*/;
  for (jI in S) O[II++] = 0;
  for (var LI = 0; LI < Z1.s2J; LI++) l[LI] = 1;         // ← NASCE TODO 1
  for (jI in s)
    ... S.hasOwnProperty(jI) && (II--, _ = S[jI], l[_] = !!LI + 0, O[_] = 1);
  if (II && oZI) ... "Not found in the Modernizr feature[" + _ + "]: " + jI
  L2.iIJ = l;
}
```

> **O vetor é inicializado com 1 em todos os slots.** Um slot só vira 0 quando
> existe um teste registrado, com nome presente no mapa de índices, que retorna
> `false` explicitamente.

Slot cujo teste **não existe**, **não foi registrado**, **não rodou** ou
**lançou** permanece **1** — indistinguível de capacidade presente.

##### R33.3 — O tamanho fecha a aritmética que o §R31 não fechou `[FACT]`

```
s2J = J(691) ? 157 : 128        e      function J(I) { return 155 > I }
J(691) = (155 > 691) = false    ->     s2J = 128
```

**128 slots.** A máscara medida no §9.3-R31.2 tem **16 bytes = 128 bits**.
Coincidência exata.

Isto **resolve a objeção que eu mesmo levantei** no §9.3-R31.5 ("≈57 testes
contra 128 bits, e não há empacotador"):

- os ~57–74 testes por deploy endereçam **parte** dos 128 slots;
- os slots não endereçados ficam em 1 — e é por isso que a máscara é quase toda
  `0xFF`, com os bytes 0 e 11–15 **puros** `0xFF`: são slots sem teste;
- os 13 bits zerados são exatamente os testes que retornaram `false`.

> §9.3-R31.5 estava em `HYPOTHESIS`. Passa a **`FACT`**: a máscara de 16 bytes do
> `TS6695b38b071` **é** o vetor de capacidades do Modernizr embutido.

O §9.3-R31.4 ("não há empacotamento de bits") continua correto e não conflita: o
vetor é montado como **array de 0/1**, e a conversão para bytes acontece no
serializador TLV genérico, não com `1<<` no ponto de montagem.

##### R33.4 — Não há score do lado do cliente para capacidades `[FACT]`

O serializador produz vetor de bits puro: sem pesos, sem soma, sem limiar.

Isto **contrasta com o type=17** (§6), que tem 18 eventos suspeitos, cada um com
peso (`oZ_` = 13, `OO_` = 8), somados num campo. Comportamento é pontuado no
cliente; **capacidade não é**.

Qualquer ponderação sobre capacidades é **server-side**, e continua fora de
alcance (§13.4-Q2).

##### R33.5 — Resposta direta: a telemetria é tolerante, e mais que tolerante

A pergunta era se o que entregamos precisa casar 1:1 com o que é pedido.

> **Não é 1:1, e a tolerância é assimétrica: falhar em entregar uma capacidade é
> codificado exatamente como possuí-la.**

Ausência não é penalizada porque **ausência não é representável** neste vetor. O
canal só distingue "testei e deu falso" de "1". Um coletor que morre não deixa
rastro.

Consequência para o desfecho: o vetor de capacidades **não pode** explicar por
que algumas sessões passam e outras não — exceto pelos poucos bits que ficam 0
por teste explicitamente falso. E o §9.3-R32 mediu esses: **0 diferenças entre
perfis, 1 entre ambientes (`webgl`)**, e `webgl` já era `REFUTADO` desde o
§9.3-R13.2.

Isto **fecha o eixo das capacidades** de ponta a ponta — não por não termos
olhado, mas por o canal ser permissivo por construção.

##### R33.6 — O que isto NÃO diz

O `audio.hash = err` (§9.3-R13.4) **não está neste vetor**. Áudio, canvas, WebGL
(parâmetros), fontes e tela são coletores **separados**, com serialização
própria. O R33.5 vale para o vetor de 128 bits, não para o payload inteiro.

Como esses outros coletores tratam falha — omitem, mandam sentinela, mandam
vazio — é **pergunta distinta e ainda aberta**. É a continuação natural desta
linha, e também é análise estática.

---

#### §9.3-R34 — Dois regimes de falha no mesmo script: capacidade é invisível, coletor é sinalizado (2026-09-09)

Continuação do §9.3-R33.6, que deixou aberta a pergunta gêmea: o vetor de 128
capacidades é permissivo, mas e os **outros** coletores — áudio, canvas, WebGL,
fontes — que têm serialização própria e são justamente onde o contêiner difere?
Análise estática, **zero sessões CADESP**.

##### R34.1 — Os 33 coletores, nomeados `[FACT]`

`new Is(nome, …)` aparece 33 vezes. Os nomes são codinomes internos:

```
early  subdivision  maroon  tidy    steep     heart    cosmic  grandmother
drill  fucsia       gruesome ivory  skilled   white    salmon  orange
aqua   mauve        grey    khaki   violet    amber    scarlet teal
magenta ostrich     octarine cyan   intense   warehouse brave
```

O de **áudio é `amber`** (contém `createOscillator`, `createDynamicsCompressor`,
`createAnalyser`, `getFloatFrequencyData`). O `violet`, imediatamente antes,
coleta geometria (`width`, `height`).

##### R34.2 — O laço de drenagem `[FACT]`

```js
for (var O = [], s, II, jI = 0; jI < _I; ++jI) {
  s = sI[jI];
  II = 0;
  if (Is["cm"](s))
    try {
      II = s.gez();
    } catch (LI) {
      _("Group" + jI + " failed");
    }
  O.push(II || 0);
}
_(Jj + "unfinished groups");
```

As strings de log são César +6: `"Alioj"`→`Group`, ``"`[cf_^"``→`failed`,
`"oh`chcmb\_^aliojm"`→`unfinished groups`. A F5 **loga explicitamente** grupos que
falharam e grupos não terminados.

##### R34.3 — A sentinela de falha: `99` `[FACT]`

No construtor `Is`, o método que colhe o resultado:

```js
this[gez] = function () {
  try {
    return O();
  } catch (I) {
    return ((this.IOj = I), J(927) ? 61 : 99);
  }
};
```

Com `function J(I){ return 155 > I }`, `J(927)` é **falso** → retorna **`99`**.
O erro fica guardado em `this.IOj`.

E `O.push(II || 0)`: `99` é truthy, então **`99` entra no vetor de grupos**.

> Um coletor que lança grava a sentinela **99**. Um coletor cujo grupo não passa
> no portão `Is.cm` grava **0**. Um coletor íntegro grava o hash do valor.

Três desfechos, **todos distinguíveis** entre si e de qualquer hash legítimo.

##### R34.4 — O caso do áudio, que era a pergunta `[FACT]`

O corpo do `amber`:

```js
var s = "", S = false;                        // resultado nasce VAZIO
function l() {
  var O = window.AudioContext || window.webkitAudioContext;
  if (O != undefined) {
    ... createOscillator / createDynamicsCompressor / createAnalyser ...
    oI.onaudioprocess = function () { ... getFloatFrequencyData ... S = true; };
    s.start(0);
  }                                            // sem AudioContext: pula tudo
}
function O() { return { "audioProp": s } }     // devolve {audioProp:""} na falha
```

Se o `AudioContext` não existe, ou existe e o `onaudioprocess` nunca dispara, o
coletor **não lança** — devolve `{audioProp:""}`, cujo hash é determinístico e
diferente de qualquer hash de áudio real.

No nosso contêiner o `webaudio` é **verdadeiro** (§9.3-R32: não está na lista de
falsas), mas a renderização não conclui — o nosso probe registra `err` desde o
§9.3-R13.4. Ou seja: o caminho provável é o **hash do vazio**, não a sentinela.

##### R34.5 — Resposta consolidada: a telemetria tem DOIS regimes `[FACT]`

A pergunta era se o que entregamos precisa casar 1:1 com o que é pedido. A
resposta depende do canal, e os dois canais são opostos:

| canal                                   | o que acontece na falha     | é distinguível?           |
| --------------------------------------- | --------------------------- | ------------------------- |
| **vetor de 128 capacidades** (§9.3-R33) | slot permanece **1**        | **NÃO** — falha ≡ possuir |
| **33 grupos coletores** (este §)        | `99`, `0`, ou hash-do-vazio | **SIM**, e de três formas |

> Não é 1:1 nem uniformemente tolerante. É **permissivo onde mede capacidade** e
> **explícito onde mede conteúdo**.

Isto corrige, por precisão, a leitura que o §9.3-R33.5 poderia sugerir se
generalizada: a permissividade vale para os 128 bits, e **não** vale para o
payload inteiro. Onde o contêiner realmente difere — áudio e WebGL — a falha
**é** representada.

##### R34.6 — O que isto orienta, e o que NÃO afirma

**Orienta:** o canal onde uma diferença contêiner×local poderia chegar ao
servidor é o dos **grupos coletores**, não o das capacidades. E chega de forma
legível (`99` / `0` / hash-do-vazio), não como ausência silenciosa.

**Não afirma:** que o servidor use isso. Continua valendo o §13.4-Q2 — ler o que
é enviado nunca mostrou o servidor lendo. O §9.3-R13.2 já mostrou que ausência de
WebGL isolada **não** basta para bloquear, com GPU real; este § não reabre aquilo.

**Não afirma** tampouco que exista score sobre os grupos: o §9.3-R33.4 registrou
que não há ponderação no cliente para capacidades, e nada aqui indica pesos para
os grupos. A soma, se existe, é server-side.

**Continua aberto:** quais dos 33 grupos gravam sentinela no nosso contêiner. É
verificável in-band decifrando o vetor de grupos numa sessão de cada ambiente,
capturada no mesmo ponto do pipeline — exatamente o "caminho 2" que o §9.3-R33
havia rebaixado. Este § o **repromove**, agora com pergunta afiada: _quantos
`99`/`0` o contêiner grava a mais que o local?_

---

#### §9.3-R35 — O type=18 é a camada de anti-adulteração, e o mapa passa a ter quatro canais (2026-09-09)

Cópia completa do `type=18` (15.341 B, 293 linhas) acrescentada a `portal/TSPD/type18`.
A §5 o descrevia como _"Script auxiliar, ~9 KB"_ — a descrição menos informativa
da tabela. Ele não é auxiliar: é o **enforcement**. Análise estática, **zero
sessões CADESP**.

##### R35.1 — Detonador de DOM contra instrumentação `[FACT]`

Uma regex é montada por _char-picking_ sobre nomes de tags HTML — pega o
caractere `i` do item `i` de cada grupo:

```
"datalist,details,embed,figure,hrimg,strong,article,formaddress"
   d        e        b       u       g      g       e       r
"audio,blockquote,area,source,input"          -> alert
"canvas,form,link,tbase,option,details,article" -> console
```

Resultado, verificado: **`/debugger|alert|console/g`**. É aplicada à **própria
fonte** (`Ji.exec(ll)` coage a função a string).

Se casar, dispara `O(1)`, que percorre o DOM **recursivamente** marcando cada
elemento:

```js
l.setAttribute("data-" + "vi", O.O5()); // O5() = gerador de Fibonacci com reset
```

Não é só detecção — é **contaminação**. Corrompe a página e altera tudo que os
coletores do type=11 leem depois.

_Não nos atinge por este mecanismo:_ a varredura é sobre a fonte **dele**, não
sobre código injetado por nós. O hook do §9.3-R17 era em `document.cookie`, fora
desse alcance. Registrado sem inflar.

##### R35.2 — `alert`, `confirm` e `prompt` são sequestrados `[FACT]`

Alvos codificados em base36, decodificados: `17795081`→`alert`,
`27611931586`→`confirm`, `1558153217`→`prompt`.

```js
window[nome] = function (I, l) {
  lJ = false;
  return O(I, l);
};
window[nome].toString = function () {
  return s;
}; // o hook fica invisível
```

Serve para que um modal aberto não pareça congelamento ao watchdog do R35.3.

_Nota sobre o adversário:_ a F5 sobrescreve nativos **preservando o `toString`** —
exatamente a técnica que o §12.4/§10 classificam como evasão e que a POC não usa.
Observação factual, não recomendação.

##### R35.3 — Watchdog de timing: detector de debugger sem `debugger` `[FACT]`

```js
zJ = Sj ? 3E4 : 6E3;          // 30 s mobile / 6 s desktop
jJ = +new Date + 6E5;         // janela de 10 min
document.addEventListener("visibilitychange", ...)  // checa `isTrusted`
function ZJ() { ... zj(lJ && !oJ && JJ + zJ < I) ... }
```

Uma aba **visível** cujo JS congela por mais de **6 s** dispara. Detecção de
breakpoint por timing.

**Medimos se somos nós que produzimos esse sinal** (offline, `about:blank`):

```
macos    bloqueio_sincrono = 154,0 ms / 17,0 ms
windows  bloqueio_sincrono = 273,0 ms / 17,0 ms
limite do watchdog                     6000 ms
```

> Pior caso **273 ms** contra 6.000 ms — margem de 22×. O `FULL_FP_JS` **não**
> dispara o watchdog. `[FACT]`

É o único dos quatro mecanismos com risco plausível para a POC, e o risco está
descartado por medição, não por argumento.

##### R35.4 — É o type=18 que cria o `TS_Injection` `[FACT]`

```js
var l = document.createElement("iframe");
l.style.width = "0px"; l.style.height = "0px";
l.style.visibility = "hidden"; l.style.display = "none";
l.id = "TS_Injection";
document.body.appendChild(l);
...
runLoader = function (l) { var O = window.loaderConfig; ... l.src = O ... }
```

Confirma **na fonte** o que a §3 e a §8 traziam por dedução a partir do HAR,
inclusive o nome do iframe e a origem do `src` (`window.loaderConfig`).

##### R35.5 — O predicado opaco muda por script `[FACT]` — nota de método

```
type_11.js :  function J(I) { return 155 > I }
type_18    :  function J(I) { return  16 > I }
```

Os ternários `J(x)?a:b` só são resolvíveis com a constante **daquele arquivo**.

O §9.3-R34.3 resolveu `J(927)?61:99` com `155 > I`, do `type_11` — correto.

**Correcao de um exemplo meu:** cheguei a escrever que herdar a constante do
`type_18` daria `61` em vez de `99`. **Falso.** `155 > 927` e `16 > 927` são
**ambos** falsos, e os dois levam a `99`. O achado do R34.3 não dependia da
constante.

O risco continua real, mas a faixa importa: dois predicados só divergem para
argumentos **entre** suas constantes. `J(100)` daria `true` com 155 e `false` com
16 — e aí o ternário inverte. Como os argumentos são sorteados pelo ofuscador ao
longo de todo o arquivo, a colisão e' questão de sorte, não de segurança.

> Regra: a constante do predicado opaco é **por arquivo** e deve ser relida a
> cada script, nunca herdada. Vale para toda desofuscação futura (§9.3-R31.3).

##### R35.6 — O mapa passa a ter QUATRO canais `[FACT]`

Somando §6, §9.3-R33, §9.3-R34 e este:

| canal                       | script        | natureza na falha / no desvio                            |
| --------------------------- | ------------- | -------------------------------------------------------- |
| capacidades (128 bits)      | `type_11`     | **permissivo** — slot fica 1; falha ≡ possuir            |
| coletores (33 grupos)       | `type_11`     | **explícito** — sentinela `99`, ou `0`, ou hash-do-vazio |
| comportamento               | `type_17`     | **pontuado com pesos** (`oZ_`=13, `OO_`=8)               |
| **integridade/adulteração** | **`type_18`** | **flag booleana + detonador de DOM**                     |

Resposta consolidada à pergunta _"existe score sobre os dados coletados?"_: **há
ponderação em exatamente um dos quatro canais** — o comportamental. Os outros três
entregam sinais discretos. A agregação, se existe, é **server-side** (§13.4-Q2).

##### R35.7 — O que isto NÃO diz

Nada aqui explica bloqueio. Nenhum dos quatro mecanismos do type=18 foi observado
disparando nas nossas sessões, e o §9.3-R35.3 mostra que o único plausível está
22× abaixo do limiar. O §13.1 permanece: o discriminante conhecido é a conjunção
ambiente × perfil, e sua causa server-side segue desconhecida.

##### R35.8 — A entrega é polimórfica, e o §12.7 subestimava a velocidade `[FACT]`

Ao verificar a nota de método do R35.5, mediu-se o predicado opaco **e** a chave
de 16 bytes em todas as cópias, ordenadas por captura:

| arquivo                  | hora           | predicado     | chave de 16 B  |
| ------------------------ | -------------- | ------------- | -------------- |
| `live_type11_b4210163b0` | 07-09 17:47:28 | `z = 466 > x` | `<chave-F5-A>` |
| `live_type11_f1abef9231` | 08-09 07:41:20 | `s = 84 > x`  | `<chave-F5-C>` |
| `live_type11_a2e5e7c7ed` | 08-09 08:52:10 | `J = 16 > x`  | `<chave-F5-D>` |
| `live_type11_1614fc8cb5` | 08-09 09:00:45 | `J = 155 > x` | `<chave-F5-E>` |

Quatro capturas, **quatro predicados distintos e quatro chaves distintas**. E o
par decisivo: `a2e5e7c7ed` e `1614fc8cb5` estão a **8 min 35 s** um do outro, com
chave **e** ofuscação diferentes.

> O §12.7 registra que a chave rotaciona **"por deploy"**. Oito minutos não é
> deploy. A rotação é de **minutos**, não de entrega — é **polimorfismo de
> resposta**, e vale para a ofuscação e para a chave ao mesmo tempo.

Não é correção do fato (a chave muda, e o §12.7 acertou nisso); é correção da
**escala**, e a escala muda a prática.

**Consequência operacional:** decifrar exige o script da **mesma resposta**, não
do mesmo dia nem do mesmo deploy. O `forensic/decifrar_jar.py` já opera assim —
extrai a chave do script salvo naquela sessão — mas o comentário dele e o §12.7
descreviam a janela como muito mais larga do que ela é. Qualquer análise que
reaproveite chave entre sessões está errada por construção.

**Sobre o pareamento type_11 × type_17:** nos quatro pares capturados a 0,3 s um
do outro, os dois scripts compartilham o predicado. Nas cópias separadas por mais
tempo, não: `portal/type_11.js` (`L=368`) × `portal/type_17.js` (`J=566`), 39 s; e
`portal/TSPD/type17` (`l=502`) × `portal/TSPD/type18` (`J=16`), 5,8 s.

**CORRIGIDO no §9.3-R36.4:** o par `TSPD/type17` × `TSPD/type18` **não** e'
contraexemplo — o `type=18` tem semente própria por ser servido por outro
caminho. Com os quatro arquivos do mesmo carregamento (lote B), o quadro real e':
type=11, 17 e 20 compartilham `l=502`; só o type=18 difere. E o par do lote A
(`L=368` × `J=566`) e' de outro dia e outra consulta, sem garantia de mesmo
carregamento — sai da conta.

**Sete valores observados** ao todo: `L=368`, `J=566`, `J=155`, `J=16`, `z=466`,
`s=84`, `l=502` — nome e constante variam de forma independente.

---

#### §9.3-R36 — Confirmação em runtime do type=18, e o watchdog não bastou para bloquear (2026-09-09)

Quatro capturas de tela de uma sessão real com DevTools aberto
(`portal/prints_exec_18/`), fornecidas pelo operador. Não é experimento nosso —
é **observação de uma sessão manual**, e é tratada como tal.

##### R36.1 — A regex oculta, confirmada ao vivo `[FACT]`

O §9.3-R35.1 decodificou estaticamente a regex montada por _char-picking_. Os
prints mostram a função `ii` do `TSPD/?type=18` **pausada em breakpoint**, com o
Scope do DevTools exibindo as variáveis em construção:

| print | estado observado                                                                                                         |
| ----- | ------------------------------------------------------------------------------------------------------------------------ |
| 1     | `Ii: Array(8)` = `["datalist","details","embed","figure","hrimg","strong","article","formaddress"]`; `O: []`; `s: 0`     |
| 2     | `O: ['debugger']`; `Ii: Array(5)` = `["audio","blockquote","area","source","input"]`; `s: 1`                             |
| 3     | `O: (2) ['debugger', 'alert']`; `Ii: Array(7)` = `["canvas","form","link","tbase","option","details","article"]`; `s: 2` |

A pilha confirma o encadeamento deduzido: `ii` → `Ii` → `ll` → `(anonymous)`,
em `TSPD/?type=18:2` e `:3`.

> A decodificação estática do §9.3-R35.1 está **confirmada em execução**. Os dois
> primeiros elementos aparecem literalmente no depurador: `debugger`, `alert`.

É a primeira vez no estudo que uma leitura estática do script é verificada em
runtime, e ela bateu byte a byte.

##### R36.2 — O iframe `TS_Injection` existe, na árvore do DevTools `[FACT]`

O print 4 mostra `TS_Injection (TSPD/)` como contexto próprio no painel Page.
Confirma o §9.3-R35.4 do lado do navegador, não só do código.

##### R36.3 — Pausar o script em breakpoint NÃO bloqueou a sessão `[OBSERVATION]`

O §9.3-R35.3 documentou o watchdog: aba **visível** com JS congelado por mais de
`zJ` = 6.000 ms dispara `zj()`.

Um breakpoint congela a main thread indefinidamente. Os prints 1–3 mostram três
pausas distintas na mesma sessão. Ao retomar, a próxima chamada de `ZJ()`
compara `JJ + zJ < agora` com um intervalo muito maior que 6 s — deveria
disparar.

E o print 4 mostra a **página de consulta carregada e funcional**: formulário de
CNPJ, botões Consultar/Voltar, sem página de rejeição.

> Congelar o script muito além do limiar do watchdog **não produziu bloqueio**.

**Leitura compatível:** o flag do watchdog é _um_ sinal, não veredito — coerente
com o modelo "soma com limiar" que o §13.1 mantém como `HYPOTHESIS`, e com o
padrão já estabelecido de que nenhum sinal isolado bloqueia (§9.3-R13, R14, R15).

**O que NÃO se pode concluir:** que o watchdog seja inerte. Não sabemos se ele
disparou; só que, se disparou, não bastou. `OBSERVATION`, n=1, sessão manual sem
controle, sem braço de comparação. Não entra como refutação do §9.3-R35.3 — o
mecanismo lá é `FACT` lido na fonte; o que está em questão é a **consequência**,
e essa continua desconhecida.

**Reforça, por outro lado, o §9.3-R35.3 na parte que importa para a POC:** já
sabíamos por medição que o `FULL_FP_JS` fica 22× abaixo do limiar; agora há
indício de que mesmo ultrapassá-lo, e muito, não é decisivo.

##### R36.4 — A proveniência dos arquivos do `portal/`, e o que ela corrige

O operador registrou que os arquivos do `portal/` vêm de dias e consultas
diferentes. Os `mtime` confirmam **dois lotes**:

```
LOTE A — 2026-09-07 13:26–13:29 : type_17.js, type_11.js, type_12.js, decoded_strings.txt
LOTE B — 2026-09-09 06:57–07:04 : ScriptResource1-6, webresource, TS_Injection/*,
                                   TSPD/type17, TSPD/type18, Scripts do portal, prints
```

Predicados opacos por lote:

| lote | arquivo                          | predicado    |
| ---- | -------------------------------- | ------------ |
| B    | `TS_Injection/TSPD/TSPD-type=20` | `l = 502`    |
| B    | `TS_Injection/TSPD/type11`       | `l = 502`    |
| B    | `TSPD/type17`                    | `l = 502`    |
| B    | **`TSPD/type18`**                | **`J = 16`** |
| A    | `type_11.js`                     | `L = 368`    |
| A    | `type_17.js`                     | `J = 566`    |

> **Dentro de um mesmo carregamento (lote B), os type=11, 17 e 20 compartilham a
> semente `l=502`; o type=18 não.** `[FACT]`

Isto **corrige o §9.3-R35.8**, que listou o par `TSPD/type17` × `TSPD/type18`
como evidência _contra_ o compartilhamento por rajada. Não é: o type=18 é a
exceção estrutural — servido por outro caminho, com semente própria. O lote B,
com quatro arquivos, é evidência mais forte **a favor** do compartilhamento entre
os scripts do pipeline.

O par discordante do lote A (`L=368` × `J=566`) permanece sem explicação, e agora
sem controle: são de 07/09, de outra consulta, e não há garantia de que venham do
mesmo carregamento. Sai da conta como evidência.

**O que NÃO muda:** o núcleo do §9.3-R35.8 — rotação em escala de minutos — não
depende do `portal/`. Vem das **nossas** capturas automatizadas
(`forensic/live_type11_*.js`), com carimbo de tempo confiável, onde duas capturas
a **8 min 35 s** de distância já trazem chave e predicado diferentes.

**Consequência de método:** o §9.4 foi lido sobre `portal/type_11.js` — lote A,
07/09, deploy distinto de tudo o mais. As constantes ali (`L(x)=368>x`) são
daquela cópia e de mais nenhuma. A ressalva já foi inserida na §9.4.

---

#### §9.3-R37 — O watchdog do type=18 é inalcançável nesta cópia; o mecanismo real é integridade de motor (2026-09-09)

Correção de duas leituras minhas: o §9.3-R35.3 descreveu o watchdog de
congelamento como mecanismo ativo, e o §9.3-R36.3 interpretou a sessão com
breakpoints como _"disparou mas não bastou"_. Reler o arquivo inteiro mostra que
**nenhum caminho interno consegue satisfazer a condição de disparo**.

##### R37.1 — Três razões independentes, todas na fonte `[FACT]`

**(a) A ordem de execução.** Posições no arquivo:

```
    59   IIFE ll()        <- o tripwire; e' onde os breakpoints do §9.3-R36 estavam
  3033   bloco do watchdog
  5219   jJ = agora + janela
  6198   definicao de ZJ()
  6675   primeira chamada de ZJ()
```

A função `ii` dos prints vive dentro de `ll`, na posição 59 — **antes de o
watchdog sequer ser inicializado**. Não havia linha de base temporal para violar.

**(b) A primeira chamada de `ZJ()` não pode disparar.**

```js
jJ = +new Date + 6E5, JJ, lJ, oJ, ...     // JJ, lJ, oJ declaradas SEM valor
...
var l = zj(lJ && !oJ && JJ + zJ < I);
```

Com `lJ === undefined`, o `&&` curto-circuita antes de qualquer comparação. E
ainda que não curto-circuitasse: `JJ` é `undefined`, e `undefined + 6000 < I`
avalia `NaN < I` → **falso, sempre**.

**(c) O caminho do `visibilitychange` também não pode.**

```js
visible -> (JJ = +new Date, oJ = !1, ZJ())
```

`JJ` é redefinido para _agora_ **antes** da chamada. Dentro de `ZJ()`, a
comparação vira `agora + 6000 < agora` → falso, sempre.

O terceiro ponto de entrada, `il(I)`, é **declarado e nunca chamado**, e está no
escopo da IIFE — inalcançável de fora.

##### R37.2 — O que a trava `lJ` realmente mede `[FACT]`

```js
lJ ||
  ((lJ = !0),
  setTimeout(function () {
    lJ = !1;
  }, 1));
```

`lJ` só permanece `true` se um timer de **1 ms não conseguiu rodar** — isto é, se
o event loop ficou bloqueado _enquanto o JS seguia executando_.

A confirmação está no §9.3-R35.2: o `SJ()` sequestra `alert`/`confirm`/`prompt`
justamente para setar `lJ = false`. Modais travam o loop legitimamente e por isso
são liberados. Isso fixa o significado da trava.

> O alvo é **bloqueio síncrono do event loop** — busy loop, XHR síncrono,
> `debugger;` dentro de laço. Uma pausa de DevTools é invisível: ela **congela o
> próprio detector**, e ao retomar o timer atrasado dispara primeiro, limpando a
> trava.

##### R37.3 — O mecanismo real: quatro asserções de integridade `[FACT]`

O que de fato pode derrubar a flag `Oj` neste script são quatro `zj(...)` com
argumento não-temporal:

| asserção                                         | derruba a flag quando                            |
| ------------------------------------------------ | ------------------------------------------------ |
| `sj["name"] === sj`                              | `Function.prototype.name` foi adulterado         |
| `typeof ie9rgb4 !== "function"`                  | a função-canário foi removida antes do `finally` |
| `RegExp("<").test(f1) & !RegExp("x3d").test(f2)` | ver abaixo                                       |
| `!1 !== window.pPL`                              | o script executou **duas vezes** na mesma janela |

A terceira é a mais fina. Com `f1 = function(){ return "\x3c" }` e
`f2 = function(){ return "'x3'+'d';" }`, o resultado por caso:

```
motor fiel (fonte preservada)      : false & !false = 0  -> nao derruba
motor que normaliza escape E dobra : true  & !true  = 0  -> nao derruba
normaliza escape, NAO dobra        : true  & !false = 1  -> DERRUBA
nao normaliza, dobra               : false & !true  = 0  -> nao derruba
```

> Só derruba num motor que **resolve `\x3c` → `<` no `toString` mas não dobra a
> concatenação `'x3'+'d'`**. É assinatura de instrumentação específica, não de
> depuração genérica.

São, portanto, checagens de **integridade do motor JS e de re-execução** — não de
tempo.

##### R37.4 — O que isto corrige

- **§9.3-R35.3** permanece correto na leitura da fórmula e na medição do
  `FULL_FP_JS` (273 ms contra 6.000 ms), mas estava **incompleto**: descrevia um
  limiar que, nesta cópia, nenhum caminho alcança. A medição continua útil como
  margem de segurança; o mecanismo não é o risco que eu supus.
- **§9.3-R36.3** dizia _"se disparou, não bastou"_. Errado: **não disparou**. A
  sessão com breakpoints não é evidência sobre o peso do sinal — é evidência de
  que o sinal não existe por aquele caminho. Retirada como apoio ao modelo "soma
  com limiar"; o §13.1 mantém aquela hipótese pelas evidências anteriores, não
  por esta.

##### R37.5 — Ressalva de cópia única

Foi lida **uma** cópia do `type=18` (lote B, 2026-09-09, §9.3-R36.4). Com a
entrega polimórfica do §9.3-R35.8 — ofuscação e chave mudando em escala de
minutos — outro deploy pode ligar o `il()` ou reordenar a inicialização.

O achado é sobre **esta** cópia. Generalizá-lo exigiria comparar o `type=18` de
outras capturas, o que não temos: é o único `type=18` no corpus.

---

#### §9.3-R38 — O vetor dos 33 grupos vai para o `TS00000000074`, e ele é 49% zeros no contêiner (2026-09-09)

Trilha B1: descobrir **em qual cookie** o vetor de grupos coletores (§9.3-R34)
acaba, antes de gastar sessão procurando no lugar errado. Análise estática,
**zero sessões CADESP**.

##### R38.1 — O caminho completo, do coletor ao cookie `[FACT]`

O registro de coletores é o objeto `js`; o método que drena a fila é `js.get()`
(§9.3-R34.2). Seguindo o consumidor:

```js
function O(l) {
  var O = [ 2017112100, 0, "", Ss.get(), activeGroups, js.get(), jI ];
  s() && … && (l = localStorage[…]) && l.length < 1500 && (O[1] = 1, O[2] = oL.IJ(l));
  return Sl.Lz(O, oI)                       // serializa com schema
}

function S(l, S, _) {
  …
  LI = _z.SLj();                            // prefixo do nome  ("TS")
  jI = jz.Oo(8, l[…], 16);                  // 8 digitos hex
  oI = _z.so( J(839) ? 91 : 74 );           // sufixo de 3 digitos
  Oj = LI + jI + oI;                        // NOME do cookie
  LI = oL.seal( O(l), ":=" );               // sela o payload
  _z.Sjj( Oj, S + LI, 0 );                  // grava
  …                                          // depois: GET /TSPD/?type=<N>
}
```

E a gravação é cookie, confirmado:

```js
Sjj: function (I, l, O) { … _z.JJ( I + "=" + l + O + "; path=/" ) }
so:  function (I) { I += _z.Jzj(); return jz.Oo(3, I, 10) }   // 3 digitos decimais
```

##### R38.2 — O nome resolve para `TS…074` `[FACT]`

`J(839)` com `J(I) = 155 > I` é **falso** → `_z.so(74)` → sufixo `"074"`.
Nome = prefixo + 8 hex + `074`.

> O payload que contém `js.get()` é escrito no **`TS00000000074`** — exatamente o
> cookie transiente do §9.3-R25, do qual temos **7 capturas de contêiner**.

Estávamos olhando o cookie certo. A Trilha A não precisa mudar de alvo.

##### R38.3 — A estrutura do payload de 280 bytes `[FACT]`

Sete campos, nesta ordem:

| #   | conteúdo                                                        |
| --- | --------------------------------------------------------------- |
| 0   | `2017112100` — constante de versão                              |
| 1   | flag: `localStorage` disponível                                 |
| 2   | conteúdo do `localStorage` (até 1500 chars) ou `""`             |
| 3   | `Ss.get()` — outro registro                                     |
| 4   | `activeGroups`                                                  |
| 5   | **`js.get()` — o vetor dos 33 grupos coletores**                |
| 6   | `jI` — um número pequeno por grupo (`s % 80 + 2·(versão % 80)`) |

Isto **reenquadra o §9.3-R30.5**, que mapeou bytes soltos (SO em 91-94/145-146,
`cores` em 127-128, tela em 182) sem conhecer a estrutura. Aqueles offsets agora
podem ser atribuídos a campos.

##### R38.4 — Cada grupo vale um inteiro de 32 bits, e falha vazia vira `0` `[FACT]`

```js
Oj: function (I, l) {
  if (!I) return l;                                   // l default = 0
  switch (typeof I) { case "string": break;
                      case "object": I = JSON.stringify(I); break;
                      default: I = "" + I }
  for (So = 0; So < I.length; So++) { S = I.charCodeAt(So); s = (s << 5) - s + S; s &= s }
  return Math.abs(s + l)
}
```

djb2 de 32 bits, com `Math.abs`. E a primeira linha é o que importa: **valor
falsy → `0`**.

##### R38.5 — Nenhuma sentinela `99` nos 7 payloads de contêiner `[FACT]`

Busca por `00 00 00 63` e `63 00 00 00` nos sete payloads decifrados: **nenhuma
ocorrência**.

Coerente com o §9.3-R34.4: o coletor de áudio **não lança** — devolve
`{audioProp: ""}`, que é objeto truthy, vira `JSON.stringify` e produz hash real.
A sentinela `99` cobre coletor que **explode**, e nenhum explodiu nas nossas
sessões.

_(Correção de rota: minha primeira busca procurou um `0x63` solto e achou um em
todas as sessões no offset 125. Com o slot sendo inteiro de 32 bits, aquilo era
coincidência de um byte dentro de outro valor, não sentinela. Descartado.)_

##### R38.6 — 49% do payload é zero, e a codificação é de tamanho variável `[FACT]`

```
payload      : 280 bytes
bytes zero   : 138 (49%)
faixas       : 74-90, 96-114, 129-134, 147-154, 159-170, 175-178,
               201-234, 236-243, 245-250, 252-258, 260-276
```

**Idênticas nas sete sessões de contêiner.**

As faixas **não** se alinham a 4 bytes (4 de 11 têm tamanho múltiplo de 4). Logo
o `Sl.Lz` não emite inteiros de largura fixa — usa **codificação de tamanho
variável**.

> Isto reconcilia o §9.3-R30.2, que sempre me incomodou: mudar a tela moveu **1**
> byte e mudar `cores` moveu **2**. Não são campos de larguras diferentes — são
> valores pequenos ocupando poucos bytes num encoding varint.

##### R38.7 — O que isto decide sobre a Trilha A

A pergunta do §9.3-R34.6 era vaga: _"quantos `99`/`0` o contêiner grava a mais?"_.
Agora é precisa e tem instrumento:

> **Medida:** fração de bytes zero no `TS00000000074`.
> **Contêiner:** 49% (138/280), estável em 7 sessões.
> **Falta:** o valor local. Nunca capturamos o `074` fora do contêiner — ele é
> transiente e os snapshots locais são de fim de sessão (§9.3-R25).

**Predições, registradas antes:**

- local também ≈ 49% → a degradação do ambiente **não** é visível neste canal, e
  o eixo dos coletores fecha como os anteriores;
- local sensivelmente menor → **o ambiente degradado é visível num canal que
  sabemos ler**, e seria a primeira vez no estudo.

**Custo:** uma sessão local com o `exp_074.py`, que já existe e capturou 4/4
(§9.3-R25). Não provoca bloqueio; o desfecho não é o objeto e não será
interpretado.

`REGRA DE PARADA`: uma sessão. Se o resultado for ambíguo, **não** emendar uma
segunda "para confirmar" — seria busca, não experimento.

---

#### §9.3-R39 — Oito bytes do `TS00000000074` separam contêiner de local (2026-09-09)

Trilha A do §9.3-R38.7, com a predição registrada antes: medir a fração de zeros
do `TS00000000074` numa sessão **local** e comparar com os 49% do contêiner.

##### R39.1 — Duas sessões, e a primeira foi perdida pelo instrumento

A primeira sessão local (`A1L`) rodou o pipeline completo (type=13 → type=14) e
capturou **zero** ocorrências do alvo. Diagnostiquei mal na hora: comparei a
janela `type=13 → type=14` e vi que a local era **mais larga** (2 s) que a do
contêiner (<1 s, mesmo segundo), e concluí que não era timing.

Errado — a janela relevante é outra. Com o diagnóstico de jar acrescentado, a
segunda sessão (`A2L`) mostrou:

```
07:50:19   TS01ec2f54, TS0eaa…027, TS6695…029, TS6695…077
07:50:20   TS00000000074, TS00000000076, …          <- aparece
07:50:20   TS00000000076, …                          <- ja sumiu
```

**Janela sub-segundo**, entre duas amostras consecutivas de 150 ms. A primeira
sessão foi azar, não diferença de ambiente.

_Correção acrescentada ao instrumento:_ captura pelo cabeçalho `Cookie` das
requisições de saída (`request.all_headers()`), que é como a timeline forense
sempre viu o cookie — não depende de acertar a janela. Ficou como caminho
redundante ao amostrador.

**Nota de método:** eu quase registrei "o `074` não existe localmente". Não
registrei porque conferi antes: o cookie aparece em **8 timelines locais** do
corpus. Foi a checagem, não a sorte, que evitou o quinto falso negativo da série
§9.3-R19.2/R30/R32.

##### R39.2 — A medida `[FACT]`

| sessão       | ambiente  | bytes | zeros           |
| ------------ | --------- | ----- | --------------- |
| A1, A2, C, D | contêiner | 280   | 138 (49,3%)     |
| B, E, E2     | contêiner | 280   | 139 (49,6%)     |
| **A2L**      | **local** | 280   | **130 (46,4%)** |

O contêiner é notavelmente estável: 138–139 em sete sessões, com perfis e telas
diferentes entre elas. O local cai fora dessa faixa por 8.

##### R39.3 — E os 8 bytes são contíguos `[FACT]`

A contagem sozinha valeria pouco (n=1 local). O mapa vale mais:

```
ZERO em 7/7 do conteiner e NAO-ZERO no local : 8 bytes, offsets 99-106
   valores no local                          : 83 b5 f2 27  ea 85 c6 43
ZERO no local e nao-zero em nenhum conteiner : 0 bytes
```

> Não é ruído distribuído. É **um bloco contíguo de 8 bytes**, e a assimetria é
> total: nada zera no local que não zere no contêiner.

Oito bytes contíguos = **dois valores de 32 bits**. Pelo §9.3-R38.4, cada grupo
coletor vale um inteiro de 32 bits, e `iZ.Oj` devolve **0** quando o valor
coletado é falsy.

##### R39.4 — A leitura, e o que ela ainda não é `[HYPOTHESIS]`

> **Dois grupos coletores produzem valor no host local e nada no contêiner.**

Os candidatos óbvios são **WebGL** e **áudio** — as duas capacidades que o estudo
já sabe degradadas no contêiner (§9.3-R32.5: `webgl` é a única das 80 capacidades
que difere entre os ambientes; §9.3-R13.4: `audio.hash = err`).

O encaixe é bom demais para eu tratar como estabelecido. O que falta:

1. **n=1 no local.** A série §9.3-R19.2 registra quatro hipóteses minhas nascidas
   de n=1 e refutadas no teste seguinte. Esta não tem status melhor.
2. **Não provei que 99-106 pertencem ao campo [5]** (o vetor de grupos). Sei que
   o campo existe (§9.3-R38.3); não mapeei suas fronteiras de byte.
3. **Atribuir os dois slots a WebGL e áudio é inferência por eliminação**, não
   observação.

##### R39.5 — O teste que decidiria

Braço local com **WebGL desligado** e o resto idêntico:

- se **4 dos 8 bytes** zerarem → o slot é o do WebGL, e a leitura se confirma;
- se os **8** zerarem → WebGL e áudio dependem do mesmo grupo, ou o corte é outro;
- se **nenhum** zerar → os 8 bytes não são WebGL, e a hipótese cai.

Custo: uma sessão local. O §9.3-R13 já rodou "GPU real + `webgl.disabled`" e
registrou ACCEPTED, mas capturava o jar ao fim da sessão — não tinha o `074`.

`REGRA DE PARADA`: um braço. E antes dele, **uma replicação do local sem
alteração** — sem saber se 130 se repete, o braço com WebGL desligado não tem
contra o que ser comparado.

##### R39.6 — O que isto significa para o estudo

É a **primeira vez** que um trecho do payload separa contêiner de local com
assinatura limpa: contíguo, todo-ou-nada, e estável do lado do contêiner (7/7).

Todo o resto do estudo eliminou canais: TLS, HTTP/2, headers, fontes, rotação de
cookies, as 80 capacidades, o vetor de 128 bits. Este é o primeiro que **não**
foi eliminado.

**E continua sem dizer nada sobre o desfecho.** Mostra o que é _enviado_
diferente, não que o servidor leia ou pondere. O §13.4-Q2 permanece aberto, e o
§9.3-R13.2 já mostrou que ausência de WebGL isolada, com GPU real, **não** basta
para bloquear.

---

#### §9.3-R40 — Os 8 bytes são o WebGL, e o payload do contêiner é reproduzido exatamente ao desligá-lo (2026-09-09)

Braço pré-registrado no §9.3-R39.5. Sessão local com `block_webgl=True` e todo o
resto idêntico às baselines locais.

##### R40.1 — Verificação da manipulação, ANTES da sessão `[FACT]`

Disciplina do §9.3-R30.6, com duas baselines idênticas primeiro:

```
baseline-1     sonda=True   ctx=True   ext=27   renderer=Radeon R9 200 Series
baseline-2     sonda=True   ctx=True   ext=27   renderer=Apple M1
block_webgl    sonda=False  ctx=False  ext=0    renderer=None
```

As baselines concordam entre si (a sonda mede _presença_, e o renderer sorteado
por lançamento não a perturba). E in-band, na própria sessão:

```
validade: webgl obtido='False' esperado='False'
```

##### R40.2 — O resultado `[FACT]`

| sessão | ambiente             | zeros / 280 | offsets 99-106                |
| ------ | -------------------- | ----------- | ----------------------------- |
| A1…E2  | contêiner (n=7)      | 138–139     | `00 00 00 00 00 00 00 00`     |
| A2L    | local, base          | 130         | `83 b5 f2 27 ea 85 c6 43`     |
| A3L    | local, base          | 131         | `3a 87 75 17 71 64 54 14`     |
| **W**  | **local, WebGL OFF** | **138**     | **`00 00 00 00 00 00 00 00`** |

Desligar o WebGL num host local reproduz a **contagem exata** do contêiner.

##### R40.3 — E o mapa de nulidade é idêntico, byte a byte `[FACT]`

Analisando por **nulidade** em vez de valor (imune ao hash variar por sessão):

```
nao-zero nas 2 locais e ZERO no braco WebGL-off  : [99..106]
nao-zero nas 2 locais e ZERO em 7/7 conteiner    : [99..106]

mapa_de_zeros(W) == mapa_de_zeros(conteiner) ?   True
   zero so no W (e nao no conteiner) : nenhum
   zero so no conteiner (e nao no W) : nenhum
```

> **Toda** a diferença legível entre contêiner e local no `TS00000000074` é o
> WebGL. Nenhum outro byte difere, em nenhuma direção, em 280 bytes.

##### R40.4 — A predição errou, e o erro é informativo

O §9.3-R39.5 previa três desfechos. Saiu o segundo — **os 8 zeraram**, não 4.

Consequências:

1. **Os dois `int32` em 99-106 são ambos do WebGL** — um grupo com dois valores,
   ou dois grupos ambos dependentes de contexto WebGL. Não é "um slot de WebGL e
   um de áudio".
2. **O áudio não está nesses 8 bytes.** Confirma o §9.3-R34.4 pelo lado do dado:
   o coletor `amber` não devolve falsy quando falha — devolve `{audioProp: ""}`,
   que é objeto truthy, vira `JSON.stringify` e produz hash real. Um áudio que
   não renderiza **não zera nada**.
3. Portanto o `audio.hash = err` (§9.3-R13.4), que o §13.1 listava como _"o único
   sinal ainda observável no fingerprint que distingue os ambientes"_, **não é
   observável neste payload**. Ele existe na nossa medição; não chega ao servidor
   como ausência.

##### R40.5 — Correção de um erro meu de análise

Na primeira passagem calculei os candidatos subtraindo um conjunto de "ruído"
definido como _bytes que diferem entre as duas baselines locais_ — e o resultado
veio **vazio**.

O erro: os offsets 99-106 diferem entre A2L e A3L justamente porque o hash do
WebGL varia por sessão. Subtrair o "ruído" apagou exatamente o sinal.

A análise correta compara **nulidade**, não valor. É uma armadilha genérica:
quando o sinal é "o campo existe ou não", filtrar por variabilidade de valor
descarta o campo mais informativo do conjunto.

##### R40.6 — O eixo dos coletores fecha, e desta vez por identificação positiva

O §9.3-R38 abriu este eixo perguntando quanto o contêiner "entrega a menos". A
resposta completa:

> Entrega a menos **exatamente 8 bytes**, e eles são o WebGL.

Isso é diferente de todos os fechamentos anteriores do estudo, que foram
eliminações (TLS, HTTP/2, headers, fontes, rotação, as 80 capacidades, o vetor de
128 bits). Aqui houve **identificação**.

E converge com o §9.3-R32.5, que por um canal independente — medir as 80
capacidades que a F5 mede — achou `webgl` como a única que separa os ambientes.
Dois métodos, mesma resposta.

**Mas não explica o desfecho, e isto é decisivo:** o §9.3-R13.2 já rodou
"GPU real + `webgl.disabled` + perfil windows" e registrou **ACCEPTED**. Ou seja,
produzir exatamente este payload — com os 8 bytes zerados — **não basta para
bloquear**.

> O canal está agora completamente caracterizado, e caracterizá-lo mostrou que
> ele não é o discriminante.

##### R40.7 — O que resta

Com este fechamento, todos os canais observáveis do lado do cliente foram
varridos: identidade declarada, capacidades, coletores, rede, comportamento
(parcial), integridade. O §13.4-Q2 — _o servidor de fato lê e pondera isto?_ —
permanece a pergunta que o instrumento não alcança.

---

#### §9.3-R41 — Cinco bytes separam os ambientes e NÃO são WebGL; correção ao §9.3-R40 (2026-09-09)

O §9.3-R40.3 afirmou: _"toda a diferença legível entre contêiner e local no
`TS00000000074` é o WebGL. Nenhum outro byte difere, em nenhuma direção."_

**A afirmação estava errada, e o erro foi de método.**

##### R41.1 — O erro: comparei nulidade e generalizei para valor

A análise do §9.3-R40.3 comparou **mapas de zeros**. Nisso ela está correta: o
mapa de nulidade do braço local-sem-WebGL é idêntico ao do contêiner, byte a
byte.

Mas _"nenhum outro byte difere"_ é afirmação sobre **valor**, e eu nunca a testei.
Um byte pode ser não-zero nos dois ambientes e ainda assim carregar valores
diferentes — e é exatamente onde um coletor que **falha sem zerar** apareceria
(§9.3-R34.4: o `amber` devolve `{audioProp:""}`, objeto truthy, que vira hash
real).

Ou seja: eu usei o método cego justamente para a classe de sinal que o §9.3-R34
tinha previsto.

##### R41.2 — O que a comparação por valor encontra `[FACT]`

Critério: bytes estáveis nas 7 sessões de contêiner **e** estáveis nas 3 locais
(incluindo o braço com WebGL desligado), com valores diferentes entre os grupos.

```
                     off 95     off 183-186
conteiner (7/7)        1b       9d 1d 11 32
local     (3/3)        c8       db 88 23 66
```

**Cinco bytes**, e o braço `W` (WebGL off) **não migrou** para o valor do
contêiner — fica com o local. Portanto **não são WebGL**.

`183-186` é bloco contíguo de 4 bytes: um `int32`, isto é, **um slot de grupo
coletor** (§9.3-R38.4).

##### R41.3 — Ambiente ou deploy? O controle `[FACT]`

As 7 sessões de contêiner eram de um lote antigo; as 3 locais, de hoje. Ambiente
e deploy estavam **confundidos** — os 5 bytes poderiam codificar versão de
script, não ambiente.

Controle: uma sessão de contêiner **hoje** (`A4C`), mesmo deploy das locais.

| grupo                        | off 95   | off 183-186       | off 99-106 | zeros   |
| ---------------------------- | -------- | ----------------- | ---------- | ------- |
| contêiner, lote antigo (n=7) | `1b`     | `9d 1d 11 32`     | `00`×8     | 138–139 |
| local, hoje (n=3)            | `c8`     | `db 88 23 66`     | valores    | 130–131 |
| **contêiner, hoje (n=1)**    | **`1b`** | **`9d 1d 11 32`** | **`00`×8** | **138** |

> Os 5 bytes acompanham o **ambiente**, não o deploy. E são **estáveis entre
> deploys** — dois deploys com chaves e ofuscação diferentes produzem os mesmos
> valores no mesmo ambiente.

##### R41.4 — O que isto muda no balanço

O `TS00000000074` distingue contêiner de local por **13 bytes**, em dois blocos
de natureza diferente:

| bloco       | bytes | comportamento                 | atribuição                      |
| ----------- | ----- | ----------------------------- | ------------------------------- |
| 99–106      | 8     | **zera** no contêiner         | **WebGL** — `FATO` (§9.3-R40.2) |
| 95, 183–186 | 5     | **muda de valor**, nunca zera | **`UNKNOWN`**                   |

O segundo bloco é exatamente o perfil que o §9.3-R34.4 previu para um coletor que
falha sem lançar: valor presente, valor diferente.

##### R41.5 — A hipótese, e o teste que a decide `[HYPOTHESIS]`

Candidato natural para `183-186`: o coletor de **áudio** (`amber`, §9.3-R34.1).
É `err` no contêiner e funciona no local, e nunca zera — o que casa com o padrão.

O `off 95`, isolado e a 4 bytes de distância de nada conhecido, não tem candidato.

**Teste pré-registrado:** sessão local com `dom.webaudio.enabled = false` (a
mesma manipulação do §9.3-R14), com verificação in-band antes de interpretar.

- `183-186` migram para `9d 1d 11 32` → é o slot do áudio;
- não migram → o áudio não está ali, e os 5 bytes voltam a `UNKNOWN` sem
  candidato.

`REGRA DE PARADA`: um braço. E o desfecho da sessão **não** será interpretado —
o objeto é o payload.

##### R41.6 — Nota de método

Terceira vez que uma conclusão minha cai por escolha de métrica, não por falta de
dado: §9.3-R30.3 (sonda media agregado errado), §9.3-R40.5 (subtrair "ruído"
apagou o sinal) e agora esta.

O padrão comum: **eu escolho a métrica que torna a análise fácil e depois
generalizo a conclusão para além do que a métrica mede.** A regra que faltava:

> Antes de escrever "nenhum X difere", verificar se a métrica usada consegue
> **ver** um X que difira. Nulidade não vê mudança de valor; agregado não vê
> elemento; variabilidade não vê o campo mais informativo.

---

#### §9.3-R42 — Regressão na AWS: macOS no Fargate-Spot continua passando, com POST real (2026-09-09)

Verificação do **ponto de retorno declarado** no início desta linha de trabalho —
_"podemos gastar a sessão desde que possamos voltar ao ponto onde macOS roda no
Fargate-Spot"_. Uma execução real contra o CADESP.

##### R42.1 — O que foi rodado, e sob que estado

Nada precisou ser reconstruído: a imagem no ECR é de 2026-09-02 14:57, posterior
à última alteração do caminho de nuvem (`t.py` 14:42, `config_cloud.py` 14:42), e
a task definition (revisão 12) já trazia `F5_CAMOUFOX_OS=macos`. Invocação
mínima documentada no próprio script: `-Passos 8,10`.

`deploy.ps1`, `t_cloud.py`, `config_cloud.py`, `Dockerfile` e `t.py`
**intocados** — mtimes conferidos antes e depois.

##### R42.2 — Condições e desfecho `[FACT]`

|            |                                                                           |
| ---------- | ------------------------------------------------------------------------- |
| task       | `<task-id-fargate>`, Fargate-Spot, `sa-east-1`                            |
| IP público | `<IP-AWS-10>` (AWS)                                                       |
| perfil     | `macos` — UA Macintosh, `platform=MacIntel`, `oscpu=Intel Mac OS X 10.15` |
| renderer   | **`None`** — Fargate não tem GPU (limitação registrada na §7.1)           |
| duração    | 37,6 s, 76 rotações de cookie                                             |

```
sessao_forense#1     estado_final=ACCEPTED     POST=True     BLOCK=False
T+20927   FORM_SUBMITTED -> ACCEPTED  (redirect no POST de entrada)
T+33534   PRE_POST_SNAPSHOT   estado da maquina: ACCEPTED
T+33561   POST_RESPONSE       status=200   support ID: null
T+37591   fim da rodada — estado final ACCEPTED
```

##### R42.3 — Por que este ponto vale mais que as sessões locais recentes

As sessões do §9.3-R39/R40/R41 (`A2L`, `A3L`, `W`, `A4C`) apenas **carregam a
página inicial** e esperam o pipeline assentar — nunca navegam nem submetem.
"Não bloqueou" ali é afirmação fraca, e foi registrada como tal.

Esta fez o **fluxo completo**: POST de entrada, formulário submetido, redirect de
sucesso, 76 rotações de cookie ao longo de 37,6 s. É o mesmo protocolo das
sessões que **produziram** bloqueios no corpus (§9.3-R8, R9, R12).

##### R42.4 — O que acrescenta ao corpus `[FACT]`

Célula: _ambiente de contêiner_ (Fargate, sem GPU) **+** _perfil macOS_ → ACCEPTED.
Entra no lado "sem uma das duas condições".

```
antes  (n=22) : 7/7 bloquearam x 0/15   Fisher exato p = 5,86e-06
depois (n=23) : 7/7 bloquearam x 0/16   Fisher exato p = 4,08e-06
```

A H-CONJ′ do §13.1 sai marginalmente mais forte. Não é achado novo — é
replicação — que é exatamente o que um **teste** de regressão deve produzir.

##### R42.5 — O que este ponto **não** autoriza a concluir

O ambiente da AWS é do mesmo tipo degradado do contêiner local: `renderer=None`,
sem contexto WebGL. Logo esta sessão quase certamente carregou os **8 bytes
zerados** do §9.3-R40 — e passou, com POST real.

Isso é **corroboração** do §9.3-R13.2 (GPU real + `webgl.disabled` + windows →
ACCEPTED), vinda de outro ambiente. Não é evidência nova sobre o discriminante,
por três razões:

1. **Não foi pré-inscrita como experimento.** Foi teste de regressão. Ler nela um
   resultado sobre WebGL é análise pós-hoc do desfecho que motivou a corrida.
2. **A célula já estava povoada** — o §13.1 registra macOS em contêiner com 22
   ações e 0 bloqueios. Este é mais um ponto na mesma direção, não um teste.
3. **O payload não foi capturado.** O `TS00000000074` é transiente (§9.3-R25) e o
   `t_cloud.py` tira o snapshot ao fim da sessão. Que os 8 bytes estivessem
   zerados é **inferência** a partir de `renderer=None`, não medição.

##### R42.6 — O ponto de retorno está preservado

Era a condição declarada para gastar sessões nesta investigação. Confirmada: o
caminho `deploy.ps1 → Fargate-Spot → macOS` roda e passa, sem regressão, depois
de todas as revisões §9.3-R30 a R41.

_Dívida conhecida e não paga:_ o cabeçalho do `deploy.ps1` ainda cita
_"1 execução Windows bloqueou e 4 macOS passaram: p=0.20"_, número anterior ao
§9.3-R4.1. O valor atual do corpus é p = 4,08×10⁻⁶ (R42.4). O arquivo está na
lista de preservados e a correção foi adiada por decisão do operador.

---

## 10. O que isso significa para automação legítima

Reunindo as consequências práticas de cada descoberta:

| Descoberta                         | Consequência para a automação                                                                                                                |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Render de WebGL da GPU real (§7.1) | **Precisa de GPU real** — navegador headful numa máquina com GPU. Headless sem GPU é detectado.                                              |
| `isNative` (§7.2)                  | **Não sobrescrever nenhuma função nativa.** Nada de stealth plugin.                                                                          |
| `navigator.webdriver` (§7.2)       | Desligar **por flag do navegador** (`--disable-blink-features=AutomationControlled`), não por JavaScript.                                    |
| `isTrusted` (§6)                   | Usar a API de input do Playwright (`page.mouse`/`page.keyboard`), que passa pelo CDP e gera eventos `isTrusted=true`. Nunca `dispatchEvent`. |
| RSD / retidão / teleporte (§6)     | Mover o mouse em **curvas** com **timing irregular** e passos pequenos.                                                                      |
| Sequência Selenium (§6)            | Não usar a interpolação linear padrão; emitir os pontos da curva manualmente.                                                                |
| Teia de cookies (§8)               | **Deixar o navegador real gerar os cookies** — não fabricá-los.                                                                              |

Essa tabela é, essencialmente, a especificação da POC.

---

## 11. Como a POC aplica cada descoberta

A POC (neste projeto) é um instrumento de observação local: carrega a página num
navegador real da sua máquina, loga todo o pipeline do F5, e deixa **você**
resolver o CAPTCHA. Cada arquivo corresponde a uma parte do estudo:

- **`browser.py`** — sobe o navegador real (`channel=msedge/chrome`, headful),
  com `webdriver` desligado por flag e **sem** nenhum override nativo. (§10)
- **`human/mouse.py`** — movimento em curvas de Bézier, timing irregular, passos
  pequenos, nunca em (0,0), pontos emitidos manualmente. Calibrado aos
  thresholds da §6.
- **`human/timing.py`** — gera intervalos de RSD alto (a §6 em código).
- **`human/typing.py`** — digitação com ritmo humano.
- **`f5monitor.py`** — intercepta a rede, classifica cada `type=` (§4), rastreia
  o nascimento e a rotação dos cookies (§8), e dá um veredito.
- **`flow.py`** — orquestra o fluxo da §9, com a pausa do CAPTCHA.

O veredito confirma o sucesso observando: o pipeline de fingerprint rodou
(type=11+12), o cookie de fingerprint se formou (>400 B), o clntcap_success foi
atingido (type=14), e os beacons type=22 responderam 200.

---

## 12. A criptografia dos cookies — verificada linha a linha

Esta seção existe para **cruzar fato e dedução**. Tudo aqui foi lido diretamente
do módulo `ii` (cripto) do type=17 — não é suposição. As referências de linha são
do script beautificado.

### 12.1 A cifra: XTEA (não AES, não custom)

O núcleo é **XTEA** — uma cifra de bloco Feistel clássica, publicada em 1997.
Confirmado por três marcas inconfundíveis no código:

- **Delta = `0x9E3779B9`** (`2654435769`, linhas 241/250) — a constante mágica
  derivada da razão áurea, assinatura do TEA/XTEA.
- **Função de round `v<<4 ^ v>>>5`** combinada com a soma (linhas 238–252) — a
  mistura exata do XTEA.
- **Bloco de 8 bytes, chave de 16 bytes** (checagens `8 != l.length` e
  `16 != I.length`, linhas 227–229). A chave vira 4 palavras de 32 bits.

**Um detalhe factual que corrige uma suposição anterior:** o loop roda **16
ciclos** (`for(Li=0; 16>Li; Li++)`), não os 32 do XTEA "de manual". É uma
variante de rounds reduzidos. Na descriptografia, a soma começa em
`delta*16 = 0xE3779B90` e desce — verificamos a aritmética, bate certo.

### 12.2 O modo: CBC com IV de 8 bytes nulos

A função `ii.SO` (linha 340) encadeia os blocos em **CBC** (Cipher Block
Chaining): decifra cada bloco de 8 bytes, faz XOR com o bloco cifrado anterior, e
usa o bloco atual como "anterior" do próximo. O **IV** (vetor inicial) tem valor
padrão `Z(38, 38,38,38,38,38,38,38,38)` → como o offset é 38, cada byte é
`38−38 = 0`: **8 bytes nulos** (linha 358). Isso é FATO, não dedução.

### 12.3 A autenticação: um HMAC NÃO-PADRÃO

A função `ii.so` (linha 416) é um HMAC — mas com uma torção. O HMAC padrão
(RFC 2104) usa os pads `ipad = 0x36` e `opad = 0x5C`. Este usa:

- **pad externo = `0x5C`** (via `Z(38,130)` → `130−38 = 0x5C`) — igual ao padrão
- **pad interno = `0x06`** (via `L(-32,38)` → `−32+38 = 0x06`) — **diferente do
  padrão `0x36`**

Ou seja: é HMAC na estrutura (`hash(key⊕opad ‖ hash(key⊕ipad ‖ msg))`), mas com
uma constante trocada, sobre uma **função de hash própria** (`ii.Sl`), com bloco
de chave de 16 bytes. É o tipo de modificação sutil que só se descobre lendo o
código — e que quebraria qualquer tentativa de replicar assumindo HMAC padrão.

### 12.4 Por que isso é útil (e por que não muda a POC)

Entender isso **valida** nosso modelo: confirma que os cookies são payloads
cifrados de verdade, com integridade autenticada, e explica por que forjá-los
"na mão" é tão frágil (bastaria errar um pad `0x06` para tudo falhar). Mas, como
discutido, **não muda a POC** — o navegador real faz toda essa cripto sozinho.
O valor aqui é de entendimento e verificação, não operacional.

### 12.5 Assinaturas de E/S e a construção Encrypt-then-MAC — VERIFICADO na fonte

As subseções acima descreviam cada primitiva isolada. Esta fecha os **contratos
de entrada/saída** e mostra **como o cookie inteiro é montado e verificado**.
Tudo aqui foi lido diretamente do módulo `ii` em `portal/type_17.js` (script
beautificado, 18.231 linhas) — as referências de linha são desse arquivo. O
"dicionário" `portal/decoded_strings.txt` confirma que `z()/Z()/L()` são apenas
**geradores de constantes por offset** (offsets `ji=7`, `O=38`), não lógica.

**Nota de revisão à §12.2:** o IV de 8 bytes nulos é o **default** de `SO`
(`S = S || Z(O,38,...)`). Os chamadores podem passar um IV próprio — de fato, o
call site da linha 1077 passa um IV explícito. Portanto: "IV default = 8 nulos;
chamadores podem fornecer o seu".

#### Contratos das funções (todos verificados, sem suposição)

| Função (linha)          | Papel                                 | Entradas                                                                          | Saída                      |
| ----------------------- | ------------------------------------- | --------------------------------------------------------------------------------- | -------------------------- |
| `ii.i$` / `ii.sJ` (770) | bloco XTEA puro                       | chave `I` (16 B), bloco `l` (8 B), `s` = flag (1 = decifra / falsy = cifra)       | bloco de 8 B               |
| `ii.SO` (1091)          | modo CBC                              | chave (16 B), dados (8·n B), callback opcional, **IV opcional** (default 8 nulos) | plaintext                  |
| `ii._O` (1120)          | orquestrador (base64 + CBC + padding) | chave, dados, `s` = flag (truthy = decifra)                                       | cookie decifrado / cifrado |
| `ii.so` (1232)          | HMAC não-padrão                       | chave `I`, mensagem `l`                                                           | tag                        |
| `ii.Sl` (1148)          | função de hash própria                | mensagem                                                                          | digest                     |

#### Helpers (aritmética pura — ignorando a "poeira" anti-tamper `Ii=""`/`("")`)

- `ii.LS(a,b)` = `(a+b) mod 2³²` — **soma 32 bits** (linha 756)
- `ii.il(a,b)` = `(a−b) mod 2³²` — **subtração 32 bits** (linha 763)
- Esse par soma/subtração é o que dá a simetria cifra/decifra do XTEA.
- `ii.l_` = _byte-swap_ de 32 bits (endianness, linha 583); `ii.IO` = bytes→palavras
  (1540); `ii.J$` = palavras→bytes; `ii.ji` = **XOR** de strings (699); `ii._l` =
  repetição de string (monta os blocos de pad do HMAC).

#### O fluxo real: Encrypt-then-MAC, com a tag prefixada

A §12 tratava as três camadas isoladas. Na fonte, a ordem em que se encaixam é
**Encrypt-then-MAC** — e isso resolve a dúvida que ficara implícita ("o HMAC
cobre o cifrado ou o claro?"):

- **Geração** (linha 2111): `Oi = ii._O(li, s, !1)` cifra o payload → depois
  `Zi = ii.so(li, Oi + Ii + Li) + Oi`: o HMAC cobre o **texto cifrado + metadados**
  (`Oi + Ii + Li`) e a **tag é prefixada** ao cifrado.
- **Verificação** (linha 2238): recomputa `ii.so(si, _I + jI + iI)`, **compara a
  tag ANTES de decifrar**, e só então `ii._O(si, _I, SI)` decifra. Tag inválida →
  `throw ""`, nada é decifrado.

Ou seja: `saída = HMAC(cifrado ‖ meta) ‖ cifrado`, verificada antes de decifrar —
o padrão seguro (Encrypt-then-MAC), com hash e ipad próprios. Isso **reforça** a
conclusão da §12.4: forjar cookies "na mão" exige acertar cifra reduzida, CBC,
base64/padding, hash próprio e o pad `0x06` — e ainda na ordem certa.

#### A origem da chave — VERIFICADO (correção de um palpite anterior)

Uma revisão anterior supôs que a chave viesse "injetada pelo escopo externo, como
parte da teia de cookies da §8". **Isso estava errado.** Rastreando o fluxo a
partir dos call sites, a chave é **estática e embutida no próprio `type_17.js`** —
`li`/`si` não são a chave, são apenas o **índice** que seleciona qual chave usar.

- Em `ii.ZJ.Jl(s, S, Ii, li)` (linha 2094) o `li` recebido passa por um seletor
  local: `li = _(li)`.
- Esse `_` (definido em `ii.ij()`, linha 2007) faz `I = S[I]` sobre uma **tabela
  de chaves** literal (linha 2047) e normaliza para 16 bytes
  (`length !== 16 && slice(0,16)`).
- A tabela tem 3 entradas — **duas chaves de 16 bytes e uma vazia**:

| Índice                  | Origem no código                     | Chave (hex) — _nesta cópia do script_ |
| ----------------------- | ------------------------------------ | ------------------------------------- |
| 0 (default, `I \|\| 0`) | literal `"<bytes da chave-F5-key0>"` | `<chave-F5-key0>`                     |
| 1                       | `""`                                 | — (vazia)                             |
| 2                       | `z(O,61,170,121,…)` decodificado     | `<chave-F5-key2>`                     |

**Qual índice cada caminho usa — VERIFICADO.** Rastreando os chamadores até
`ii.o2` (linha 1930) e `ii.L2` / `ii.oi` / `ii.lZS`:

- **Chave 0** (`<chave-F5-key0>`) é a **chave geral**: usada por `L2`, `lZS`, `oi`
  (índice default `I || 0`) e praticamente todo encrypt/decrypt/verify de payload
  e telemetria.
- **Chave 2** (`<chave-F5-key2>`) é usada **só** por `ii.o2`, exclusivamente para
  decodificar o valor do **cookie-semente `TSX010AAA`** (`II.Jz`, da família TS
  das §4/§8).
- **Índice 1** é a string vazia — slot isca, não usado.

Há ainda uma **decifra em duas camadas** no bootstrap (linhas 3005–3026):
`o2`(chave 2) desembrulha o cookie `TSX010AAA` → `II.zi`, e então `L2`(chave 0)
desembrulha isso → `II.I2`. A chave 2 protege o "envelope" da semente; a chave 0,
o conteúdo interno e todo o resto. Isso **reconecta à §8**: a seleção de chave é
atrelada a _qual_ cookie da teia, embora as chaves em si sejam literais estáticos.

Ressalva final: o F5 serve o script **renovado a cada entrega**, então esses
literais podem **rotacionar por versão** — os valores acima são os _desta_ cópia,
não constantes universais.

### 12.6 A função de hash própria `ii.Sl` — Davies–Meyer sobre XTEA — VERIFICADO

A §12.3 tratou `ii.Sl` como caixa-preta ("uma função de hash própria"). Lida na
fonte (`portal/type_17.js`, linha 1148), ela é uma **construção Davies–Meyer** —
o método clássico de transformar uma cifra de bloco em função de compressão de
mão única. Não é hash inventado do zero: é XTEA embrulhado num esquema padrão.

Ignorando a "poeira" anti-tamper (o `(function(I){…})(!Number)` do topo é chamado
com `false`, então nunca executa), a lógica real é:

1. **Padding** (`ii.iO(I, 8, 0x22)`, linha 871): completa a entrada para um
   múltiplo de **8 bytes** — esquema tipo PKCS#7, com o comprimento do padding
   guardado no último byte (o inverso é `ii.jO`).
2. **Estado inicial**: `l = "poiuytre"` (8 bytes ASCII — um _keyboard walk_,
   assinatura inconfundível de hash artesanal).
3. **Para cada bloco `m` de 8 bytes** do input:
   - **Expansão de chave**: `K = m ‖ (m ⊕ C)` → 16 bytes, onde
     `C = b7d9200d3dc66c49` (constante `z(O,221,255,70,51,99,236,146,111)`).
   - **Compressão Davies–Meyer**: `l = l ⊕ E_K(l)`, onde `E` é o bloco XTEA
     cifrando (`ii.sJ(K, l, false)`) — o bloco de mensagem vira a **chave**, o
     estado vira o **texto-claro**, e há o _feed-forward_ XOR característico.
4. **Saída**: `l` — um digest de **8 bytes (64 bits)**.

**O que isso fecha:** a §12.3 dizia "HMAC sobre função de hash própria". Agora sabemos
que essa função é `HMAC-Sl`, com `Sl = Davies–Meyer(XTEA)`. Toda a camada cripto do
type=17 se reduz, então, a **uma única primitiva** — o bloco XTEA de 16 rounds — reusada
em três papéis: cifra (CBC, §12.2), compressão de hash (Davies–Meyer, aqui) e, via a
hash, autenticação (HMAC não-padrão, §12.3). Economia de código elegante, e uma pista
de que quem escreveu conhecia construções canônicas.

**Ressalva honesta:** um digest de 64 bits é **criptograficamente fraco** (colisões
por aniversário viáveis com ~2³² trabalho). Para o propósito real — integridade
anti-adulteração de cookies gerados pelo próprio script — é "suficiente"; não é, nem
pretende ser, resistência de hash moderna. Isso não muda a POC (§12.4): o navegador
real computa tudo isso sozinho.

### 12.7 Decifração de um cookie de produção — VERIFICADO (2026-09-07)

Pela primeira vez **deciframos um cookie real** e lemos o que o F5 recebe. Isso
valida a cadeia cripto das §§12.1–12.6 **contra dados vivos**, não só contra a
leitura da fonte. Ferramental: `teste.py` (captura via hook de `document.cookie`

- salva os scripts vivos do `/TSPD/`), `forensic/f5_crypto.py` (port da cripto,
  auto-verificado) e `forensic/decrypt_live.py`.

**A chave rotaciona por deploy — §13.4-Q7 respondida: SIM.** A chave extraída do
`live_type11.js` (`<chave-F5-A>`) é **diferente** da do script
salvo (`<chave-F5-B>`). Era exatamente isso que travava a decifração: cada campanha de
captura precisa do **script vivo** junto, para casar a chave com o deploy.

**O port da §12 está correto.** Com a chave viva, os 6 cookies do deploy decifram
recuperando **padding F5 válido** (`0xFF…` + contagem) e um **contador monotônico
consistente** — prova que a aritmética (XTEA 16-rounds, CBC, padding) casa com o F5.
Não foi preciso validar via Node.

**Correção a uma leitura apressada minha:** a primeira análise disse "o cookie
inteiro é um CBC / há um header mágico". **Impreciso.** Bytes constantes no
_ciphertext_ em offsets fixos (`08`@48, `172000`@53–55, e o bloco @64–71) são
**impossíveis** dentro de um bloco de cifra (avalanche) — logo o cookie **não é
CBC monolítico**. É um **registro estruturado** com marcadores literais e campos
cifrados separados:

```
TS6695b38b077 (88 bytes):
  [0-7]    083d8fda4cab2800   prefixo literal (deploy + frame clntcap, §3/§8)
  [8-47]   40B  CAMPO A        payload cifrado (5 blocos CBC) — varia por escrita
  [48]     08                  marcador literal
  [49-52]  4B                  campo curto (varia)
  [53-55]  172000              marcador literal
  [56-63]  8B                  campo (varia)
  [64-71]  8B                  bloco constante por-deploy — serve de IV da cauda
  [72-87]  16B  CAUDA cifrada  IV=[64:71] → 00×6 + [contador] + 1d9f6a + pad(0xFF..)
```

A **cauda** decifra limpo e reproduzível: seis zeros, **um byte de contador que
cresce a cada escrita** (`8e→90→ad→b5→d2→d4` no lote — a "rotação" da §8, provável
`lo32`/sequência da §13.1), um trailer fixo `1d9f6a` e o padding. O **Campo A** são
40 bytes de **payload binário empacotado** (não texto), que varia a cada cookie.

**O que isto entrega ao estudo.** É o instrumento de diagnóstico previsto na
§13.3/§13.4: podemos **ler os campos cifrados** de cookies de produção (do deploy
correspondente). Como o payload é binário, os "campos" (§13.4-Q4) são **bytes** —
mas agora **visíveis e diffáveis**: com um par passou×bloqueio do **mesmo deploy**,
dá para diffar os plaintexts e ver _quais bytes_ mudam.

**Ressalvas honestas.** (1) Este `TS6695…` é o cookie do frame clntcap (88 B), **não**
o grande cookie de fingerprint (~528 B, §8) — o método serve para ambos, mas ainda
não capturamos o grande. (2) O layout campo-a-campo do Campo A ainda não foi
desempacotado; sabemos _onde_ ele está e que decifra, não o significado de cada byte.
(3) Nada disso muda a POC (§12.4): a decifração é **diagnóstico**, não evasão.

#### 12.7.a Client-sealed × server-sealed — nem todo cookie é decifrável (2026-09-07)

Ao ampliar o coletor para dumpar o **jar completo** (`page.context.cookies()`, que
pega HttpOnly/server-set/de-todos-os-frames), um segundo cookie clntcap
(`TS6695b38b029`, com `expires` real), o cookie domain-wide (`TS01ec2f54`) e o do
frame TS_Injection (`TS0eaa6361027`) apareceram — **invisíveis** ao hook de
`document.cookie`. Testando a decifração emergiu um padrão:

| Cookie                                    | Como foi visto                           | Decifra com a chave do script? |
| ----------------------------------------- | ---------------------------------------- | ------------------------------ |
| `TS6695b38b077` (clntcap, sessão)         | **hook** (escrito por `document.cookie`) | **SIM** (sz key0)              |
| `TS6695b38b029` (clntcap, `expires` real) | só no jar                                | **não**                        |
| `TS0eaa6361027` (frame TS_Injection)      | só no jar                                | **não**                        |
| `TS01ec2f54` (domain-wide)                | só no jar                                | **não**                        |

**A leitura:** os cookies **escritos pelo cliente** via `document.cookie` (que o hook
capta) são **client-sealed** → deciframos com a chave embutida no script. Os que só
aparecem no jar — em especial o `b029`, cujo `expires` é assinatura de `Set-Cookie` —
são **server-sealed**: selados com a **chave do servidor**, que não temos. É a
"rotação" da §8 vista por dentro: **o cliente sela alguns cookies; o servidor sela e
reemite outros.** Nenhuma das duas chaves do `sz` (key0 `<chave-F5-A>`, key2 `<chave-F5-key2>`) decifra
os do jar, sob qualquer span/IV testado.

**Nota sobre rotação de chave (refina §13.4-Q7):** a **key0 rotaciona** por deploy
(`<chave-F5-A>` vivo ≠ `<chave-F5-B>` salvo), mas a **key2 (`<chave-F5-key2>`) é
idêntica** à `ii` key2 do script salvo — ou seja, **nem toda chave rotaciona**; há
pelo menos uma constante entre deploys/módulos.

**Consequência para o cookie grande de fingerprint (~528B, §8):** só será decifrável
se for **client-written** (aparecer em `sealed_cookie_writes`, o hook). Se cair apenas
no `cookie_jar`, é server-sealed e fica **fora de alcance** sem a chave do servidor.
Distinguir os dois é o próximo teste de captura.

**Resultado do teste (2026-09-07, 3 sessões do mesmo deploy) — a decifração alcança
session-state, NÃO o fingerprint.** Deciframos o payload do `TS6695b38b077` (o único
client-sealed) em sessões que passaram e numa que bloqueou ao "voltar". O **Campo A
(40 B) muda a cada escrita** e a cada sessão — é **estado de sessão/rotação**, com um
**contador** que só incrementa; **nada nele distingue passou×bloqueou**. O cookie que
plausivelmente carrega o fingerprint — `TS0eaa6361027`, do frame **TS_Injection** — **não
decifra** com nenhuma das duas chaves do `sz` (`<chave-F5-A>`, `<chave-F5-key2>`), sob qualquer span/IV:
é **server-sealed** (ou usa chave derivada por-frame ausente do script). O cookie grande
(~528 B, §8) **não apareceu** em nenhuma das capturas deste fluxo.

**Consequência — correção de rumo à §12.7 e ao §13.3-ponto-4.** A "porta de diagnóstico"
que as chaves abriram leva a **estado de sessão**, não aos 18 campos. O conteúdo decisivo
(o fingerprint) fica atrás da **chave do servidor**, inalcançável offline. Isto **não**
enfraquece a cripto mapeada (§12 está toda verificada, o port funciona) — apenas mostra
que o cliente sela o que é **efêmero**, e o servidor guarda o que **decide**. Reforça a
§13: a decisão é irredutivelmente **server-side**, e nem a leitura das entradas (que não
temos) daria a _função_ de decisão (que nunca sai do servidor).

---

## 13. Fato vs. dedução: o balanço honesto

O que sabemos com certeza (lido no código) e o que ainda é inferência:

| Afirmação                                        | Status      | Base                                                                                          |
| ------------------------------------------------ | ----------- | --------------------------------------------------------------------------------------------- |
| Cifra é XTEA, bloco 8B, chave 16B                | **FATO**    | delta 0x9E3779B9 + round function, linhas 227–252                                             |
| 16 ciclos (rounds reduzidos)                     | **FATO**    | loop `16 > Li`, linha 246                                                                     |
| Modo CBC, IV = 8 bytes nulos                     | **FATO**    | `ii.SO`, linha 358                                                                            |
| HMAC com pad interno 0x06 (não-padrão)           | **FATO**    | `ii.so`, linha 421–422                                                                        |
| 3 frames (top / TS_Injection / clntcap)          | **FATO**    | árvore de Sources + escopo de cookies                                                         |
| Grafo de chamadas: 18→20→{11→{13,14}, 12}; 17→22 | **FATO**    | iniciador via CDP (§9.1)                                                                      |
| Módulos condicionais type=8/4/21 na retentativa  | **DEDUÇÃO** | vistos só em desafio de retry; grafo desse cenário não capturado                              |
| type=11 lê UNMASKED_RENDERER + renderiza shaders | **FATO**    | strings decodificadas do type=11                                                              |
| isNative checa ~30 nativos                       | **FATO**    | strings decodificadas do type=11                                                              |
| Não há POST de fingerprint                       | **FATO**    | HAR: todo /TSPD/ é GET                                                                        |
| TSPD_101_DID é aleatório por sessão              | **FATO**    | comparação entre duas sessões                                                                 |
| Thresholds comportamentais (RSD, retidão…)       | **FATO**    | constantes decodificadas do type=17                                                           |
| Cookie `TS…076` carrega o fingerprint            | **DEDUÇÃO** | é o maior (~528B) e nasce após a coleta; não descriptografamos o conteúdo (não temos a chave) |
| Schema de 15 campos do cookie                    | **DEDUÇÃO** | inferido do serializador `ZI`, não de um cookie decifrado                                     |
| Significado de cada cookie menor                 | **DEDUÇÃO** | inferido de nome, tamanho e timing                                                            |
| Valores espelhados = consistência cruzada        | **DEDUÇÃO** | observamos os valores iguais; o propósito é inferido                                          |

A honestidade dessa tabela é o ponto: a **mecânica** (cifra, modo, fluxo,
detecções) é fato verificável; a **semântica do conteúdo cifrado** permanece
dedução, porque nunca extraímos a chave de sessão para decifrar um cookie real —
e, dentro do escopo que combinamos, não é isso que vamos fazer.

### 13.1 A camada de DECISÃO — o balanço consolidado (revisões §9.3-R4 a R12)

A tabela acima cobre a mecânica. A pergunta "por que **esta** sessão foi
bloqueada" é outra camada, investigada nas revisões R4–R12 sobre um corpus de
**23 sessões**. Esta subseção é o **estado atual**; as revisões são a trilha de
auditoria. Quem retoma o estudo lê aqui primeiro.

#### O achado central

```
com AS DUAS condicoes (ambiente de CONTEINER  E  perfil nao-macOS) : 7/7 bloquearam
sem uma delas                                                      : 0/16
Fisher exato, n=23                                                 : p = 4,08e-06
   (n=22 / p = 5,86e-06 antes do teste de regressão na AWS, §9.3-R42 —
    nao houve regressao: a sessao PASSOU)
```

> **H-CONJ′** — o bloqueio ocorre quando coincidem **(a)** o _ambiente de
> contêiner_ e **(b)** perfil declarado não-macOS.
>
> `HYPOTHESIS` — construída **pós-hoc** sobre o corpus que a gerou (§9.3-R12.5).

**A versão anterior desta hipótese foi FALSIFICADA e a correção importa.** A
H-CONJ original dizia _"ambiente **sem WebGL**"_. O §9.3-R13 testou isso
diretamente — Windows real, GPU real, IP residencial, perfil `windows`, só com o
WebGL desligado — e a sessão **passou**. Ausência de WebGL não basta.

A antecedente volta a ser um **pacote não decomposto**. Riscado o WebGL, o único
sinal ainda observável no fingerprint que distingue os ambientes e não foi
eliminado é **`audio.hash = err`** (§9.3-R13.4); o resto do pacote —
host/kernel, conteinerização — não é visível de dentro do cliente.

> **ATUALIZADO em §9.3-R40.4 e §9.3-R41.** O `audio.hash = err` é visível na
> _nossa_ medição, mas **não chega ao servidor como ausência**: o coletor `amber`
> devolve `{audioProp:""}`, objeto truthy que vira hash real — não zera nada.
> O que de fato separa os ambientes no payload são **13 bytes**: 8 que zeram
> (WebGL, `FATO`) e 5 que mudam de valor sem zerar (`UNKNOWN`, com o áudio como
> candidato ainda não testado).

_Lição de método:_ a H-CONJ tinha p = 8,6×10⁻⁶ e ainda assim sua leitura
mecanicista estava errada. O `p` mede a improbabilidade do arranjo sob a
hipótese nula — nunca a validade da explicação proposta para ele.

#### O balanço

| Afirmação                                                                        | Status                               | Base                                                                                                                     |
| -------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| Nenhuma das duas condições basta sozinha                                         | **FATO**                             | macOS: 22 ações em contêiner, 0 bloqueios; não-macOS com GPU real: 0/3 (R12.4)                                           |
| Ausência de WebGL **não** basta para bloquear                                    | **FATO**                             | GPU real + `webgl.disabled` + perfil windows → ACCEPTED (R13.2)                                                          |
| Ausência de áudio **não** basta para bloquear                                    | **FATO**                             | GPU real + `dom.webaudio.enabled=false` + windows → ACCEPTED (R14.2)                                                     |
| Nenhuma capacidade JS degradada **isolada** basta                                | **FATO**                             | WebGL sozinho (R13) e áudio sozinho (R14): ambos ACCEPTED                                                                |
| ~~**H-CAP** — exige as duas capacidades juntas~~                                 | **REFUTADO**                         | WebGL+áudio ambos off → ACCEPTED (R15.2)                                                                                 |
| A explicação não está nos ~40 campos do probe                                    | **FATO, mas o probe era incompleto** | 20 campos diferem e ficaram de fora (R23.1)                                                                              |
| ~~`speechSynthesis` é superfície de fingerprint útil~~                           | **REFUTADO**                         | contagem varia sozinha: 118, 83, 88 (R29.4)                                                                              |
| ~~A lista de **fontes** não está no payload~~                                    | **REVOGADO**                         | a sonda contava 14 fontes genéricas; a removida (`Party LET`) não estava entre elas (R30.3)                              |
| A **geometria de tela** está no payload, 1 byte no offset 182                    | **FATO**                             | validade in-band, `0x19` em 6 sessões x `0x06` em E2 (R30.2)                                                             |
| `fonts` e `voices` são variáveis controláveis no contêiner                       | **REFUTADO**                         | valor observado não é função da config: vozes 131/96/142/123, duas baselines idênticas (R30.4)                           |
| WebGL participa da decisão no contêiner                                          | **REFUTADO**                         | não há contexto WebGL nos dois perfis (R23.2)                                                                            |
| `mediaDevices`                                                                   | **NÃO TESTADO**                      | não se manifesta em `about:blank`; exige https (R23.5)                                                                   |
| ~~Estender o probe ao `type=11`~~                                                | **DESCARTADO**                       | sem contexto WebGL nos dois lados, o probe estendido não distingue (R15/R16)                                             |
| O bloqueio tem **janela de recuperação**                                         | **FATO**                             | recuperou sozinho em dezenas de minutos, sem limpar estado (R16.2)                                                       |
| O bloqueio é carregado pelo estado do cliente                                    | **UNKNOWN**                          | testes não simultâneos; tempo não controlado (R16.3)                                                                     |
| A origem residencial foi contaminada                                             | **REFUTADO**                         | recuperação rápida, sem troca de rede (R16.3)                                                                            |
| Risco por ação do macOS ≤ 0,136 (IC 95%)                                         | **FATO**                             | regra dos três, 0 eventos em 22 ações; razão de risco ≥ 3,7× (R12.3)                                                     |
| O desfecho acompanha o pacote de perfil **em ambiente sem WebGL**                | **FATO**                             | duas origens de rede distintas (R9.2, R12.4)                                                                             |
| Em ambiente com GPU real, nenhum perfil discrimina                               | **FATO**                             | 8 sessões, p = 0,57 (R5.5)                                                                                               |
| A origem **não é necessária** para o bloqueio                                    | **FATO**                             | bloqueou do IP residencial validado 6/6 (R8.4)                                                                           |
| O bloqueio acompanha o **reuso** da sessão                                       | **FATO**                             | 1ª ação passa, 2ª bloqueia; instância nova passa 3/3 (R10)                                                               |
| Reuso e perfil são **independentes**                                             | **FATO**                             | R8 e R9 fizeram 2 POSTs cada — reuso constante, desfechos opostos (R11.1)                                                |
| A assinatura de rede não acompanha o perfil                                      | **FATO**                             | JA3, HTTP/2 e ordem de headers idênticos (R6.4, R7.3)                                                                    |
| O Camoufox fornece as fontes que declara                                         | **FATO**                             | 439 arquivos empacotados no binário (R7.2)                                                                               |
| `hi32` não depende da origem e é do lado do F5                                   | **FATO**                             | 7 bloqueios, 6 origens, mesmo valor (R5.2)                                                                               |
| ~~`hi32` é constante~~                                                           | **CORRIGIDO**                        | assume ≥ 2 valores; variou na mesma origem em minutos (R11.6)                                                            |
| Cookie/rotação discriminam o desfecho                                            | **REFUTADO**                         | R3.3                                                                                                                     |
| `lo32` é um relógio                                                              | **REFUTADO**                         | anda para trás, n=6 (R5.3)                                                                                               |
| Lista de fontes explica o desfecho                                               | **REFUTADO**                         | lista byte-idêntica, desfechos opostos (R5.4)                                                                            |
| Fontes fabricadas (HR4) explicam                                                 | **REFUTADO**                         | o Camoufox empacota as fontes (R7.2)                                                                                     |
| Coerência JS↔kernel explica                                                      | **REFUTADO**                         | o caso mais coerente bloqueou (R4.2)                                                                                     |
| Camada de rede explica                                                           | **REFUTADO**                         | R6.4 + R7.3                                                                                                              |
| O cookie de fingerprint É legível offline                                        | **FATO**                             | decifrado com a chave do deploy; contém o User-Agent literal (R17.3)                                                     |
| A identidade de SO viaja **em claro** no payload                                 | **FATO**                             | UA em ASCII literal; §13.4-Q4 respondido (R20.3)                                                                         |
| No payload legível, só o UA difere entre bloqueio e passagem                     | **FATO**                             | mesmo deploy, mesma chave, campos #0 e #2 idênticos (R20.2)                                                              |
| ~~O campo de 16B é bitmask de detecção~~                                         | **REFUTADO**                         | byte-idêntico entre bloqueio e passagem (R20.4)                                                                          |
| O campo de 16B acompanha o **ambiente**                                          | **FATO**                             | `f6` em contêiner, `f7` no local, em 10 amostras (R22.4)                                                                 |
| O campo de 16B é **vetor de flags**, não digest                                  | **FATO**                             | 13 bits zerados em 128; um hash teria ~64 (R31.2)                                                                        |
| O `type_11.js` embute registro de feature-tests **Modernizr**                    | **FATO**                             | 52–60 registros `I.I(nome,valor)` por deploy, 38 comuns aos 4 (R31.3)                                                    |
| Os booleanos são empacotados 1-bit-por-feature nesses scripts                    | **REFUTADO**                         | nenhum `1<<`, `%8` ou `                                                                                                  | =` de flags em type_11/12/17 (R31.4) |
| A máscara de 16B codifica o vetor de features                                    | **HYPOTHESIS**                       | aritmética não fecha (~57×128) e não há empacotador (R31.5)                                                              |
| Campo de 5 bytes zerados após a máscara                                          | **NÃO EXAMINADO**                    | offsets 191–195, nunca olhado (R31.2)                                                                                    |
| Nosso probe e o inventario da F5 medem eixos disjuntos                           | **FATO**                             | 48 campos x 74 capacidades, interseção 2 e ambas fracas (R32.1)                                                          |
| Alguma das 80 capacidades distingue **macos x windows**                          | **REFUTADO**                         | 0 diferenças, nos dois ambientes (R32.4)                                                                                 |
| Só `webgl` separa contêiner de local entre as 80                                 | **FATO**                             | listas idênticas exceto por 1 item; instrumento com 0 instáveis (R32.5)                                                  |
| A máscara de 16B **é** o vetor de capacidades Modernizr                          | **FATO**                             | `s2J`=128 slots e a máscara tem 128 bits; serializador lido (R33.3)                                                      |
| O vetor nasce todo **1**; só teste explicitamente falso zera                     | **FATO**                             | `for(LI=0;LI<s2J;LI++) l[LI]=1` (R33.2)                                                                                  |
| Coletor que falha e' penalizado                                                  | **REFUTADO**                         | falha deixa o slot em 1 — idêntico a possuir a capacidade (R33.5)                                                        |
| Há score de capacidades no cliente                                               | **REFUTADO**                         | vetor de bits puro, sem pesos nem soma — ao contrário do type=17 (R33.4)                                                 |
| O bit contêiner/local da máscara é a flag de `webgl`                             | **HYPOTHESIS**                       | delta de bits zerados (+1) bate com delta de capacidades falsas (+1) (R32.6)                                             |
| São 33 coletores nomeados; o de áudio é `amber`                                  | **FATO**                             | 33 `new Is(nome,…)`; `amber` contém createOscillator/DynamicsCompressor (R34.1)                                          |
| Coletor que lança grava a sentinela **99**                                       | **FATO**                             | `catch { return J(927)?61:99 }`, e `J(I)=155>I` → 99 (R34.3)                                                             |
| A falha de coletor é indistinguível de sucesso                                   | **REFUTADO**                         | três desfechos distintos: `99`, `0`, hash-do-vazio (R34.3)                                                               |
| A telemetria tem **dois regimes de falha** opostos                               | **FATO**                             | capacidade permissiva (1), coletor explícito (99/0) (R34.5)                                                              |
| O vetor dos 33 grupos e' escrito no **`TS00000000074`**                          | **FATO**                             | `Sjj(prefixo+8hex+so(74), seal(payload))`; `so(74)`→"074" (R38.1-2)                                                      |
| O payload de 280 B tem **7 campos**; o vetor de grupos e' o [5]                  | **FATO**                             | `[versao, flag, localStorage, Ss.get(), activeGroups, js.get(), jI]` (R38.3)                                             |
| Cada grupo vale um int32 (djb2); valor falsy vira **0**                          | **FATO**                             | `Oj(I,l){ if(!I) return l; … s=(s<<5)-s+S }` (R38.4)                                                                     |
| Há sentinela `99` nos payloads de contêiner                                      | **REFUTADO**                         | zero ocorrências de `00000063`/`63000000` em 7/7; nenhum coletor lançou (R38.5)                                          |
| O `TS00000000074` é **49% zeros** no contêiner                                   | **FATO**                             | 138/280 bytes, faixas idênticas em 7 sessões (R38.6)                                                                     |
| O serializador usa largura fixa de 4 bytes por grupo                             | **REFUTADO**                         | só 4 de 11 faixas de zeros são múltiplo de 4 — encoding varint (R38.6)                                                   |
| Fração de zeros do `074`: contêiner 49,4% x local 46,4%                          | **FATO**                             | 138-139/280 em 7 sessões de contêiner; 130/280 no local (R39.2)                                                          |
| Os offsets **99-106** são zero em 7/7 contêiner e não-zero no local              | **FATO**                             | bloco contíguo de 8 bytes; assimetria total, nada zera só no local (R39.3)                                               |
| Os 8 bytes (99-106) são o **WebGL**                                              | **FATO**                             | `block_webgl` local zera os 8 e reproduz 138 zeros, idêntico ao contêiner (R40.2-3)                                      |
| ~~São um slot de WebGL e um de áudio~~                                           | **REFUTADO**                         | os **8** zeraram, não 4; áudio não está nesse bloco (R40.4)                                                              |
| O `audio.hash = err` chega ao servidor como ausência                             | **REFUTADO**                         | `amber` devolve `{audioProp:""}`, objeto truthy → hash real; não zera nada (R40.4)                                       |
| O mapa de **nulidade** local-sem-WebGL == contêiner                              | **FATO**                             | idêntico byte a byte em 280 B (R40.3)                                                                                    |
| ~~Nenhum outro byte difere entre contêiner e local~~                             | **CORRIGIDO**                        | vale para nulidade, não para valor: 5 bytes diferem (R41.1-2)                                                            |
| Os offsets **95 e 183-186** separam os ambientes e **não são WebGL**             | **FATO**                             | estáveis em 7 contêiner x 3 locais; o braço WebGL-off não migrou (R41.2)                                                 |
| Esses 5 bytes acompanham o **ambiente**, não o deploy                            | **FATO**                             | contêiner de hoje, mesmo deploy das locais, reproduz os valores do lote antigo (R41.3)                                   |
| `183-186` é o slot do coletor de **áudio**                                       | **HYPOTHESIS**                       | 4 B = 1 int32; áudio e' `err` no contêiner e nunca zera; teste com `dom.webaudio.enabled=false` (R41.5)                  |
| Reproduzir o payload do contêiner basta para bloquear                            | **REFUTADO**                         | é o cenário do R13.2 (GPU real + `webgl.disabled` + windows) → ACCEPTED (R40.6)                                          |
| A janela de vida do `TS00000000074` é **sub-segundo**                            | **FATO**                             | aparece e some entre duas amostras de 150 ms (R39.1)                                                                     |
| O `type=18` é a camada de **anti-adulteração**, não auxiliar                     | **FATO**                             | detonador de DOM, sequestro de modais, watchdog e `TS_Injection` (R35)                                                   |
| Instrumentar o script detona contaminação do DOM                                 | **FATO**                             | `/debugger\|alert\|console/` sobre a própria fonte → `data-vi` em todo elemento (R35.1)                                  |
| O `FULL_FP_JS` dispara o watchdog de congelamento                                | **REFUTADO**                         | pior caso 273 ms contra limite de 6.000 ms, margem 22× (R35.3)                                                           |
| O iframe `TS_Injection` é criado pelo `type=18`                                  | **FATO**                             | confirmado na fonte; antes era dedução do HAR (R35.4)                                                                    |
| A constante do predicado opaco `J()` é **por arquivo**                           | **FATO**                             | `155 > I` no type_11, `16 > I` no type_18 (R35.5)                                                                        |
| A entrega dos scripts é **polimórfica**: ofuscação e chave rotacionam em minutos | **FATO**                             | 4 capturas, 4 predicados e 4 chaves distintas; par a 8min35s já difere (R35.8)                                           |
| Num mesmo carregamento, type=11/17/20 compartilham a semente; o type=18 não      | **FATO**                             | lote B: `l=502` nos três, `J=16` no type=18 (R36.4)                                                                      |
| A regex oculta `/debugger\|alert\|console/` foi confirmada em runtime            | **FATO**                             | DevTools pausado na função `ii`, Scope mostra `O: ['debugger','alert']` (R36.1)                                          |
| ~~Congelar o script acima do limiar do watchdog bloqueia~~                       | **PERGUNTA MAL POSTA**               | o watchdog **não disparou**: nenhum caminho interno alcança a condição (R37.1)                                           |
| O watchdog de 6 s é alcançável nesta cópia do type=18                            | **REFUTADO**                         | `JJ` indefinido na 1ª chamada (NaN) e zerado antes da 2ª; `il()` nunca chamado (R37.1)                                   |
| A trava `lJ` mede **bloqueio síncrono do event loop**, não pausa de depurador    | **FATO**                             | timer de 1 ms + whitelist de `alert`/`confirm`/`prompt` (R37.2)                                                          |
| O mecanismo real do type=18 é integridade de motor e re-execução                 | **FATO**                             | quatro asserções não-temporais; a de `toString` só dispara em motor que normaliza escape sem dobrar concatenação (R37.3) |
| ~~A chave rotaciona **por deploy**~~                                             | **CORRIGIDO na escala**              | muda em minutos, não por entrega; decifrar exige o script da MESMA resposta (R35.8, refina §12.7)                        |
| Há ponderação em **um** dos quatro canais (comportamento)                        | **FATO**                             | capacidades/coletores/integridade são discretos; só o type=17 tem pesos (R35.6)                                          |
| O servidor decide pelo UA em claro ou pelo condensado                            | **UNKNOWN**                          | bloqueio ambíguo com incoerência; pode ser indecidível (R22.6)                                                           |
| ~~O fingerprint é server-sealed e inalcançável~~                                 | **REFUTADO**                         | a ausência era causada pelo nosso hook, não pelo selo (R17.4)                                                            |
| O hook de `document.cookie` trunca o pipeline                                    | **FATO**                             | 8/8 com hook truncam; 2/2 sem hook completam (R17.1)                                                                     |
| Repetir **consultas** na mesma sessão bloqueia                                   | **REFUTADO**                         | 7 ciclos × 2 sessões sem hook, 0 bloqueios (R18.4)                                                                       |
| ~~O reload é o gatilho~~                                                         | **REFUTADO**                         | reload seguinte não bloqueou (R18.7 / R19.2)                                                                             |
| ~~A geometria de tela discrimina~~                                               | **REFUTADO**                         | a mesma 5120×1440 bloqueou e passou (R19.1)                                                                              |
| **O desfecho local NÃO é determinístico**                                        | **FATO**                             | 7 sessões Win32 idênticas: 6 passaram, 1 bloqueou, sem variável que explique (R19.3)                                     |
| Sessões locais únicas têm baixa potência                                         | **FATO**                             | base de ~86% de passagem; R13/R14/R15 são mais fracos que o texto sugere (R19.4)                                         |
| O payload usa campos com prefixo de tamanho                                      | **FATO**                             | ` en-US`, `P` + UA de 80 chars (R18.1)                                                                                   |
| O cookie de fingerprint tem 3 registros de 66B                                   | **FATO**                             | marcador `"016a"` invariante em 4 amostras, 2 deploys (R21.2)                                                            |
| Os 3 registros são **um valor espelhado**                                        | **FATO**                             | R1==R2 em 8/8; R3 truncado (R24.2)                                                                                       |
| O registro é **tempo + valor por sessão**                                        | **FATO**                             | prefixo monotônico ~254/s; cauda muda com config idêntica (R24.3/R24.4)                                                  |
| ~~O `TS00000000076` carrega o fingerprint~~                                      | **REFUTADO**                         | dedução do §8 testada e derrubada (R24.4)                                                                                |
| ~~O fingerprint está fora de alcance offline~~                                   | **REFUTADO**                         | o `TS00000000074` é client-sealed e decifra (R26.2)                                                                      |
| O `TS00000000074` é binário, 17% ASCII                                           | **FATO**                             | 280 B; o `076` é 80% texto — são coisas distintas (R26.3)                                                                |
| **6 bytes do `074` codificam a identidade de SO**                                | **FATO**                             | offsets 91-94 e 145-146; n=2 por perfil, telas distintas (R27.2)                                                         |
| §13.4-Q4 (SO em claro ou derivado?)                                              | **RESPONDIDO**                       | ambos: UA em claro no `071`, derivado em 6B no `074` (R27.3)                                                             |
| O payload é **diferenciável** por entrada                                        | **FATO**                             | `hardwareConcurrency` → offset 127-128 (R28.3)                                                                           |
| Os campos têm **posições fixas** no vetor                                        | **FATO**                             | SO em 91-94/145-146, cores em 127-128, sem sobreposição (R28.4)                                                          |
| Os valores são **derivados**, não brutos                                         | **FATO**                             | cores=8→`f406`, cores=16→`a7be` (R28.4)                                                                                  |
| Existe um 2º cookie grande, `TS00000000074` (560B)                               | **FATO**                             | nasce no type=13, some após o 14; 12/12 timelines (R25.3)                                                                |
| Nunca o capturamos                                                               | **FATO**                             | o snapshot do jar era ao FIM da sessão; ele já não existia (R25.5)                                                       |
| O fingerprint sai pela URL                                                       | **REFUTADO**                         | GET 12/12, URL máx 146 chars (R25.1)                                                                                     |
| Os 18 campos **não** viajam individualmente                                      | **FATO**                             | só UA/locale em claro; o resto vai condensado (R21.3)                                                                    |
| Isolar o campo causal LENDO o payload                                            | **INVIÁVEL**                         | os campos não existem como campos no que é enviado (R21.4)                                                               |
| **Qual dos 18 campos do pacote carrega o efeito**                                | **DESCONHECIDO**                     | os campos movem-se juntos; ver R9.6                                                                                      |
| **Qual componente do "pacote contêiner"** participa                              | **DESCONHECIDO**                     | proxy = renderer ausente; não isolado (R12.6)                                                                            |
| Existe pool de backends (H4 do briefing)                                         | **HIPÓTESE**                         | dois `hi32` da mesma origem em minutos (R11.6)                                                                           |
| Modelo de soma com limiar                                                        | **HIPÓTESE**                         | a conjunção é a forma empírica que ele assumiria (R8.7, R12.4)                                                           |

Duas ressalvas de leitura, ambas importantes:

**1. "Refutado" aqui significa "refutado como explicação isolada".** As
refutações por contra-exemplo eliminam explicações de **variável única**; elas
não eliminam a contribuição dessas variáveis dentro de uma soma. Ler a coluna
como "nada explica" seria errado — o correto é "nada explica **sozinho**"
(R8.7).

**2. O desconhecido restante é um limite de desenho — mas um dos muros caiu.**
Isolar os 18 campos esbarrava em três obstáculos (R9.6): o Camoufox avisa contra
o override por propriedade (`LeakWarning`), o subconjunto que varia sem criar
incoerência já foi refutado, e cada sessão devolveria **um bit**.

O terceiro **não vale mais**. O §9.3-R10 mostrou que o bloqueio acompanha o
reuso da sessão, e o §9.3-R11 explorou isso: a variável dependente pode ser o
**índice da ação em que a sessão bloqueia** — uma contagem, não um bit
(`windows = 2`, `macos > 8`). Os dois primeiros muros seguem de pé.

**3. Um confundidor conhecido do instrumento.** No laço do R11 as ações 3–8
ficaram ~1,5 s apart, contra ~10 s entre as ações 1→2. Se o sinal de reuso for
por **taxa** numa janela de tempo em vez de por **contagem**, ações rápidas não
somam como ações espaçadas — e o desenho não distingue as duas leituras
(R11.5). Qualquer repetição precisa espaçar o laço com a mesma cadência.

### 13.2 Reconciliação com a leitura da fonte (pasta `portal/`) — 2026-09-07

As §§9.4, 12.5 e 12.6 foram escritas lendo os scripts **desofuscados**
(`portal/type_11.js`, `type_17.js`, `decoded_strings.txt`). Isso **atualiza
linhas do balanço acima** — registro aqui, por honestidade, o que mudou de status:

| Linha do balanço                                           | Status anterior                   | Novo status                                       | O que mudou                                                                                                                                                      |
| ---------------------------------------------------------- | --------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "Não descriptografamos o conteúdo — **não temos a chave**" | limite assumido                   | **SUPERADO (com ressalva)**                       | As chaves são **literais estáticos no `type_17.js`**: chave 0 `<chave-F5-key0>` (geral) e chave 2 `<chave-F5-key2>` (cookie-semente `TSX010AAA`). Ver §12.5.     |
| "Não há POST de fingerprint"                               | FATO (via HAR)                    | **FATO (confirmado na fonte)**                    | O código faz `XHR GET` com `?type=` na URL; nenhum corpo. Ver §9.4.                                                                                              |
| Cifra/CBC/HMAC (linhas 227–252 etc.)                       | FATO (script beautificado antigo) | **FATO (reverificado)**                           | Confirmado no `type_17.js` real; numeração de linha atualizada nas §§12.1–12.3.                                                                                  |
| Mecânica cripto = 3 primitivas                             | —                                 | **NOVO FATO**                                     | Tudo se reduz ao bloco XTEA: cifra (CBC), hash (Davies–Meyer, §12.6) e MAC (HMAC, §12.3). Construção **Encrypt-then-MAC** (§12.5).                               |
| "Schema de N campos do cookie"                             | DEDUÇÃO (serializador `ZI`)       | **DEDUÇÃO (refinada)**                            | Achamos o **manifesto `ZZ`** (`type_11.js` ~26315), lista ordenada de `{type: …}`; ainda não é um cookie decifrado.                                              |
| "O cookie `TS…076` carrega o fingerprint"                  | DEDUÇÃO (tamanho/timing)          | **MECANISMO = FATO; cookie específico = DEDUÇÃO** | A fonte mostra `sz.seal(valor) → document.cookie` (§9.6): o valor coletado é selado e vira cookie. _Qual_ cookie é o `TS…076` segue inferido por tamanho/timing. |

**Ressalva que impede exagero:** ter as chaves **não** equivale a ter decifrado um
cookie real. Faltam três coisas, e é aí que vamos: **(1)** as chaves podem
**rotacionar por versão do script** (§12.5); **(2)** ainda não reconstruímos o
**token `I` da URL** — onde o payload cifrado efetivamente viaja (§9.4, limite
honesto); **(3)** nada disso muda a POC (§12.4) — o valor é de entendimento e
verificação. O próximo passo declarado é o **token `I`**: seguir
`SS.I_ → z_.ol → z_.lzz` com o ferramental de `forensic/deobf_f5.py`.

### 13.3 O que a camada de mecanismo revela sobre a camada de decisão

> **Redação revista (2026-09-07).** Versão anterior desta subseção usava
> "relator fiel", "snapshot atômico" e "campos amarrados pela criptografia".
> A revisão abaixo mantém todos os fatos e ressalvas e **corrige três
> sobre-extensões**: separa fidelidade-de-_transporte_ (provada) de
> fidelidade-de-_descrição_ (refutada pelos dados — o perfil é spoofável na
> coleta); localiza a co-variação dos 18 campos no **instrumento de coleta**
> (Camoufox, R9.4/R9.6), não no HMAC; e distingue amarração-de-transporte de
> co-variação-na-coleta. Nada de fato foi removido; a mudança é de rigor.

O item 2 (§§9.4–9.6, mecanismo) e as revisões R4–R9 (§13.1, decisão) foram
investigações separadas. Esta subseção amarra as duas — com cuidado para **não
transformar propriedade do instrumento de coleta em propriedade da cripto do
F5**. O mecanismo **não** identifica a função de decisão; ele elimina causas de
transporte e delimita onde o achado "o desfecho acompanha o perfil de SO em
ambiente sem WebGL" (13/13, p = 5,8×10⁻⁴) pode e não pode morar.

**1. A decisão é server-side; o cliente é um mensageiro autenticado do que
coletou.** Está **provado na fonte** que o cliente coleta a autodescrição do
ambiente (campos de SO inclusos), a **sela** (Encrypt-then-MAC, §9.6) e a grava
em cookies; a URL leva um token de roteamento/liveness (§9.5), com a ressalva de
que o token `I` ainda não foi reconstruído e o payload pode viajar nos cookies
**e/ou** em `I` (§9.4). É **suportado pelos dados** (não lido na fonte do
servidor) que a decisão é do servidor: o veredito chega no `POST_RESPONSE` com
support ID, e `hi32` é constante do lado do F5 (R5.2, R8.4). **Ressalva forte:**
"mensageiro fiel" vale para o _transporte_ — o cliente entrega sem corromper o
que coletou — **não** para a _descrição_: os valores coletados são spoofáveis na
coleta, e foram spoofados (macOS declarado sobre kernel Linux passou 7/7, R9.2).
Que o servidor **decifre e leia justamente os campos de SO** para decidir é
**hipótese** plausível, não fato — nenhum cookie de produção foi decifrado
(§13.2).

**2. Uma leitura do UNKNOWN da R9.6 — com a causa no lugar certo.** Os 18 campos
"andam juntos" **porque o instrumento de coleta os move juntos**: o Camoufox gera
o perfil como pacote coerente e avisa contra override por propriedade
(`LeakWarning`), e cada sessão troca o **perfil inteiro** (R9.4, R9.6). Essa é a
razão client-side, no momento da coleta. A criptografia entra **depois** e num
papel **diferente**: o HMAC torna o blob _tamper-evident no transporte_ — não se
edita um campo já selado sem a chave e sem reconstruir um payload consistente.
São duas amarrações distintas; fundi-las numa só ("os campos andam juntos por
causa da cripto") seria erro. _Ressalva:_ nem sequer está provado que os 18
campos formem **um** blob selado — a fonte mostra vários cookies, duas variantes
de seal (tags `0x09`/`0x10`) e múltiplos backends `s5` (§9.4/§9.6); o schema
único é **dedução** (§13). Somam-se à co-variação os checks de coerência —
`isNative` (**fato**, §7.2) e valores espelhados (**dedução** de propósito, §8).

**3. Editar o SO _no cookie transmitido_ não funciona — e só isso.** Com
Encrypt-then-MAC + coerência cruzada, alterar post-hoc os campos de SO no cookie
de uma sessão bloqueada exigiria a chave **e** um payload inteiro consistente
(§12.5, §8). O escopo é estrito: isto **não** cobre a troca de SO **na coleta**,
que é o que o corpus faz e que passa. E a barreira "exigiria a chave" é
relativa — as chaves são literais estáticos no script (§12.5, ponto 4). Portanto,
do lado do F5, o campo de SO é resistente a **adulteração ingênua do cookie**,
não a spoofing na origem. É a razão técnica da conclusão da §8.

**4. As chaves estáticas (§12.5) abrem uma porta de DIAGNÓSTICO, não de evasão.**
Em tese permitem **decifrar um cookie de produção** e ver os campos como o
servidor os recebe — o instrumento que poderia atacar o UNKNOWN da R9.6. Limites
intactos: as chaves podem **rotacionar por versão**; decifrar mostra os _campos_,
não os _pesos_ da decisão; e continua sendo leitura — forjar ainda esbarra na
teia (§8). Avança a diagnose, não a POC (§12.4). **Correção (2026-09-07, §12.7.a):
na prática essa porta abriu para o lugar errado — os cookies client-sealed que
deciframos carregam session-state, não o fingerprint; os de fingerprint são
server-sealed. Ler os 18 campos por decifração está, por ora, fora de alcance.**

**5. Por que WebGL-sim vs. WebGL-não.** O **transporte é idêntico** nos dois
casos (mesmo seal→cookie→GET, §9.4/§9.6) — o que **elimina** "o transporte
difere" como causa e deixa a diferença inteiramente do lado do servidor. A
leitura _compatível_ (hipótese "soma com limiar", §13.1) é: a WebGL contribuiria
um termo grande; sem GPU, os termos do **perfil de SO** cruzariam o limiar
sozinhos. Os campos de SO são sempre coletados e selados; _sob esta hipótese_ só
se tornam **decisivos** na ausência da WebGL. Nada aqui prova que o servidor
"prioriza" esses campos — apenas que o mecanismo **não contradiz** o modelo.

**Síntese honesta:** o trabalho de mecanismo **fecha a camada de transporte** —
mostra que o "os campos andam juntos" **não** é artefato de transporte nem de
medição, e que a cirurgia isolada de um campo no blob transmitido está bloqueada.
Ele **não** converte esse fenômeno em "consequência da cripto": a co-variação é
consequência do **instrumento de coleta** e do **desenho experimental** (troca de
perfil inteiro, saída de um bit — R9.4/R9.6). A função de decisão do F5 segue
**DESCONHECIDA**, agora com (a) causas de transporte eliminadas e (b) um
instrumento — a chave — que, com as ressalvas do ponto 4, poderia um dia lê-la.

### 13.4 Perguntas científicas em aberto

O balanço das §§13.1–13.3 fecha a camada de mecanismo e delimita a de decisão,
mas deixa oito perguntas explicitamente **não** resolvidas. Registrá-las é parte
do método (§46): são os fios que um retomador do estudo pega primeiro.

1. **Qual canal carrega o sinal decisor** — os cookies selados, o token `I` da
   URL, ou ambos? A fonte diz "e/ou" (§9.4) e o `I` não foi reconstruído
   (`SS.I_ → z_.ol → z_.lzz`, §9.5). Sem isto, "o servidor lê os campos
   decifrados" (§13.3, ponto 1) fica sem o elo final.
2. **O servidor de fato decifra e lê os campos de SO?** Nunca observado — só
   inferido da correlação. A decisão poderia usar um subconjunto, um derivado
   (ex.: `canvas.hash`) ou metadados fora do blob. **Hipótese**, não fato (§13.2:
   nenhum cookie de produção decifrado).
3. **Os 18 campos estão num único blob selado ou espalhados** por vários
   cookies/tags (`0x09`/`0x10`, §9.6)? Decide se "snapshot" é sequer aplicável;
   hoje o schema único é **dedução** (§13).
4. **Qual dos 18 campos carrega o efeito — ou nenhum sozinho?** O `UNKNOWN`
   central (R9.6), barrado pelo desenho (saída de um bit, campos empacotados,
   `LeakWarning`), não por falta de esforço.
5. **O modelo "soma com limiar" resiste a teste direto?** É **hipótese**
   compatível com os oito pontos de R8.7, nunca testada isoladamente.
6. **A origem contribui como termo da soma** (mesmo sem ser necessária, R8.5)?
   A célula "GPU real saindo por IP de datacenter" segue vazia (R8.5, limite 1).
7. ~~**As chaves estáticas rotacionam por versão do script?**~~ **RESPONDIDA: SIM
   (2026-09-07, §12.7).** A chave do deploy vivo (`<chave-F5-A>`) difere da do script
   salvo (`<chave-F5-B>`). A "porta de diagnóstico" (§13.3, ponto 4) é **efêmera**: cada
   captura precisa do `live_type11.js` do mesmo deploy para casar a chave.
8. **Por que o efeito do perfil de SO só aparece em ambiente degradado** (sem
   WebGL, p = 5,8×10⁻⁴, R9.2) e some com GPU real (p = 0,57, R5.5)? A interação é
   observada; o mecanismo server-side que a produz é **desconhecido**.

Nenhuma destas é abordável dentro do escopo declarado do projeto (uma sessão
supervisionada por vez, saída binária contra um serviço público real). Ficam como
perguntas, não como próximos passos.

---

## 14. Glossário rápido

- **F5 Shape** — o produto anti-bot. Também chamado de "TSPD" pelo caminho de URL.
- **APM_DO_NOT_TOUCH** — o comentário que marca o script inline do F5 na página.
- **Fingerprint** — impressão digital técnica do navegador/máquina.
- **WebGL** — API de gráficos 3D no navegador; usada aqui para impressão digital da GPU.
- **ISO 12233** — carta de teste de resolução usada como textura de referência.
- **isNative** — checagem de que funções nativas não foram adulteradas.
- **isTrusted** — propriedade de um evento: `true` se veio de hardware real.
- **RSD** — desvio padrão relativo; mede a irregularidade do timing (humano = alto).
- **CDP** — Chrome DevTools Protocol; como o Playwright controla o navegador.
- **Rotação de cookie** — o servidor reemite cookies novos a cada validação.
- **clntcap** — "client capture", o frame que finaliza a coleta.

---

\*Estudo conduzido por engenharia reversa dos scripts servidos publicamente pelo
site, para fins de entendimento do mecanismo.
