# Análise de Bugs - Wpro xHTTP

## Problemas Identificados

### Bug 1: Teardown precoce da sessão (CAUSA PRINCIPAL DO TRAVAMENTO)
No log `proxy.log` e no código, quando um POST chega para uma sessão, a sessão é **removida** (`sessions.remove(&sid)`) no handle do GET. Isso faz com que POSTs subsequentes não encontrem a sessão e os dados sejam perdidos. O ciclo GET→POST causa fechamento prematuro.

### Bug 2: `read_exact` sem timeout no POST (CAUSA DO TRAVAMENTO EM REDES LENTAS)
Nas funções `handle_xhttp_post_raw` e `handle_xhttp_post_tls`, o `read_exact` para ler o corpo do POST **não tem timeout**. Em redes instáveis/móveis (timbrasil.br como visto no screenshot), se o cliente não enviar o corpo completo rapidamente, o processo trava indefinidamente esperando dados.

### Bug 3: Buffer de buffer de leitura no tunnel GET muito grande (32768)
O buffer de 32KB para leitura do SSH backend pode causar acúmulo de memória e latência em conexões lentas. Não há flush adequado entre chunked writes.

### Bug 4: Flush em cada chunk do GET causa overhead
A cada chunk enviado pelo GET, há um `flush()` separado, o que em redes móveis lentas causa múltiplos round-trips desnecessários.

### Bug 5: Não há retry/reconnect na conexão SSH
Se a conexão SSH cair durante o tunnel, não há mecanismo de reconnect. O tunnel simplesmente morre.

### Bug 6: Canal mpsc de 16384 pode saturar
Com canal de 16384 e sem backpressure adequada, em redes instáveis o canal pode encher e causar perda de dados ou deadlock.

### Bug 7: `tokio::join!` não trata erros adequadamente
O `handle_ssh_direct` e `handle_http_dual_raw` usam `tokio::join!` com `tokio::io::copy` que silenciam erros. Quando um lado falha, o outro continua tentando copiar, causando travamento.

### Bug 8: `peek` com 200ms timeout é agressivo
Em redes móveis com latência alta, 200ms pode não ser suficiente para detectar o tipo de protocolo, resultando em fallback para SSH direto que depois falha.
