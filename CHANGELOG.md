# Mpro - Changelog

## v3.6.0 - Latency Optimized for Low Latency Networks

### Otimizações de Latência

#### Fator 1 – Múltiplas requisições POST/GET:
- **Keep-Alive** adicionado nos headers (timeout=30, max=100) — o cliente reutiliza a mesma conexão TCP pra enviar POSTs, não precisa abrir nova conexão a cada envio
- **Canal GET/POST ampliado** de 4096 para **16384** — menos backpressure em redes lentas
- Buffer de leitura HTTP raw ampliado de 8192 para **16384**

#### Fator 2 – HTTP/1.1 sem multiplexação:
- **TCP_QUICKACK ativado** — ACK imediato sem delay, funciona como uma forma de "multiplexação" via TCP
- **POST read_exact sem timeout** — lê o corpo completo do POST sem esperar, mais rápido em redes lentas

#### Fator 3 – Redes restritas/ADSL com alta latência:
- **TCP_QUICKACK** (ACK imediato, elimina o delay do Nagle)
- **Peek timeout reduzido para 200ms** (detecção ultra rápida)
- **TLS read timeout reduzido para 1.5s**
- **SSH connect timeout reduzido para 3s** (resposta 200 já foi enviada antes)

### Para aplicar no servidor:
```bash
cd /root/Mxpro && git pull && ./install.sh
systemctl restart proxy-443
```

---

## v2.4.1 - xHTTP SplitHTTP

### Novo
- **Correção SplitHTTP** — suporte completo ao protocolo SplitHTTP usado no DTUNNEL
- **Persistência HTTP/1.1** — headers `Connection: keep-alive` obrigatórios para manter o canal GET aberto
- **ALPN http/1.1** — forçando ALPN http/1.1 no TLS para evitar falhas de handshake no DTUNNEL
- **Path Parsing** — suporte a paths com sequence numbers (ex: `/ssh/session/0`)
- **Headers de Streaming** — inclusão de headers `Cache-Control`, `Pragma` e `Expires` para evitar cache de proxy intermediário (CDN)


## v0.3.0 - Multi-Protocolo (TCP + UDP + QUIC)

### Novo

- **Suporte UDP** — listener UDP na mesma porta TCP, encaminhamento de datagramas
- **Suporte QUIC** — servidor QUIC completo com `quinn` crate, streams bidirecionais
- **Certificado auto-assinado** — geração automática de cert.pem e key.pem via `rcgen`
- **Ativação automática** — ao usar `-p 443 -t`, UDP e QUIC são ativados automaticamente
- **Flags novas:**
  - `-u` / `--udp` — ativar UDP na porta TCP
  - `-q` / `--quic` — ativar QUIC (porta separada via `--quic-port` ou mesma)

### Flags de Uso

```bash
# Multi-protocolo completo (TCP + UDP + QUIC) na 443
./mpro -p 443 -t -ssh

# Apenas TCP + UDP
./mpro -p 443 -t -u -ssh

# Apenas TCP + QUIC
./mpro -p 443 -t -q -ssh

# QUIC em porta separada
./mpro -p 443 -t -q --quic-port 8001 -ssh
```

### Configuração do menu.sh

Ao abrir a porta 443 com HTTPS habilitado, o proxy agora inicia automaticamente:
- TCP:443 (xHTTP, Proto, WebSocket, TLS, SSH)
- UDP:443 (proxy UDP para xHTTP/Proto)
- QUIC:8001 (proxy QUIC com certificado auto-assinado)

### Certificados

Os certificados QUIC são gerados automaticamente em `/opt/mpro/cert.pem` e `/opt/mpro/key.pem` na primeira execução com QUIC ativo.

### Arquitetura

```
Cliente → [TCP:443] → Mpro → SSH:22 / VPN:1194
Cliente → [UDP:443] → Mpro → SSH:22 / VPN:1194
Cliente → [QUIC:8001] → Mpro → SSH:22 / VPN:1194
```

---

## v0.2.0 - xHTTP/Proto + TLS

### Novo
- Handler xHTTP com handshake HTTP/101 + 200 e headers customizados
- Handler Proto para conexões TCP raw/binary
- TLS com passthrough e terminação (flags -t e -ssh)
- Detecção aprimorada de protocolos (TLS, xHTTP, Proto, SOCKS5)
- Integração de todos os handlers existentes
- WebSocket com suporte a Sec-WebSocket-Accept (SHA-1 + Base64)
- Fallback automático SSH↔VPN em todos os handlers
