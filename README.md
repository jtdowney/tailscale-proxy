# tailscale-proxy

| :exclamation: You don't want to use this. |
| ----------------------------------------- |

The entirety of what this project does is now [built into Tailscale serve](https://tailscale.dev/blog/tailscale-serve-obsoleted-my-code).

## Overview

A reverse proxy for [Tailscale](https://tailscale.com/) that auto-configures with certificates from the local daemon. This was inspired by the post on the Tailscale blog about [How To Seamlessly Authenticate to Grafana using Tailscale](https://tailscale.com/blog/grafana-auth/). I wanted to build a more generic version of the Grafana proxy that can be easily used to front any HTTP service. The proxy auto-configures itself with [certificates retrieved from Tailscale](https://tailscale.com/kb/1153/enabling-https). This is similar to the recently announced [Caddy support for Tailscale](https://tailscale.com/kb/1190/caddy-certificates), except it also pulls the whois information for the requesting client. It uses [rustls](https://github.com/rustls/rustls) to get a modern TLS stack on the server-side.

Overall that is just fun experimental software, so please don't use it for anything serious.

## Prior art

I used code and inspiration from [hyper-reverse-proxy](https://github.com/felipenoris/hyper-reverse-proxy) when building the reverse proxy code.
