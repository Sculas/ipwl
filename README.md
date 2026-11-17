# ipwl

Server-only IP allowlist. Connections from IPs that aren't on the list get no response at all, so port scanners can't see the server.

ipwl always allows localhost. To hide the port, the server needs `CAP_NET_ADMIN`. Use `AmbientCapabilities=CAP_NET_ADMIN` with systemd or `--cap-add NET_ADMIN` with Docker.

```
/ipwl add <ip|cidr> [note]
/ipwl addplayer <player> [note]
/ipwl remove <ip|cidr>
/ipwl list
/ipwl status
/ipwl on|off
/ipwl reload
```

**NeoForge and Minecraft 1.21.1 only.**
