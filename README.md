# ServiceBlock

AdBlock list to block specific services (a subset of those provided by Adguard).
Generated daily from [AdGuard's Hostlists Registry](https://adguardteam.github.io/HostlistsRegistry/assets/services.json).

## Blocklist URL

```
https://raw.githubusercontent.com/imathew/serviceblock/main/blocklist.txt
```

## Changing blocked services

Edit `services.txt` — one service ID per line. Push to trigger a rebuild.

This file is updated daily along with the blocklist, keeping existing selections but adding new (unblocked) services.

Valid service IDs can be found here: https://adguardteam.github.io/HostlistsRegistry/assets/services.json
