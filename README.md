# Replaced by vestibule (https://www.github.com/nicolaspernoud/Vestibule)

# ninicobox-v3-server

## Installation

See : https://github.com/nicolaspernoud/ninicobox-v3-deploy
Server written in go.

## Update dependencies (go modules)

Check (use https://github.com/psampaz/go-mod-outdated) :

```bash
go list -u -m -json all | go-mod-outdated
```

Update :

```bash
go get -u
go mod tidy
```
