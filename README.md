# ninicobox-v3-server

A home cloud providing file explorer with permissions and access control lists to share files with friends, and acting as a proxy for other services with content rewriting. Server written in go.

## To do

[x] Allow displaying of proxies in webframes
[x] Add security to proxies
[x] Add let's encrypt support
[x] Add user and geo ip to logging, log only auth and webdav operations
[x] Replace polling by reloading api
[x] Add basic auth option to webdav
[x] Make build and deploy container

[x] Correct ip geolocation
[x] Move JWT to basic auth to last resort
[x] Allow unsecured proxys
[x] Correct webdav auth
[x] [Client] Correct iframe resizing
[ ] Add sonarcloud audit
[x] [Client] Correct proxys saving
[x] [Client] Add automatic switch to main view on blur
[x] Toggle token lifespan to 24 hours
[x] Test security, http2, tls, etc...
[x] Limit proxys to registered ones
[x] Allow path in tourl
[x] Correct redirection
[ ] [Client] clean path
[/] Documentation
[x] Self doc + saves + mcd
[x] Correct informations display
[x] [Client] display techical proxys as icons
[ ] Add compression