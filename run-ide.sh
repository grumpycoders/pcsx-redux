#!/bin/sh

# This is to run the development environment to work on PCSX-Redux under Linux.
# One this script is running, port 8443 will be exposed as an http server.
# This is based on the code-server project: https://github.com/cdr/code-server

# It is possible to run it behind an apache front-end with the following piece of configuration:

#  RewriteEngine on
#  RewriteCond %{HTTP:Upgrade} =websocket
#  RewriteRule /(.*)     ws://localhost:8000/$1  [P,L]
#  RewriteCond %{HTTP:Upgrade} !=websocket
#  RewriteRule /(.*)     http://localhost:8000/$1 [P,L]
#  ProxyPass / http://localhost:8000/
#  ProxyPassReverse / http://localhost:8000/
#  ProxyRequests Off

docker pull grumpycoders/pcsx-redux-code-server:latest
docker run --rm -it -p 127.0.0.1:8443:8443 --env-file env.list -v "${PWD}:/home/coder/project" -u `id -u`:`id -g` grumpycoders/pcsx-redux-code-server:latest --allow-http --no-auth -d /home/coder
