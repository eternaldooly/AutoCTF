#!/bin/bash
export PYTHONPATH=/AUTOCTF/mcp-proxy/src:$PYTHONPATH
exec /usr/bin/python3 -m mcp_proxy "$@"