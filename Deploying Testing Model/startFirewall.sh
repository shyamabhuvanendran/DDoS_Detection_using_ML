#!/bin/bash
curl http://127.0.0.1:8080/wm/firewall/module/enable/json -X PUT -d '' | python -m json.tool
curl -X POST -d '{"switchid": "00:00:00:00:00:00:00:01", "priority":"200"}' http://localhost:8080/wm/firewall/rules/json
curl -X POST -d '{"switchid": "00:00:00:00:00:00:00:02", "priority":"200"}' http://localhost:8080/wm/firewall/rules/json
curl -X POST -d '{"switchid": "00:00:00:00:00:00:00:03", "priority":"200"}' http://localhost:8080/wm/firewall/rules/json
curl -X POST -d '{"switchid": "00:00:00:00:00:00:00:04", "priority":"200"}' http://localhost:8080/wm/firewall/rules/json
curl -X POST -d '{"switchid": "00:00:00:00:00:00:00:05", "priority":"200"}' http://localhost:8080/wm/firewall/rules/json

