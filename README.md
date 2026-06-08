# Dns-defense

1-
ryu-manager --wsapi-port 8082 ryu.app.simple_switch_13 ryu.app.ofctl_rest ryu.app.gui_topology.gui_topology ryu.app.rest_firewall
2-
sudo mn --topo tree,depth=3,fanout=2   --mac   --switch ovsk,protocols=OpenFlow13   --controller remote,ip=127.0.0.1,port=6633
3-
curl -X PUT  http://localhost:8082/firewall/module/enable/0000000000000009
4-
curl http://localhost:8082/firewall/module/status take time
5-
\\\\\\\\\\\\\\\
V6


curl -X POST http://localhost:8082/stats/flowentry/add \
-H "Content-Type: application/json" \
-d '{
    "dpid":1,
    "priority":100,
    "match":{
        "dl_type":34525
    },
    "actions":[
        {
            "type":"OUTPUT",
            "port":"NORMAL"
        }
    ]
}'

\\\\\\\\\\\\\\\
1- 
