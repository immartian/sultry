#\!/bin/bash
echo "Starting Sultry in direct dual mode"
cd $(dirname "$0")/..
cat > config-http.json << 'CFG'
{
    "mode": "dual",
    "local_proxy_addr": "127.0.0.1:7008",
    "relay_port": 9008,
    "cover_sni": "harvard.edu",
    "prioritize_sni_concealment": true,
    "full_clienthello_concealment": true,
    "handshake_timeout": 10000,
    "enforce_tls13": true,
    "use_oob_for_application_data": true
}
CFG
go build -o bin/sultry
./bin/sultry -config config-http.json
