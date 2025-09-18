#!/bin/bash

# Create directories if they don't exist
mkdir -p /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME

# Create all middleware and chain files in one command
cat > /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME/tls-opts.yml << 'EOL'
tls:
  options:
    tls-opts:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
        - TLS_AES_128_GCM_SHA256
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
        - TLS_FALLBACK_SCSV
      curvePreferences:
        - CurveP521
        - CurveP384
      sniStrict: true
EOL

cat > /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME/middlewares-rate-limit.yml << 'EOL'
http:
  middlewares:
    middlewares-rate-limit:
      rateLimit:
        average: 100
        burst: 50
EOL

cat > /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME/middlewares-secure-headers.yml << 'EOL'
http:
  middlewares:
    middlewares-secure-headers:
      headers:
        accessControlAllowMethods:
          - GET
          - OPTIONS
          - PUT
        accessControlMaxAge: 100
        hostsProxyHeaders:
          - "X-Forwarded-Host"
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        # forceSTSHeader: true # This is a good thing but it can be tricky. Enable after everything works.
        customFrameOptionsValue: SAMEORIGIN
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "same-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), vr=()"
        customResponseHeaders:
          X-Robots-Tag: "none,noarchive,nosnippet,notranslate,noimageindex,"
          server: ""
EOL

cat > /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME/chain-no-auth.yml << 'EOL'
http:
  middlewares:
    chain-no-auth:
      chain:
        middlewares:
          - middlewares-rate-limit
          - middlewares-secure-headers
EOL

cat > /home/$USER/docker/appdata/traefik3/rules/$HOSTNAME/chain-authelia.yml << 'EOL'
http:
  middlewares:
    chain-basic-auth:
      chain:
        middlewares:
          - middlewares-rate-limit
          - middlewares-secure-headers
          - middlewares-authelia
EOL

# Set proper permissions for acme.json
chmod 600 /home/$USER/docker/appdata/traefik3/acme/acme.json

echo "All middleware and chain files have been created successfully!"
