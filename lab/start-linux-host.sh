#!/bin/sh
set -eu

HOST_ROLE="${HOST_ROLE:-linux-host}"
HTTP_PORTS="${HTTP_PORTS:-8080}"
LISTEN_PORTS="${LISTEN_PORTS:-}"
ENABLE_NGINX="${ENABLE_NGINX:-1}"

mkdir -p /run/sshd /var/www/html
ssh-keygen -A >/dev/null 2>&1
/usr/sbin/sshd

cat >/var/www/html/index.html <<EOF
AuditBot lab host: ${HOSTNAME}
Role: ${HOST_ROLE}
EOF

if [ "${ENABLE_NGINX}" = "1" ]; then
       nginx
fi

start_http_server() {
       port="$1"

       if [ -z "${port}" ] || { [ "${port}" = "80" ] && [ "${ENABLE_NGINX}" = "1" ]; }; then
              return
       fi

       python3 -m http.server "${port}" --directory /var/www/html >/dev/null 2>&1 &
}

start_banner_listener() {
       port="$1"

       if [ -z "${port}" ] || [ "${port}" = "22" ]; then
              return
       fi

       if [ "${port}" = "80" ] && [ "${ENABLE_NGINX}" = "1" ]; then
              return
       fi

       case ",${HTTP_PORTS}," in
              *",${port},"*) return ;;
       esac

       socat TCP-LISTEN:"${port}",fork,reuseaddr SYSTEM:"printf 'AuditBot ${HOST_ROLE} service on port ${port}\\r\\n'" >/dev/null 2>&1 &
}

for port in $(echo "${HTTP_PORTS}" | tr "," " "); do
       start_http_server "${port}"
done

for port in $(echo "${LISTEN_PORTS}" | tr "," " "); do
       start_banner_listener "${port}"
done

trap 'kill $(jobs -p) 2>/dev/null || true; nginx -s quit 2>/dev/null || true; exit 0' INT TERM

while true; do
       sleep 3600 &
       wait $!
done
