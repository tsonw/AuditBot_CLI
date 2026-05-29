#!/bin/sh
set -eu

HOST_ROLE="${HOST_ROLE:-linux-host}"
HTTP_PORTS="${HTTP_PORTS-8080}"
LISTEN_PORTS="${LISTEN_PORTS-}"
ENABLE_NGINX="${ENABLE_NGINX:-1}"
VULN_HTTP_PORTS="${VULN_HTTP_PORTS-}"
VULN_FTP_PORTS="${VULN_FTP_PORTS-}"

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

start_vulnerable_http_server() {
       port="$1"

       if [ -z "${port}" ]; then
              return
       fi

       response_file="/tmp/auditbot-vuln-apache-${port}.http"
       printf 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAuditBot vulnerable lab Apache httpd 2.4.49\r\n' > "${response_file}"
       socat TCP-LISTEN:"${port}",fork,reuseaddr SYSTEM:"cat ${response_file}" >/dev/null 2>&1 &
}

start_vulnerable_ftp_server() {
       port="$1"

       if [ -z "${port}" ]; then
              return
       fi

       response_file="/tmp/auditbot-vuln-vsftpd-${port}.banner"
       printf '220 (vsFTPd 2.3.4)\r\n' > "${response_file}"
       socat TCP-LISTEN:"${port}",fork,reuseaddr SYSTEM:"cat ${response_file}" >/dev/null 2>&1 &
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

       case ",${VULN_HTTP_PORTS}," in
              *",${port},"*) return ;;
       esac

       case ",${VULN_FTP_PORTS}," in
              *",${port},"*) return ;;
       esac

       socat TCP-LISTEN:"${port}",fork,reuseaddr SYSTEM:"printf 'AuditBot ${HOST_ROLE} service on port ${port}\\r\\n'" >/dev/null 2>&1 &
}

for port in $(echo "${HTTP_PORTS}" | tr "," " "); do
       start_http_server "${port}"
done

for port in $(echo "${VULN_HTTP_PORTS}" | tr "," " "); do
       start_vulnerable_http_server "${port}"
done

for port in $(echo "${VULN_FTP_PORTS}" | tr "," " "); do
       start_vulnerable_ftp_server "${port}"
done

for port in $(echo "${LISTEN_PORTS}" | tr "," " "); do
       start_banner_listener "${port}"
done

trap 'kill $(jobs -p) 2>/dev/null || true; nginx -s quit 2>/dev/null || true; exit 0' INT TERM

while true; do
       sleep 3600 &
       wait $!
done
