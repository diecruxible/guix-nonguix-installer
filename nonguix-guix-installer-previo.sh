#!/bin/bash
# =============================================================================
# INSTALADOR PERSONALIZADO DE GUIX SYSTEM CON BTRFS, PLASMA Y NONGUIX
# =============================================================================
# Descripción: Instalador de Guix System optimizado con Btrfs, Plasma Desktop,
# soporte para redes ocultas, Flatpak + Discover, y configuración "erase your darlings".
# Este script está diseñado para ejecutarse directamente desde el entorno live
# del ISO de nonguix.
# =============================================================================
set -euo pipefail
trap 'echo "Error en la línea $LINENO"' ERR

# =============================================================================
# CONFIGURACIÓN DE ENTORNO PARA EL LIVE SYSTEM
# =============================================================================
export PATH=/run/current-system/profile/bin:/run/current-system/profile/sbin:$PATH
export GUIX_LOCPATH=/run/current-system/locale
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

# =============================================================================
# CONFIGURACIÓN DE COLORES Y VARIABLES GLOBALES
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configuración por defecto
declare -A DEFAULTS=(
    [lang]="es_CR.UTF-8"
    [timezone]="America/Costa_Rica"
    [keyboard]="latam"
    [name]="Usuario"
    [login_name]="usuario"
    [hostname]="blabla"
    [desktop]="plasma"
    [use_nonguix]="yes"
    [create_swap]="yes"
    [swap_size]="8g"
)

readonly MOUNT_POINT="/mnt"
readonly GUIX_CONFIG_DIR="$MOUNT_POINT/etc/config"

# Variables globales para UUIDs (serán establecidas durante la instalación)
ROOT_UUID=""
EFI_UUID=""
SSD_OPTION="nossd"
CREATE_SWAP="no"
ENCRYPT_DISK="no"
LUKS_UUID=""
ENCRYPTED_NAME="guix-encrypted"
RESUME_UUID=""
RESUME_OFFSET=""

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

prompt_yes_no() {
    local prompt=$1
    local default=${2:-no}
    read -r -p "${prompt} (Por defecto: ${default}) " response
    echo "${response:-$default}"
}

get_user_input() {
    local prompt=$1
    local default=$2
    local is_password=${3:-false}
    if [ "$is_password" = true ]; then
        read -r -s -p "${prompt}: " value
        echo
    else
        read -r -p "${prompt} (Por defecto: ${default}): " value
    fi
    echo "${value:-$default}"
}

validate_desktop() {
    local desktop=$1
    local valid_desktops=("plasma" "gnome" "xfce" "mate" "i3" "sway" "none")
    for valid_desktop in "${valid_desktops[@]}"; do
        if [ "$desktop" = "$valid_desktop" ]; then
            return 0
        fi
    done
    return 1
}

detect_ssd() {
    local disk_device=$1
    local dev_name
    dev_name=$(basename "$disk_device")
    local rotational_path="/sys/block/$dev_name/queue/rotational"
    if [ -f "$rotational_path" ]; then
        if [[ $(< "$rotational_path") == "0" ]]; then
            SSD_OPTION="ssd,discard=async"
            print_message "$GREEN" "Disco detectado como SSD. Activando optimizaciones."
        else
            SSD_OPTION="nossd"
            print_message "$CYAN" "Disco detectado como HDD. Usando configuración estándar."
        fi
    else
        SSD_OPTION="nossd"
        print_message "$YELLOW" "No se pudo detectar tipo de disco. Usando configuración estándar."
    fi
}

get_partition_uuid() {
    local partition=$1
    if [ -b "$partition" ]; then
        blkid -s UUID -o value "$partition"
    else
        print_message "$RED" "Error: Partición $partition no existe o no es válida."
        exit 1
    fi
}

# =============================================================================
# FUNCIONES PARA SOPORTE DE SUSTITUTOS (NONGUIX)
# =============================================================================
authorize_nonguix_key() {
    if [ "$use_nonguix" = "yes" ]; then
        print_message "$CYAN" "Autorizando clave pública de nonguix para sustitutos..."
        local key_data='(public-key
 (ecc
  (curve Ed25519)
  (q #B3C6F2A47E297F274C2F4543F9B4C5A5D36C92B1E50E2F6DBF53854E5E91A6C7#)))'
        if ! printf '%s\n' "$key_data" | guix archive --authorize; then
            print_message "$RED" "Fallo al autorizar clave de nonguix."
            return 1
        fi
        print_message "$GREEN" "✓ Clave de nonguix autorizada"
    fi
}

restart_guix_daemon_with_substitutes() {
    local substitute_urls="$1"
    print_message "$CYAN" "Reiniciando guix-daemon con soporte para sustitutos..."
    herd stop guix-daemon 2>/dev/null || true
    sleep 2
    if ! herd start guix-daemon -- substitute-urls="$substitute_urls" 2>/dev/null; then
        print_message "$YELLOW" "No se pudo reiniciar guix-daemon con sustitutos. Continuando sin daemon."
    fi
}

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN DE RED
# =============================================================================
check_internet_connection() {
    print_message "$CYAN" "Verificando conexión a internet..."
    if curl -sfI --max-time 8 https://ci.guix.gnu.org &>/dev/null; then
        print_message "$GREEN" "✓ Conexión a internet activa"
        return 0
    else
        print_message "$YELLOW" "✗ Sin conexión a internet"
        return 1
    fi
}

show_network_interfaces() {
    print_message "$CYAN" "Interfaces de red disponibles:"
    echo ""
    ip -br link show | awk '{print "  - " $1 " (" $2 ")"}'
    echo ""
    ip -br addr show | grep -v "lo" | awk '$3 == "inet" {print "    IP: " $4}'
}

setup_ethernet_connection() {
    print_message "$CYAN" "Configurando conexión por cable..."
    local ethernet_interfaces
    ethernet_interfaces=$(ip -br link show | grep -E "eth|enp|ens" | awk '{print $1}')
    if [ -z "$ethernet_interfaces" ]; then
        print_message "$RED" "No se encontraron interfaces ethernet disponibles."
        return 1
    fi
    local interface
    if [ "$(echo "$ethernet_interfaces" | wc -l)" -eq 1 ]; then
        interface=$ethernet_interfaces
        print_message "$GREEN" "Usando interfaz: $interface"
    else
        print_message "$CYAN" "Seleccione una interfaz ethernet:"
        select interface in $ethernet_interfaces; do
            if [ -n "$interface" ]; then
                break
            fi
        done
    fi
    print_message "$GREEN" "Activando interfaz $interface..."
    ip link set "$interface" up
    print_message "$GREEN" "Obteniendo dirección IP por DHCP..."
    if command -v dhclient >/dev/null 2>&1; then
        dhclient -v "$interface"
    elif command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$interface"
    else
        print_message "$YELLOW" "No se encontró cliente DHCP. Intentando con ip route..."
        ip addr add 192.168.1.100/24 dev "$interface" 2>/dev/null || true
        ip route add default via 192.168.1.1 2>/dev/null || true
    fi
    sleep 2
    if check_internet_connection; then
        print_message "$GREEN" "✓ Conexión ethernet configurada exitosamente"
        return 0
    else
        print_message "$YELLOW" "Conexión ethernet configurada pero sin acceso a internet"
        return 1
    fi
}

scan_wifi_networks() {
    local interface=$1
    print_message "$CYAN" "Escaneando redes WiFi disponibles..."
    if ! command -v iwlist >/dev/null 2>&1; then
        print_message "$RED" "Comando 'iwlist' no encontrado. Instale wireless-tools."
        return 1
    fi
    ip link set "$interface" up
    local networks
    networks=$(iwlist "$interface" scan 2>/dev/null | grep -E "ESSID|Encryption key" | paste - - | sed 's/.*ESSID:"\(.*\)".*Encryption key:\(.*\)/\1 (\2)/')
    if [ -z "$networks" ]; then
        print_message "$YELLOW" "No se encontraron redes WiFi disponibles."
        return 1
    fi
    echo ""
    print_message "$CYAN" "Redes WiFi disponibles:"
    echo "$networks" | nl -w2 -s') '
    echo ""
    return 0
}

connect_to_wifi() {
    local interface=$1
    local ssid=$2
    local password=$3
    if command -v nmcli >/dev/null 2>&1; then
        print_message "$GREEN" "Conectando a WiFi usando NetworkManager..."
        nmcli dev wifi connect "$ssid" password "$password" ifname "$interface"
    elif command -v wpa_passphrase >/dev/null 2>&1 && command -v wpa_supplicant >/dev/null 2>&1; then
        print_message "$GREEN" "Conectando a WiFi usando wpa_supplicant..."
        local temp_conf
        temp_conf=$(mktemp)
        wpa_passphrase "$ssid" "$password" > "$temp_conf"
        wpa_supplicant -B -i "$interface" -c "$temp_conf"
        dhclient "$interface"
        rm -f "$temp_conf"
    else
        print_message "$RED" "No se encontraron herramientas para conectar a WiFi."
        return 1
    fi
    return 0
}

connect_to_hidden_wifi() {
    local interface=$1
    local ssid=$2
    local password=$3
    if command -v nmcli >/dev/null 2>&1; then
        print_message "$GREEN" "Conectando a red WiFi oculta usando NetworkManager..."
        nmcli connection add type wifi con-name "Hidden-$ssid" ifname "$interface" ssid "$ssid" \
            wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$password" \
            802-11-wireless.hidden yes autoconnect yes
        nmcli connection up "Hidden-$ssid"
    elif command -v wpa_passphrase >/dev/null 2>&1 && command -v wpa_supplicant >/dev/null 2>&1; then
        print_message "$GREEN" "Conectando a red WiFi oculta usando wpa_supplicant..."
        local temp_conf
        temp_conf=$(mktemp)
        cat > "$temp_conf" <<EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={
    ssid="$ssid"
    scan_ssid=1
    psk="$password"
    key_mgmt=WPA-PSK
}
EOF
        wpa_supplicant -B -i "$interface" -c "$temp_conf"
        dhclient "$interface"
        rm -f "$temp_conf"
    else
        print_message "$RED" "No se encontraron herramientas para conectar a redes ocultas."
        return 1
    fi
    return 0
}

setup_wifi_connection() {
    print_message "$CYAN" "Configurando conexión WiFi..."
    local wifi_interfaces
    wifi_interfaces=$(ip -br link show | grep -E "wlan|wlp|wlx" | awk '{print $1}')
    if [ -z "$wifi_interfaces" ]; then
        print_message "$RED" "No se encontraron interfaces WiFi disponibles."
        return 1
    fi
    local interface
    if [ "$(echo "$wifi_interfaces" | wc -l)" -eq 1 ]; then
        interface=$wifi_interfaces
        print_message "$GREEN" "Usando interfaz WiFi: $interface"
    else
        print_message "$CYAN" "Seleccione una interfaz WiFi:"
        select interface in $wifi_interfaces; do
            if [ -n "$interface" ]; then
                break
            fi
        done
    fi
    if scan_wifi_networks "$interface"; then
        local hidden_net
        hidden_net=$(prompt_yes_no "¿Desea conectar a una red WiFi oculta? (no/yes)" "no")
        local ssid=""
        local password=""
        if [ "$hidden_net" = "yes" ]; then
            ssid=$(get_user_input "Nombre de la red WiFi oculta (SSID)" "")
            password=$(get_user_input "Contraseña de la red" "" true)
            connect_to_hidden_wifi "$interface" "$ssid" "$password"
        else
            local network_choice
            network_choice=$(get_user_input "Seleccione el número de la red WiFi a la que conectar" "1")
            ssid=$(iwlist "$interface" scan 2>/dev/null | grep -A 1 "ESSID" | sed -n "${network_choice}p" | sed 's/.*ESSID:"\(.*\)"/\1/')
            password=$(get_user_input "Contraseña para $ssid" "" true)
            connect_to_wifi "$interface" "$ssid" "$password"
        fi
    else
        print_message "$YELLOW" "No se encontraron redes WiFi visibles."
        local try_hidden
        try_hidden=$(prompt_yes_no "¿Desea intentar conectar a una red WiFi oculta? (yes/no)" "yes")
        if [ "$try_hidden" = "yes" ]; then
            local hidden_ssid
            hidden_ssid=$(get_user_input "Nombre de la red WiFi oculta (SSID)" "")
            local hidden_password
            hidden_password=$(get_user_input "Contraseña de la red" "" true)
            connect_to_hidden_wifi "$interface" "$hidden_ssid" "$hidden_password"
        else
            return 1
        fi
    fi
    sleep 5
    if check_internet_connection; then
        print_message "$GREEN" "✓ Conexión WiFi configurada exitosamente"
        return 0
    else
        print_message "$YELLOW" "Conexión WiFi configurada pero sin acceso a internet"
        return 1
    fi
}

setup_network_connection() {
    print_message "$CYAN" "Configuración de conexión a internet"
    echo "================================================================"
    if check_internet_connection; then
        print_message "$GREEN" "Ya tiene una conexión activa. ¿Desea reconfigurarla?"
        local reconfig
        reconfig=$(prompt_yes_no "¿Reconfigurar conexión? (yes/no)" "no")
        if [ "$reconfig" != "yes" ]; then
            return 0
        fi
    fi
    show_network_interfaces
    print_message "$CYAN" "Seleccione el tipo de conexión:"
    local connection_type
    select connection_type in "Ethernet (cable)" "WiFi" "WiFi oculta" "Saltar configuración"; do
        case $connection_type in
            "Ethernet (cable)")
                setup_ethernet_connection && return 0
                ;;
            "WiFi")
                setup_wifi_connection && return 0
                ;;
            "WiFi oculta")
                setup_wifi_connection && return 0
                ;;
            "Saltar configuración")
                print_message "$YELLOW" "Advertencia: Sin conexión a internet, la instalación puede fallar o ser muy lenta."
                local proceed
                proceed=$(prompt_yes_no "¿Desea continuar sin conexión a internet? (yes/no)" "no")
                if [ "$proceed" = "yes" ]; then
                    return 0
                else
                    continue
                fi
                ;;
            *)
                print_message "$RED" "Opción no válida"
                ;;
        esac
    done
    return 1
}

# =============================================================================
# FUNCIONES DE DETECCIÓN DE REQUISITOS
# =============================================================================
check_system_requirements() {
    print_message "$CYAN" "Verificando requisitos del sistema..."
    # Verificar espacio en disco
    local required_space_gb=20
    local available_space_gb
    available_space_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$available_space_gb" -lt "$required_space_gb" ]; then
        print_message "$RED" "ERROR: Se requieren al menos ${required_space_gb}GB de espacio libre."
        print_message "$YELLOW" "Espacio disponible: ${available_space_gb}GB"
        exit 1
    fi
    # Verificar RAM mínima
    local required_ram_gb=2
    local available_ram_gb
    available_ram_gb=$(free -g --si | awk 'FNR == 2 {print $2}')
    if [ "$available_ram_gb" -lt "$required_ram_gb" ]; then
        print_message "$YELLOW" "ADVERTENCIA: Se recomienda al menos ${required_ram_gb}GB de RAM."
        print_message "$YELLOW" "RAM detectada: ${available_ram_gb}GB"
        local proceed
        proceed=$(prompt_yes_no "¿Continuar de todas formas?" "no")
        if [ "$proceed" != "yes" ]; then
            exit 1
        fi
    fi
    print_message "$GREEN" "✓ Requisitos del sistema verificados"
}

# =============================================================================
# FUNCIONES DE SELECCIÓN INTERACTIVA
# =============================================================================
select_keyboard_layout() {
    print_message "$CYAN" "Seleccione su distribución de teclado:"
    # Listar layouts disponibles
    local layouts
    layouts=$(find /run/current-system/profile/share/keymaps/ -name "*.map.gz" 2>/dev/null | 
             sed 's|.*/||; s/\.map\.gz$//' | sort)
    if [ -z "$layouts" ]; then
        print_message "$YELLOW" "No se encontraron layouts disponibles. Usando valor por defecto."
        echo "${DEFAULTS[keyboard]}"
        return
    fi
    select layout in $layouts "back"; do
        case $layout in
            "back")
                return 1
                ;;
            *)
                if [ -n "$layout" ]; then
                    echo "$layout"
                    return 0
                fi
                ;;
        esac
    done
}

configure_keyboard_layout() {
    local current_layout="${DEFAULTS[keyboard]}"
    while true; do
        print_message "$CYAN" "Layout actual: $current_layout"
        local choice
        choice=$(prompt_yes_no "¿Cambiar layout de teclado? (yes/no)" "no")
        if [ "$choice" = "yes" ]; then
            local new_layout
            new_layout=$(select_keyboard_layout)
            if [ -n "$new_layout" ] && [ "$new_layout" != "back" ]; then
                current_layout="$new_layout"
                # Probar el layout temporalmente
                if command -v loadkeys >/dev/null 2>&1; then
                    loadkeys "$current_layout" 2>/dev/null || true
                fi
                print_message "$GREEN" "Layout cambiado a: $current_layout"
            fi
        else
            break
        fi
    done
    echo "$current_layout"
}

select_timezone_interactive() {
    print_message "$CYAN" "Seleccione su continente:"
    local continents=(
        "Africa"
        "America"
        "Antarctica"
        "Arctic"
        "Asia"
        "Atlantic"
        "Australia"
        "Europe"
        "Indian"
        "Pacific"
    )
    select continent in "${continents[@]}" "back"; do
        if [ "$continent" = "back" ]; then
            return 1
        elif [ -n "$continent" ]; then
            print_message "$CYAN" "Seleccione su ciudad en $continent:"
            local cities
            cities=$(timedatectl list-timezones | grep "^$continent/" | sed "s|$continent/||")
            select city in $cities "back"; do
                if [ "$city" = "back" ]; then
                    break
                elif [ -n "$city" ]; then
                    echo "$continent/$city"
                    return 0
                fi
            done
        fi
    done
}

select_timezone() {
    print_message "$CYAN" "Seleccione su zona horaria:"
    # Intentar interfaz interactiva primero
    local selected_tz
    selected_tz=$(select_timezone_interactive)
    if [ -z "$selected_tz" ] || [ "$selected_tz" = "back" ]; then
        # Si falla la interfaz interactiva, usar el método simple
        local timezones
        timezones=$(timedatectl list-timezones 2>/dev/null)
        if [ -z "$timezones" ]; then
            print_message "$YELLOW" "No se pudieron listar las zonas horarias. Usando valor por defecto."
            echo "${DEFAULTS[timezone]}"
            return
        fi
        echo ""
        local count=1
        for tz in $timezones; do
            printf "%-40s" "$tz"
            if (( count % 2 == 0 )); then
                echo ""
            fi
            ((count++))
        done
        echo ""
        echo ""
        selected_tz=$(get_user_input "Ingrese su zona horaria" "${DEFAULTS[timezone]}")
        # Validar timezone
        if timedatectl list-timezones | grep -q "^$selected_tz$"; then
            echo "$selected_tz"
        else
            print_message "$YELLOW" "Zona horaria no válida. Usando valor por defecto."
            echo "${DEFAULTS[timezone]}"
        fi
    else
        echo "$selected_tz"
    fi
}

# =============================================================================
# FUNCIONES DE ENCRIPTACIÓN
# =============================================================================
setup_encryption() {
    local partition=$1
    print_message "$CYAN" "¿Desea encriptar el disco con LUKS? (yes/no)"
    local encrypt_choice
    encrypt_choice=$(prompt_yes_no "Encriptar disco" "no")
    if [ "$encrypt_choice" = "yes" ]; then
        print_message "$YELLOW" "ADVERTENCIA: Se encriptará la partición $partition. Todos los datos serán borrados."
        local confirm
        confirm=$(prompt_yes_no "¿Está seguro? (yes/no)" "no")
        if [ "$confirm" != "yes" ]; then
            return 1
        fi
        print_message "$CYAN" "Seleccione versión de LUKS:"
        select luks_version in "LUKS1 (compatible con GRUB)" "LUKS2 (mejor rendimiento)"; do
            case $luks_version in
                "LUKS1 (compatible con GRUB)")
                    luks_opts="--type luks1"
                    break
                    ;;
                "LUKS2 (mejor rendimiento)")
                    luks_opts="--type luks2"
                    break
                    ;;
            esac
        done
        print_message "$GREEN" "Formateando partición con LUKS..."
        # shellcheck disable=SC2086
        cryptsetup luksFormat $luks_opts "$partition"
        print_message "$GREEN" "Abriendo partición encriptada..."
        cryptsetup open "$partition" "$ENCRYPTED_NAME"
        ENCRYPT_DISK="yes"
        LUKS_UUID=$(blkid -s UUID -o value "$partition")
        ROOT_PARTITION="/dev/mapper/$ENCRYPTED_NAME"
        return 0
    fi
    ENCRYPT_DISK="no"
    ROOT_PARTITION="$partition"
    return 0
}

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN DE SWAP E HIBERNACIÓN
# =============================================================================
configure_swap() {
    if [ "$CREATE_SWAP" = "yes" ]; then
        print_message "$GREEN" "Creando archivo swap para hibernación..."
        mkdir -p "$MOUNT_POINT/swap"
        truncate -s 0 "$MOUNT_POINT/swap/swapfile"
        chattr +C "$MOUNT_POINT/swap/swapfile" 2>/dev/null || true
        # Tamaño del swapfile basado en la RAM disponible
        local ram_size_gb
        ram_size_gb=$(free -g --si | awk 'FNR == 2 {print $2}')
        local swap_size_gb=$((ram_size_gb < 8 ? ram_size_gb : 8))
        print_message "$CYAN" "Tamaño de RAM detectado: ${ram_size_gb}GB, creando swapfile de ${swap_size_gb}GB..."
        btrfs filesystem mkswapfile --size "${swap_size_gb}g" --uuid clear "$MOUNT_POINT/swap/swapfile"
        chmod 600 "$MOUNT_POINT/swap/swapfile"
        # Obtener información para hibernación
        local RESUME_UUID_TEMP
        RESUME_UUID_TEMP=$(blkid -s UUID -o value "$ROOT_UUID")
        local RESUME_OFFSET_TEMP
        RESUME_OFFSET_TEMP=$(btrfs inspect-internal map-swapfile -r "$MOUNT_POINT/swap/swapfile" 2>/dev/null || echo "0")
        # Guardar valores para usar en la configuración del kernel
        echo "RESUME_UUID=$RESUME_UUID_TEMP" > "$MOUNT_POINT/etc/guix-install-vars"
        echo "RESUME_OFFSET=$RESUME_OFFSET_TEMP" >> "$MOUNT_POINT/etc/guix-install-vars"
        echo "SWAP_SIZE=${swap_size_gb}g" >> "$MOUNT_POINT/etc/guix-install-vars"
        RESUME_UUID="$RESUME_UUID_TEMP"
        RESUME_OFFSET="$RESUME_OFFSET_TEMP"
        print_message "$GREEN" "Swapfile creado exitosamente para hibernación"
        print_message "$CYAN" "UUID de hibernación: $RESUME_UUID"
        print_message "$CYAN" "Offset de hibernación: $RESUME_OFFSET"
    fi
}

check_hibernation_support() {
    print_message "$CYAN" "Verificando soporte para hibernación..."
    if [ "$CREATE_SWAP" != "yes" ]; then
        print_message "$YELLOW" "Hibernación no habilitada - no se creó swapfile"
        return 1
    fi
    # Verificar tamaño del swapfile
    local ram_size_gb
    ram_size_gb=$(free -g --si | awk 'FNR == 2 {print $2}')
    if [ "$SWAP_SIZE" -lt "$ram_size_gb" ]; then
        print_message "$YELLOW" "ADVERTENCIA: El swapfile (${SWAP_SIZE}GB) es menor que la RAM (${ram_size_gb}GB)"
        print_message "$YELLOW" "La hibernación puede no funcionar correctamente"
        local proceed
        proceed=$(prompt_yes_no "¿Desea continuar de todas formas? (yes/no)" "yes")
        if [ "$proceed" != "yes" ]; then
            return 1
        fi
    fi
    print_message "$GREEN" "✓ Soporte para hibernación verificado"
    return 0
}

# =============================================================================
# FUNCIONES DE OPTIMIZACIONES DEL KERNEL
# =============================================================================
configure_grub_optimizations() {
    local hdd_ssd=$1
    local resume_uuid=$2
    local resume_offset=$3
    print_message "$CYAN" "Configurando optimizaciones del sistema..."
    local kernel_params="quiet splash fbcon=nodefer"
    # Optimizaciones específicas para SSD
    if [[ "$hdd_ssd" == *"ssd"* ]]; then
        kernel_params+=" zswap.enabled=1 zswap.max_pool_percent=25 zswap.compressor=zstd zswap.zpool=zsmalloc"
    fi
    # Parámetros para encriptación
    if [ "$ENCRYPT_DISK" = "yes" ]; then
        kernel_params+=" rd.auto=1 rd.luks.name=$LUKS_UUID=$ENCRYPTED_NAME"
        if [[ "$hdd_ssd" == *"ssd"* ]]; then
            kernel_params+=" rd.luks.allow-discards=$LUKS_UUID"
        fi
    fi
    # Soporte para hibernación si existe swapfile
    if [ -n "$resume_uuid" ] && [ -n "$resume_offset" ] && [ "$resume_offset" != "0" ]; then
        kernel_params+=" resume=UUID=$resume_uuid resume_offset=$resume_offset"
    fi
    echo "$kernel_params"
}

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN DEL SISTEMA
# =============================================================================
generate_guix_config() {
    local config_file=$1
    local hostname=$2
    local timezone=$3
    local keyboard=$4
    local login_name=$5
    local desktop=$6
    local use_nonguix=$7
    local create_swap=$8
    local encrypt_disk=$9
    # Cargar variables de hibernación si existen
    if [ -f "$MOUNT_POINT/etc/guix-install-vars" ]; then
        # shellcheck disable=SC1091
        source "$MOUNT_POINT/etc/guix-install-vars"
    fi
    # Obtener optimizaciones del kernel con soporte para hibernación
    local kernel_params
    kernel_params=$(configure_grub_optimizations "$SSD_OPTION" "$RESUME_UUID" "$RESUME_OFFSET")
    {
    cat <<EOF
(use-modules (gnu)
             (gnu system)
             (gnu packages admin)
             (gnu packages version-control)
             (gnu packages web-browsers)
             (gnu packages terminals)
             (gnu packages editors)
             (gnu packages emacs)
             (gnu packages linux)
             (gnu packages compression)
             (gnu packages kde-frameworks)
             (gnu packages kde-plasma)
             (gnu packages flatpak)
             (gnu packages base)
             (gnu packages certs)
             (gnu packages package-management)
             (srfi srfi-1))
(use-service-modules desktop
                     networking
                     ssh
                     audio
                     dbus
                     xorg
                     sddm
                     flatpak)
EOF
    if [ "$use_nonguix" = "yes" ]; then
        cat <<EOF
(use-modules (nongnu packages linux)
             (nongnu packages firmware)
             (nongnu system linux-initrd))
EOF
    fi
    cat <<EOF
(operating-system
  (host-name "$hostname")
  (timezone "$timezone")
  (locale "es_CR.utf8")
  (locale-definitions
   (list (locale-definition
          (source "en_US")
          (name "en_US.utf8"))
         (locale-definition
          (source "es_CR")
          (name "es_CR.utf8"))))
EOF
    if [ "$use_nonguix" = "yes" ]; then
        cat <<EOF
  (kernel linux)
  (initrd microcode-initrd)
  (firmware (list linux-firmware firmware-zd1211 intel-microcode))
EOF
        # Módulos adicionales para encriptación y hibernación
        if [ "$encrypt_disk" = "yes" ] || [ "$create_swap" = "yes" ]; then
            cat <<EOF
  (initrd-modules (append (list "btrfs" "crc32c-intel" "aes" "x86_64" "dm-crypt" "dm-mod" "zram" "zstd" "crypto_zstd")
                         %base-initrd-modules))
EOF
        else
            cat <<EOF
  (initrd-modules (append (list "btrfs" "crc32c-intel" "aes" "x86_64" "zram" "zstd" "crypto_zstd")
                         %base-initrd-modules))
EOF
        fi
    else
        cat <<EOF
  (kernel linux-libre)
  (firmware %base-firmware)
  (initrd-modules (append (list "btrfs" "crc32c-intel" "aes" "x86_64" "zram" "zstd" "crypto_zstd")
                         %base-initrd-modules))
EOF
    fi
    cat <<EOF
  (bootloader (bootloader-configuration
               (bootloader grub-bootloader)
               (targets '("/dev/sda"))
               (keyboard-layout (keyboard-layout "$keyboard"))
               (bootloader-extra-arguments
                '(("GRUB_CMDLINE_LINUX_DEFAULT" . "\"$kernel_params\"")))))
  (keyboard-layout (keyboard-layout "$keyboard"))
  (file-systems (append (list 
EOF
    # Configuración de filesystems
    cat <<EOF
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/")
                          (type "btrfs")
                          (options "subvol=@root,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/home")
                          (type "btrfs")
                          (options "subvol=@home,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/var/guix")
                          (type "btrfs")
                          (options "subvol=@guix,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/var/log")
                          (type "btrfs")
                          (options "subvol=@var_log,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/persist")
                          (type "btrfs")
                          (options "subvol=@persist,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/tmp")
                          (type "tmpfs")
                          (options "size=2G,noatime,mode=1777")
                          (needed-for-boot? #f))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/var/tmp")
                          (type "btrfs")
                          (options "subvol=@vartmp,compress=zstd:3,$SSD_OPTION,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$EFI_UUID" 'fat))
                          (mount-point "/boot/efi")
                          (type "vfat")
                          (options "rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=utf8,shortname=mixed,utf8,errors=remount-ro")
                          (needed-for-boot? #t))
EOF
    if [ "$create_swap" = "yes" ]; then
        cat <<EOF
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/swap")
                          (type "btrfs")
                          (options "subvol=@swap,noatime")
                          (needed-for-boot? #t))
                        (file-system
                          (device "/swap/swapfile")
                          (mount-point "none")
                          (type "swap")
                          (options "defaults,pri=-1")
                          (needed-for-boot? #t))
EOF
    fi
    cat <<EOF
                        %base-file-systems))
  (users (cons (user-account
                (name "$login_name")
                (comment "Usuario principal")
                (group "users")
                (supplementary-groups '("wheel" "netdev" "audio" "video" "kvm" "input" "lp" "realtime")))
               %base-user-accounts))
  (sudoers-file (plain-file "sudoers"
                           "root ALL=(ALL) ALL
%wheel ALL=(ALL) ALL
"))
  (services (append (list 
                     (service network-manager-service-type)
                     (service wpa-supplicant-service-type)
                     (service openssh-service-type)
                     (service ntp-service-type)
                     (service udev-service-type)
                     (service dbus-service-type)
                     (service flatpak-service-type)
                     (service xorg-server-service-type)
                     (simple-service 'xorg-configuration
                                    xorg-service-type
                                    (xorg-configuration
                                     (keyboard-layout (keyboard-layout "$keyboard")))))
EOF
    case "$desktop" in
        "plasma")
            cat <<EOF
                     (service sddm-service-type
                              (sddm-configuration
                               (display-server "wayland")
                               (wayland-session "plasma")
                               (numlock "on")))
                     (service plasma-desktop-service-type
                              (plasma-desktop-configuration
                               (packages (list kdeconnect kcalc kate konsole dolphin ark gwenview okular spectacle systemsettings plasma-systemmonitor ksystemlog plasma-browser-integration plasma-pa plasma-nm))))
                     (service elogind-service-type)
                     (service upower-service-type)
                     (service bluez-service-type)
EOF
            ;;
        "gnome")
            cat <<EOF
                     (service gnome-desktop-service-type)
                     (service gdm-service-type)
EOF
            ;;
        "xfce")
            cat <<EOF
                     (service xfce-desktop-service-type)
                     (service lightdm-service-type)
EOF
            ;;
        "mate")
            cat <<EOF
                     (service mate-desktop-service-type)
                     (service lightdm-service-type)
EOF
            ;;
        "i3")
            cat <<EOF
                     (service i3-desktop-service-type)
                     (service lightdm-service-type)
EOF
            ;;
        "sway")
            cat <<EOF
                     (service sway-service-type)
EOF
            ;;
    esac
    cat <<EOF
                     (service pipewire-service-type)
                     (service alsa-service-type)
                     (service (simple-service 'set-mtu
                                            (service-extension activation-service-type
                                                               (lambda _
                                                                 #'(lambda _
                                                                     (zero? (system* "ip" "link" "set" "dev" "eth0" "mtu" "9000"))))))
                     ))
  (packages (append (list 
                     git curl wget nss-certs gnutls htop file ripgrep tree
                     firefox qutebrowser
                     neovim emacs emacs-pgtk
                     btrfs-progs ntfs-3g exfat-utils fuse pciutils usbutils lm-sensors powertop
                     cryptsetup  # Para soporte de encriptación
                     flatpak discover
                     intel-ucode  # Microcódigo para CPU
                     (specification->package "glibc-locales")))
EOF
    case "$desktop" in
        "plasma")
            cat <<EOF
                   (list plasma-framework
                         plasma-workspace
                         plasma-desktop
                         kde-cli-tools
                         kate
                         konsole
                         dolphin
                         ark
                         gwenview
                         okular
                         spectacle
                         kcalc
                         systemsettings
                         plasma-systemmonitor
                         ksystemlog
                         plasma-browser-integration
                         plasma-pa
                         plasma-nm
                         kdeconnect
                         kde-config-flatpak)
EOF
            ;;
        "gnome")
            cat <<EOF
                   (list gnome-shell
                         gnome-terminal
                         nautilus
                         gedit
                         evince
                         eog
                         gnome-system-monitor
                         gnome-tweaks)
EOF
            ;;
        "xfce")
            cat <<EOF
                   (list xfce4
                         xfce4-terminal
                         thunar
                         mousepad
                         xfce4-taskmanager
                         xfce4-settings)
EOF
            ;;
        "mate")
            cat <<EOF
                   (list mate-desktop
                         mate-terminal
                         caja
                         pluma
                         atril
                         mate-system-monitor)
EOF
            ;;
        "i3")
            cat <<EOF
                   (list i3-wm
                         i3status
                         i3lock
                         rofi
                         polybar
                         dmenu
                         feh
                         picom)
EOF
            ;;
    esac
    cat <<EOF
                   %base-packages))
  (name-service-switch %mdns-host-lookup-nss)
)
EOF
    } > "$config_file"
}

generate_channels_config() {
    local channels_file=$1
    local use_nonguix=$2
    {
    cat <<EOF
(cons* (channel
        (name 'guix)
        (url "https://git.savannah.gnu.org/git/guix.git")
        (branch "master")
        (introduction
         (make-channel-introduction
          "897c1a470da759236cc10598f73e5e1a0f0dc17e"
          (openpgp-fingerprint
           "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))
EOF
    if [ "$use_nonguix" = "yes" ]; then
        cat <<EOF
       (channel
        (name 'nonguix)
        (url "https://gitlab.com/nonguix/nonguix")
        (branch "master")
        (introduction
          (make-channel-introduction
            "897c1a470da759236cc10598f73e5e1a0f0dc17e"
            (openpgp-fingerprint
              "2A39 3FFF 68F4 EF7A 3D29  12AF 6F51 20A0 22FB B2D5"))))
EOF
    fi
    cat <<EOF
       %default-channels)
EOF
    } > "$channels_file"
}

# =============================================================================
# CONFIGURACIÓN DE DISCOS Y PARTICIONES
# =============================================================================
setup_disk() {
    local disk_device=$1
    local dev_name
    dev_name=$(basename "$disk_device")
    local part_prefix=""
    if [[ "${dev_name: -1}" =~ [0-9] ]]; then
        part_prefix="p"
    fi
    detect_ssd "$disk_device"
    print_message "$GREEN" "Particionando el disco $disk_device..."
    parted "$disk_device" --script -- mklabel gpt
    parted "$disk_device" --script -- mkpart ESP fat32 1MiB 551MiB
    parted "$disk_device" --script -- set 1 esp on
    parted "$disk_device" --script -- mkpart root btrfs 551MiB 100%
    print_message "$GREEN" "Formateando particiones..."
    mkfs.fat -F 32 -n ESP "${disk_device}${part_prefix}1"
    # Configurar encriptación si se seleccionó
    if [ "$ENCRYPT_DISK_CHOICE" = "yes" ]; then
        setup_encryption "${disk_device}${part_prefix}2"
    else
        mkfs.btrfs -f -L guix-root "${disk_device}${part_prefix}2"
        ROOT_PARTITION="${disk_device}${part_prefix}2"
    fi
    print_message "$GREEN" "Montando y creando subvolúmenes..."
    mkdir -p "$MOUNT_POINT"
    mount "$ROOT_PARTITION" "$MOUNT_POINT"
    local subvolumes=("@root" "@home" "@guix" "@var_log" "@persist" "@vartmp")
    if [ "$CREATE_SWAP" = "yes" ]; then
        subvolumes+=("@swap")
    fi
    for subvol in "${subvolumes[@]}"; do
        btrfs subvolume create "$MOUNT_POINT/$subvol"
    done
    btrfs subvolume snapshot -r "$MOUNT_POINT/@root" "$MOUNT_POINT/@root-blank"
    umount "$MOUNT_POINT"
    local mount_opts="rw,relatime,compress=zstd:3,$SSD_OPTION"
    print_message "$GREEN" "Montando subvolúmenes..."
    mount -o "$mount_opts,subvol=@root" "${disk_device}${part_prefix}2" "$MOUNT_POINT"
    local mount_points=(
        "home:@home"
        "var/guix:@guix"
        "var/log:@var_log"
        "persist:@persist"
        "var/tmp:@vartmp"
        "boot/efi:efi"
    )
    if [ "$CREATE_SWAP" = "yes" ]; then
        mount_points+=("swap:@swap")
    fi
    for mount_point in "${mount_points[@]}"; do
        IFS=':' read -r dir subvol <<< "$mount_point"
        mkdir -p "$MOUNT_POINT/$dir"
        if [ "$subvol" = "efi" ]; then
            mount -o "rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=utf8,shortname=mixed,utf8,errors=remount-ro" \
                  "${disk_device}${part_prefix}1" "$MOUNT_POINT/$dir"
        else
            mount -o "$mount_opts,subvol=$subvol" "${disk_device}${part_prefix}2" "$MOUNT_POINT/$dir"
        fi
    done
    if [ "$CREATE_SWAP" = "yes" ]; then
        configure_swap
    fi
    EFI_UUID=$(get_partition_uuid "${disk_device}${part_prefix}1")
    ROOT_UUID=$(get_partition_uuid "$ROOT_PARTITION")
    print_message "$GREEN" "Estructura de discos configurada correctamente."
    print_message "$CYAN" "UUID EFI: $EFI_UUID"
    print_message "$CYAN" "UUID Root: $ROOT_UUID"
    print_message "$CYAN" "Opción SSD: $SSD_OPTION"
}

# =============================================================================
# CONFIGURACIÓN DEL SISTEMA Y USUARIO
# =============================================================================
configure_system() {
    local self_conf
    self_conf=$(prompt_yes_no "¿Desea modificar la configuración manualmente?")
    if [ "$self_conf" = "no" ]; then
        local hostname
        hostname=$(get_user_input "Nombre del equipo" "${DEFAULTS[hostname]}")
        local timezone
        timezone=$(select_timezone)
        local keyboard
        keyboard=$(configure_keyboard_layout)
        local login_name
        login_name=$(get_user_input "Nombre de usuario" "${DEFAULTS[login_name]}")
        local desktop
        desktop=$(get_user_input "Entorno de escritorio" "${DEFAULTS[desktop]}")
        local use_nonguix
        use_nonguix=$(get_user_input "¿Usar canal nonguix para firmware no libre?" "${DEFAULTS[use_nonguix]}")
        CREATE_SWAP=$(prompt_yes_no "¿Crear archivo swap para hibernación?" "${DEFAULTS[create_swap]}")
        # Opción de encriptación
        print_message "$CYAN" "Configuración de seguridad:"
        ENCRYPT_DISK_CHOICE=$(prompt_yes_no "¿Encriptar el disco con LUKS?" "no")
        if ! validate_desktop "$desktop"; then
            print_message "$RED" "Entorno de escritorio no válido. Usando valor por defecto: ${DEFAULTS[desktop]}"
            desktop="${DEFAULTS[desktop]}"
        fi
        mkdir -p "$GUIX_CONFIG_DIR"
        print_message "$GREEN" "Generando configuración de Guix..."
        generate_guix_config "$GUIX_CONFIG_DIR/system.scm" "$hostname" "$timezone" \
            "$keyboard" "$login_name" "$desktop" "$use_nonguix" "$CREATE_SWAP" "$ENCRYPT_DISK_CHOICE"
        print_message "$GREEN" "Generando configuración de canales..."
        generate_channels_config "$GUIX_CONFIG_DIR/channels.scm" "$use_nonguix"
        print_message "$GREEN" "Configuraciones generadas en $GUIX_CONFIG_DIR/"
    fi
}

setup_partitions() {
    local self_hardware
    self_hardware=$(prompt_yes_no "¿Desea modificar la configuración de hardware manualmente?")
    if [ "$self_hardware" = "no" ]; then
        print_message "$CYAN" "Discos disponibles:"
        lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE
        local disk_device=""
        while true; do
            print_message "$CYAN" "Por favor ingrese el dispositivo de disco a usar (ejemplo: /dev/nvme0n1 o /dev/sda):"
            read -r disk_device
            if [[ "$disk_device" =~ ^/dev/[a-z]+[0-9]*$ ]] && [ -b "$disk_device" ]; then
                break
            fi
            print_message "$RED" "Dispositivo no válido. Por favor ingrese un dispositivo de bloque válido."
        done
        print_message "$YELLOW" "ADVERTENCIA: Esto borrará todos los datos en ${disk_device}. ¿Está seguro de continuar? (yes/no)"
        read -r response
        [[ "$response" != "yes" ]] && { print_message "$RED" "Instalación cancelada."; exit 1; }
        setup_disk "$disk_device"
    fi
}

# =============================================================================
# PREPARACIÓN DE INSTALACIÓN - VERSIÓN CORREGIDA CON COW-STORE
# =============================================================================
prepare_guix_installation() {
    print_message "$GREEN" "Preparando instalación de Guix..."
    
    # Crear directorios esenciales
    mkdir -p "$MOUNT_POINT/etc"
    mkdir -p "$MOUNT_POINT/var/guix"
    
    # ✅ CORRECCIÓN CRÍTICA: Copiar configuraciones a /mnt/etc/
    if [ -f "$GUIX_CONFIG_DIR/system.scm" ]; then
        cp "$GUIX_CONFIG_DIR/system.scm" "$MOUNT_POINT/etc/system.scm"
        print_message "$GREEN" "✓ system.scm copiado a $MOUNT_POINT/etc/"
    else
        print_message "$RED" "ERROR: No se encontró $GUIX_CONFIG_DIR/system.scm"
        print_message "$YELLOW" "Por favor, ejecute primero la configuración del sistema"
        exit 1
    fi
    
    if [ -f "$GUIX_CONFIG_DIR/channels.scm" ]; then
        cp "$GUIX_CONFIG_DIR/channels.scm" "$MOUNT_POINT/etc/channels.scm"
        print_message "$GREEN" "✓ channels.scm copiado a $MOUNT_POINT/etc/"
    else
        print_message "$RED" "ERROR: No se encontró $GUIX_CONFIG_DIR/channels.scm"
        exit 1
    fi
    
    # Verificar que los archivos están en la ubicación correcta
    if [ ! -f "$MOUNT_POINT/etc/system.scm" ] || [ ! -f "$MOUNT_POINT/etc/channels.scm" ]; then
        print_message "$RED" "ERROR: Los archivos de configuración no se copiaron correctamente"
        print_message "$YELLOW" "Archivos esperados en: $MOUNT_POINT/etc/"
        ls -la "$MOUNT_POINT/etc/" || true
        exit 1
    fi
    
    # ✅ CORRECCIÓN CRÍTICA: Inicializar cow-store
    print_message "$GREEN" "Inicializando cow-store en $MOUNT_POINT..."
    if ! herd start cow-store "$MOUNT_POINT"; then
        print_message "$RED" "ERROR: No se pudo inicializar cow-store en $MOUNT_POINT"
        print_message "$YELLOW" "Esto es necesario para que Guix pueda construir el sistema"
        exit 1
    fi
    print_message "$GREEN" "✓ cow-store inicializado correctamente"
    
    print_message "$GREEN" "Configurando el daemon de Guix..."
    mkdir -p "$MOUNT_POINT/var/guix/profiles/per-user/root"
    chown -R root:root "$MOUNT_POINT/var/guix"
    chmod -R 755 "$MOUNT_POINT/var/guix"
    
    # Configurar sustitutos
    authorize_nonguix_key
    
    local substitute_urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    if [ "$use_nonguix" = "yes" ]; then
        if curl -sfI --max-time 3 https://substitutes.nonguix.org &>/dev/null; then
            substitute_urls="$substitute_urls https://substitutes.nonguix.org"
            print_message "$CYAN" "Usando sustitutos oficiales de nonguix: substitutes.nonguix.org"
        else
            substitute_urls="$substitute_urls https://nonguix-proxy.ditigal.xyz"
            print_message "$YELLOW" "substitutes.nonguix.org no accesible. Usando mirror: nonguix-proxy.ditigal.xyz"
        fi
    fi
    
    restart_guix_daemon_with_substitutes "$substitute_urls"
    
    print_message "$GREEN" "Verificando conexión a internet..."
    if ! check_internet_connection; then
        print_message "$YELLOW" "No se detecta conexión a internet. Algunas operaciones pueden fallar."
        read -r -p "¿Desea continuar sin conexión a internet? (yes/no) " response
        [[ "$response" != "yes" ]] && exit 1
    fi
    
    # ✅ Verificación final antes de instalar
    print_message "$CYAN" "Verificación final de archivos de configuración:"
    print_message "$GREEN" "✓ system.scm: $MOUNT_POINT/etc/system.scm"
    print_message "$GREEN" "✓ channels.scm: $MOUNT_POINT/etc/channels.scm"
    print_message "$GREEN" "✓ cow-store: inicializado en $MOUNT_POINT"
    
    if [ -f "$MOUNT_POINT/etc/guix-install-vars" ]; then
        print_message "$GREEN" "✓ Variables de instalación: $MOUNT_POINT/etc/guix-install-vars"
    fi
}

install_guix_system() {
    print_message "$GREEN" "Iniciando instalación de Guix System..."
    if [ ! -f "$MOUNT_POINT/etc/system.scm" ]; then
        print_message "$RED" "Error: No se encontró el archivo de configuración del sistema."
        print_message "$YELLOW" "Por favor, asegúrese de que $MOUNT_POINT/etc/system.scm existe."
        exit 1
    fi

    local substitute_urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    if [ "$use_nonguix" = "yes" ]; then
        if curl -sfI --max-time 3 https://substitutes.nonguix.org &>/dev/null; then
            substitute_urls="$substitute_urls https://substitutes.nonguix.org"
        else
            substitute_urls="$substitute_urls https://nonguix-proxy.ditigal.xyz"
        fi
    fi
    print_message "$YELLOW" "Usando servidores de sustitución: $substitute_urls"
    print_message "$CYAN" "Instalando Guix System. Esto puede tomar varios minutos..."

    # ✅ Intento 1: con --fallback
    if ! guix system init "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" \
        --substitute-urls="$substitute_urls" \
        --fallback; then

        print_message "$RED" "Error durante la instalación principal."
        print_message "$YELLOW" "Intentando con --no-grafts..."

        # ✅ Intento 2: con --no-grafts y --fallback
        if ! guix system init "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" \
            --substitute-urls="$substitute_urls" \
            --no-grafts --fallback; then

            print_message "$RED" "Error durante la instalación con --no-grafts."
            exit 1
        fi
    fi

    print_message "$GREEN" "¡Instalación completada exitosamente!"
}

# =============================================================================
# VERIFICACIONES
# =============================================================================
check_requirements() {
    if [ "$(id -u)" -ne 0 ]; then
        print_message "$RED" "Este script debe ejecutarse como root"
        exit 1
    fi
    if ! command -v guix >/dev/null 2>&1; then
        print_message "$RED" "Guix no está disponible. Este script debe ejecutarse desde el sistema de instalación de Guix."
        print_message "$YELLOW" "Por favor, use el ISO de nonguix: https://gitlab.com/nonguix/nonguix/-/releases"
        exit 1
    fi
    local required_commands=("parted" "mkfs.fat" "mkfs.btrfs" "btrfs" "guix" "blkid" "lsblk" "ping" "chattr" "ip" "curl")
    local cmd
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            print_message "$RED" "Comando requerido '$cmd' no encontrado"
            print_message "$YELLOW" "Instale el paquete que contiene este comando o use un ISO más completo."
            exit 1
        fi
    done
    if [ ! -d "/sys/firmware/efi" ]; then
        print_message "$YELLOW" "ADVERTENCIA: El sistema no parece estar arrancado en modo EFI"
        print_message "$YELLOW" "El script está configurado para instalación EFI. ¿Desea continuar?"
        read -r -p "¿Continuar de todas formas? (yes/no) " response
        [[ "$response" != "yes" ]] && exit 1
    fi
    local free_space
    free_space=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$free_space" -lt 10 ]; then
        print_message "$YELLOW" "ADVERTENCIA: Espacio libre en disco bajo ($free_space GB). Se recomiendan al menos 10 GB."
        read -r -p "¿Desea continuar? (yes/no) " response
        [[ "$response" != "yes" ]] && exit 1
    fi
}

# =============================================================================
# LIMPIEZA ROBUSTA
# =============================================================================
robust_cleanup() {
    print_message "$YELLOW" "Realizando limpieza exhaustiva..."
    
    # ✅ CORRECCIÓN: Detener cow-store si está activo
    if herd status cow-store >/dev/null 2>&1; then
        print_message "$CYAN" "Deteniendo cow-store..."
        herd stop cow-store 2>/dev/null || true
    fi
    
    # Cerrar particiones encriptadas
    if [ "$ENCRYPT_DISK" = "yes" ] && [ -b "/dev/mapper/$ENCRYPTED_NAME" ]; then
        cryptsetup close "$ENCRYPTED_NAME" || true
    fi
    # Desmontar filesystems en orden inverso
    local mounts=(
        "$MOUNT_POINT/boot/efi"
        "$MOUNT_POINT/swap"
        "$MOUNT_POINT/persist"
        "$MOUNT_POINT/var/log"
        "$MOUNT_POINT/var/guix"
        "$MOUNT_POINT/home"
        "$MOUNT_POINT"
    )
    for mount_point in "${mounts[@]}"; do
        if mountpoint -q "$mount_point"; then
            # Intentar desactivar swap primero
            if [ -f "$mount_point/swapfile" ]; then
                swapoff "$mount_point/swapfile" 2>/dev/null || true
            fi
            umount -l "$mount_point"  # -l (lazy) para forzar desmontaje
        fi
    done
    # Limpiar mapeos de dispositivo
    dmsetup remove_all 2>/dev/null || true
    # Limpiar configuraciones temporales
    rm -rf "$GUIX_CONFIG_DIR" 2>/dev/null || true
    rm -f "$MOUNT_POINT/etc/guix-install-vars" 2>/dev/null || true
    print_message "$GREEN" "✓ Limpieza completada"
}

# =============================================================================
# FUNCIÓN PRINCIPAL
# =============================================================================
main() {
    trap robust_cleanup EXIT
    check_requirements
    check_system_requirements
    if ! setup_network_connection; then
        print_message "$RED" "No se pudo configurar conexión a internet."
        print_message "$YELLOW" "La instalación puede fallar o ser muy lenta sin conexión."
        read -r -p "¿Desea continuar de todas formas? (yes/no) " response
        [[ "$response" != "yes" ]] && exit 1
    fi
    print_message "$GREEN" "Iniciando instalación de Guix System..."
    print_message "$CYAN" "Este script le guiará a través del proceso de instalación de Guix System"
    print_message "$YELLOW" "Asegúrese de estar ejecutando desde el ISO de nonguix"
    configure_system
    setup_partitions
    # Verificar soporte para hibernación después de configurar swap
    if [ "$CREATE_SWAP" = "yes" ]; then
        check_hibernation_support
    fi
    prepare_guix_installation
    print_message "$CYAN" "Configuración completada. Listo para instalar Guix System."
    print_message "$YELLOW" "Por favor revise las configuraciones en $MOUNT_POINT/etc/"
    print_message "$YELLOW" "Archivo de sistema: $MOUNT_POINT/etc/system.scm"
    print_message "$YELLOW" "Archivo de canales: $MOUNT_POINT/etc/channels.scm"
    read -r -p "Presione Enter para comenzar la instalación o Ctrl+C para cancelar..."
    install_guix_system
    print_message "$GREEN" "Configurando usuario y servicios..."
    mount -o bind /proc "$MOUNT_POINT/proc"
    mount -o bind /sys "$MOUNT_POINT/sys"
    mount -o bind /dev "$MOUNT_POINT/dev"
    mount -o bind /run "$MOUNT_POINT/run"
    print_message "$GREEN" "Estableciendo contraseña para el usuario..."
    chroot "$MOUNT_POINT" /run/setuid-programs/passwd "${DEFAULTS[login_name]}" || true
    print_message "$GREEN" "Estableciendo contraseña para root..."
    chroot "$MOUNT_POINT" /run/setuid-programs/passwd root || true
    umount "$MOUNT_POINT/proc" "$MOUNT_POINT/sys" "$MOUNT_POINT/dev" "$MOUNT_POINT/run" || true
    print_message "$GREEN" "¡Instalación completada exitosamente!"
    echo ""
    print_message "$CYAN" "=============================================="
    print_message "$CYAN" " PASOS PARA COMENZAR A USAR SU SISTEMA GUIX OS"
    print_message "$CYAN" "=============================================="
    echo ""
    print_message "$YELLOW" "1. Reinicie su sistema:"
    echo "   sudo reboot"
    echo ""
    print_message "$YELLOW" "2. Después del primer arranque, inicie sesión con:"
    echo "   Usuario: ${DEFAULTS[login_name]}"
    echo "   Contraseña: (la que configuró durante la instalación)"
    echo ""
    print_message "$YELLOW" "3. Actualice el sistema y canales:"
    echo "   guix pull"
    echo "   guix package -u"
    echo ""
    print_message "$YELLOW" "4. Configure los canales nonguix (si los habilitó):"
    echo "   guix pull"
    echo ""
    print_message "$YELLOW" "5. Para usar Flatpak con Discover:"
    echo "   - Abra Discover desde el menú de aplicaciones"
    echo "   - En la configuración de Discover, habilite los repositorios Flatpak"
    echo "   - Reinicie Discover para que los cambios surtan efecto"
    echo ""
    print_message "$CYAN" "=============================================="
    print_message "$GREEN" "¡Sistema listo para usar!"
    print_message "$CYAN" "Disfrute de su nueva instalación de Guix System con:"
    print_message "$GREEN" "   - Entorno de escritorio: ${DEFAULTS[desktop]}"
    print_message "$GREEN" "   - Navegadores: Firefox y Qutebrowser"
    print_message "$GREEN" "   - Editores: Neovim, Emacs y Emacs pgtk"
    print_message "$GREEN" "   - Gestor de aplicaciones Flatpak: Discover"
    print_message "$CYAN" "=============================================="
}

# Verificar que estamos en el entorno live de Guix
if ! command -v guix >/dev/null 2>&1; then
    echo "ERROR: Este script debe ejecutarse desde el entorno de instalación de Guix."
    echo "Por favor, arranque desde el ISO de nonguix."
    exit 1
fi

# Ejecutar función principal
main "$@"
