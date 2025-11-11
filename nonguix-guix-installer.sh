#!/bin/bash
# =============================================================================
# INSTALADOR PERSONALIZADO DE GUIX SYSTEM CON BTRFS, PLASMA Y NONGUIX - MEJORADO
# =============================================================================
# Descripción: Instalador de Guix System optimizado con Btrfs, Plasma Desktop,
# soporte para redes WiFi/ethernet, Flatpak + Discover, y configuración "erase your darlings".
# Este script está diseñado para ejecutarse directamente desde el entorno live
# del ISO de nonguix.
# =============================================================================
set -euo pipefail
trap 'echo "Error en la línea $LINENO. Ejecutando limpieza..."' ERR

# =============================================================================
# CONFIGURACIÓN DE ENTORNO PARA EL LIVE SYSTEM
# =============================================================================
export PATH="/run/current-system/profile/bin:/run/current-system/profile/sbin:$PATH"
export GUIX_LOCPATH="/run/current-system/locale"
export LC_ALL="en_US.UTF-8"
export LANG="en_US.UTF-8"

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
    [keyboard]="la-latin1"
    [name]="Usuario"
    [login_name]="usuario"
    [hostname]="guix-system"
    [desktop]="plasma"
    [use_nonguix]="yes"
    [create_swap]="yes"
)

readonly MOUNT_POINT="/mnt"
readonly GUIX_CONFIG_DIR="$MOUNT_POINT/etc/config"

# Variables globales para UUIDs (serán establecidas durante la instalación)
ROOT_UUID=""
EFI_UUID=""
SSD_OPTION="nossd"
CREATE_SWAP="no"
SWAP_SIZE=""
ENCRYPT_DISK="no"
LUKS_UUID=""
ENCRYPTED_NAME="guix-encrypted"
RESUME_UUID=""
RESUME_OFFSET=""

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================
print_message() {
    local color="$1"
    local message="$2"
    echo -e "${color}${message}${NC}"
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-no}"
    read -r -p "${prompt} (Por defecto: ${default}) " response
    echo "${response:-$default}"
}

get_user_input() {
    local prompt="$1"
    local default="$2"
    local is_password="${3:-false}"
    if [ "$is_password" = "true" ]; then
        read -r -s -p "${prompt}: " value
        echo
    else
        read -r -p "${prompt} (Por defecto: ${default}): " value
    fi
    echo "${value:-$default}"
}

validate_desktop() {
    local desktop="$1"
    local valid_desktops=("plasma" "gnome" "xfce" "mate" "i3" "sway" "none")
    for valid_desktop in "${valid_desktops[@]}"; do
        if [ "$desktop" = "$valid_desktop" ]; then
            return 0
        fi
    done
    return 1
}

detect_ssd() {
    local disk_device="$1"
    local dev_name
    dev_name="$(basename "$disk_device")"
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
    local partition="$1"
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
}

restart_guix_daemon_with_substitutes() {
    local substitute_urls="$1"
    print_message "$CYAN" "Configurando guix-daemon con soporte para sustitutos..."
    herd stop guix-daemon 2>/dev/null || true
    sleep 2
    
    # Iniciar guix-daemon con los sustitutos configurados
    guix-daemon --substitute-urls="$substitute_urls" --disable-chroot &
    sleep 5
    
    # Configurar las URLs de sustitutos para el cliente guix
    guix archive --substitute-urls="$substitute_urls" >/dev/null 2>&1 || true
}

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN DE RED - MEJORADAS CON CONNMANCTL
# =============================================================================
check_internet_connection() {
    print_message "$CYAN" "Verificando conexión a internet..."
    if curl -sfI --max-time 8 https://ci.guix.gnu.org >/dev/null 2>&1; then
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
}

setup_ethernet_connection() {
    local interface="$1"
    print_message "$GREEN" "Configurando conexión por cable en $interface..."
    ip link set "$interface" up
    print_message "$GREEN" "Obteniendo dirección IP por DHCP..."
    
    if command -v dhclient >/dev/null 2>&1; then
        if dhclient -v "$interface"; then
            print_message "$GREEN" "Conexión ethernet configurada exitosamente."
            return 0
        fi
    elif command -v udhcpc >/dev/null 2>&1; then
        if udhcpc -i "$interface"; then
            print_message "$GREEN" "Conexión ethernet configurada exitosamente."
            return 0
        fi
    else
        print_message "$YELLOW" "No se encontró cliente DHCP. Intentando configuración manual..."
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

setup_wifi_connection() {
    local interface="$1"
    print_message "$GREEN" "Configurando WiFi en $interface usando connmanctl..."
    
    # Asegurar que la interfaz esté activa
    ip link set "$interface" up
    
    # Configurar connmanctl para WiFi
    connmanctl enable wifi
    connmanctl scan wifi
    
    print_message "$CYAN" "Escaneando redes WiFi disponibles..."
    sleep 3
    
    # Mostrar redes disponibles
    local networks
    networks=$(connmanctl services | awk '{print $3}' | grep -v "^$" | sort -u)
    
    if [ -z "$networks" ]; then
        print_message "$RED" "No se encontraron redes WiFi disponibles."
        return 1
    fi
    
    print_message "$CYAN" "Redes WiFi disponibles:"
    local i=1
    local network_array=()
    while IFS= read -r network; do
        if [ -n "$network" ]; then
            echo "  $i. $network"
            network_array[i]="$network"
            ((i++))
        fi
    done <<< "$networks"
    
    local choice
    read -r -p "Seleccione el número de la red a la que desea conectarse: " choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
        print_message "$RED" "Selección inválida."
        return 1
    fi
    
    local selected_network="${network_array[$choice]}"
    
    # Para redes ocultas
    local hidden_choice
    hidden_choice=$(prompt_yes_no "¿Es una red oculta?" "no")
    
    if [ "$hidden_choice" = "yes" ]; then
        local hidden_ssid
        hidden_ssid=$(get_user_input "Ingrese el SSID de la red oculta" "")
        local password
        password=$(get_user_input "Contraseña de la red" "" true)
        
        # Conectar a red oculta
        if connmanctl connect "wifi_${hidden_ssid}_managed_psk" --passphrase "$password"; then
            print_message "$GREEN" "Conexión a red oculta exitosa."
        else
            print_message "$RED" "Error al conectar a la red oculta."
            return 1
        fi
    else
        # Conectar a red visible
        print_message "$CYAN" "Conectando a $selected_network..."
        if connmanctl connect "$selected_network"; then
            print_message "$GREEN" "Conexión WiFi exitosa a $selected_network."
        else
            print_message "$RED" "Error al conectar a $selected_network."
            return 1
        fi
    fi
    
    sleep 3
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
    
    # Verificar si ya hay conexión
    if check_internet_connection; then
        print_message "$GREEN" "Ya tiene una conexión activa."
        local reconfigure
        reconfigure=$(prompt_yes_no "¿Desea reconfigurar la conexión?" "no")
        if [ "$reconfigure" != "yes" ]; then
            return 0
        fi
    fi
    
    show_network_interfaces
    
    # Detectar tipos de interfaces disponibles
    local ethernet_interfaces
    ethernet_interfaces=$(ip -br link show | grep -E "eth|enp|ens" | awk '{print $1}')
    local wifi_interfaces
    wifi_interfaces=$(ip -br link show | grep -E "wlan|wlp|wlx" | awk '{print $1}')
    
    print_message "$CYAN" "Seleccione el tipo de conexión:"
    local connection_type
    select connection_type in "Ethernet (cable)" "WiFi" "Saltar configuración"; do
        case $connection_type in
            "Ethernet (cable)")
                if [ -z "$ethernet_interfaces" ]; then
                    print_message "$RED" "No se encontraron interfaces ethernet disponibles."
                    continue
                fi
                
                local interface
                if [ "$(echo "$ethernet_interfaces" | wc -l)" -eq 1 ]; then
                    interface="$ethernet_interfaces"
                    print_message "$GREEN" "Usando interfaz: $interface"
                else
                    print_message "$CYAN" "Seleccione una interfaz ethernet:"
                    select interface in $ethernet_interfaces; do
                        if [ -n "$interface" ]; then
                            break
                        fi
                    done
                fi
                
                if setup_ethernet_connection "$interface"; then
                    return 0
                else
                    print_message "$YELLOW" "No se pudo configurar conexión ethernet."
                    continue
                fi
                ;;
                
            "WiFi")
                if [ -z "$wifi_interfaces" ]; then
                    print_message "$RED" "No se encontraron interfaces WiFi disponibles."
                    continue
                fi
                
                local wifi_interface
                if [ "$(echo "$wifi_interfaces" | wc -l)" -eq 1 ]; then
                    wifi_interface="$wifi_interfaces"
                    print_message "$GREEN" "Usando interfaz WiFi: $wifi_interface"
                else
                    print_message "$CYAN" "Seleccione una interfaz WiFi:"
                    select wifi_interface in $wifi_interfaces; do
                        if [ -n "$wifi_interface" ]; then
                            break
                        fi
                    done
                fi
                
                if setup_wifi_connection "$wifi_interface"; then
                    return 0
                else
                    print_message "$YELLOW" "No se pudo configurar conexión WiFi."
                    continue
                fi
                ;;
                
            "Saltar configuración")
                print_message "$YELLOW" "Advertencia: Sin conexión a internet, la instalación puede fallar o ser muy lenta."
                local proceed
                proceed=$(prompt_yes_no "¿Desea continuar sin conexión a internet?" "no")
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
# FUNCIONES DE DETECCIÓN DE REQUISITOS - CORREGIDAS
# =============================================================================
check_system_requirements() {
    print_message "$CYAN" "Verificando requisitos básicos del sistema..."
    
    # Verificar RAM mínima (solo advertencia)
    local required_ram_gb=2
    local available_ram_gb
    available_ram_gb=$(free -g --si | awk 'FNR == 2 {print $2}')
    if [ "$available_ram_gb" -lt "$required_ram_gb" ]; then
        print_message "$YELLOW" "ADVERTENCIA: Se recomienda al menos ${required_ram_gb}GB de RAM."
        print_message "$YELLOW" "RAM detectada: ${available_ram_gb}GB"
        local proceed
        proceed=$(prompt_yes_no "¿Continuar de todas formas?" "yes")
        if [ "$proceed" != "yes" ]; then
            exit 1
        fi
    fi
    
    print_message "$GREEN" "✓ Verificación de requisitos completada"
}

# =============================================================================
# FUNCIONES DE SELECCIÓN INTERACTIVA
# =============================================================================
configure_keyboard_layout() {
    local current_layout="${DEFAULTS[keyboard]}"
    print_message "$CYAN" "Layout actual: $current_layout"
    local choice
    choice=$(prompt_yes_no "¿Cambiar layout de teclado?" "no")
    if [ "$choice" = "yes" ]; then
        current_layout=$(get_user_input "Ingrese el layout de teclado" "la-latin1")
        # Probar el layout temporalmente
        if command -v loadkeys >/dev/null 2>&1; then
            loadkeys "$current_layout" 2>/dev/null || true
        fi
        print_message "$GREEN" "Layout cambiado a: $current_layout"
    fi
    echo "$current_layout"
}

select_timezone() {
    print_message "$CYAN" "Selección de zona horaria"
    local timezones
    timezones=$(timedatectl list-timezones 2>/dev/null | head -20)
    if [ -n "$timezones" ]; then
        echo ""
        echo "Zonas horarias disponibles (primeras 20):"
        echo "$timezones"
        echo ""
    fi
    local selected_tz
    selected_tz=$(get_user_input "Ingrese su zona horaria" "${DEFAULTS[timezone]}")
    # Validar timezone
    if timedatectl list-timezones 2>/dev/null | grep -q "^$selected_tz$" || [ "$selected_tz" = "${DEFAULTS[timezone]}" ]; then
        echo "$selected_tz"
    else
        print_message "$YELLOW" "Zona horaria no válida. Usando valor por defecto."
        echo "${DEFAULTS[timezone]}"
    fi
}

# =============================================================================
# CONFIGURACIÓN DE SWAP MEJORADA
# =============================================================================
configure_swap_settings() {
    print_message "$CYAN" "Configuración de memoria swap"
    
    # Mostrar RAM disponible
    local ram_size_gb
    ram_size_gb=$(free -g --si | awk 'FNR == 2 {print $2}')
    print_message "$GREEN" "RAM disponible en el sistema: ${ram_size_gb}GB"
    
    CREATE_SWAP=$(prompt_yes_no "¿Crear archivo swap para hibernación?" "${DEFAULTS[create_swap]}")
    
    if [ "$CREATE_SWAP" = "yes" ]; then
        # Sugerir tamaño basado en la RAM disponible
        local suggested_swap
        if [ "$ram_size_gb" -le 8 ]; then
            suggested_swap="${ram_size_gb}G"
        else
            suggested_swap="8G"
        fi
        
        print_message "$YELLOW" "Recomendación: Para hibernación efectiva, el swap debería ser al menos del tamaño de la RAM."
        print_message "$CYAN" "Tamaños comunes:"
        echo "  - Mínimo: 2G"
        echo "  - Recomendado: ${suggested_swap} (basado en su RAM)"
        echo "  - Máximo: 32G"
        echo ""
        
        SWAP_SIZE=$(get_user_input "Ingrese el tamaño del swap (ej: 8G, 16G)" "$suggested_swap")
        
        # Validar formato del tamaño
        if [[ ! "$SWAP_SIZE" =~ ^[0-9]+[GM]$ ]]; then
            print_message "$RED" "Formato de tamaño inválido. Usando valor por defecto: $suggested_swap"
            SWAP_SIZE="$suggested_swap"
        fi
        
        print_message "$GREEN" "Tamaño de swap configurado: $SWAP_SIZE"
    else
        SWAP_SIZE=""
        print_message "$YELLOW" "No se creará archivo swap."
    fi
}

configure_swap() {
    if [ "$CREATE_SWAP" = "yes" ] && [ -n "$SWAP_SIZE" ]; then
        print_message "$GREEN" "Creando archivo swap de $SWAP_SIZE para hibernación..."
        mkdir -p "$MOUNT_POINT/swap"
        
        print_message "$CYAN" "Creando swapfile de $SWAP_SIZE..."
        
        # Crear swapfile usando btrfs
        if btrfs filesystem mkswapfile --size "$SWAP_SIZE" --uuid clear "$MOUNT_POINT/swap/swapfile"; then
            chmod 600 "$MOUNT_POINT/swap/swapfile"
            
            # Obtener información para hibernación
            RESUME_UUID=$(blkid -s UUID -o value "$ROOT_PARTITION")
            RESUME_OFFSET=$(btrfs inspect-internal map-swapfile -r "$MOUNT_POINT/swap/swapfile" 2>/dev/null || echo "0")
            
            print_message "$GREEN" "Swapfile creado exitosamente para hibernación"
            print_message "$CYAN" "UUID de hibernación: $RESUME_UUID"
            print_message "$CYAN" "Offset de hibernación: $RESUME_OFFSET"
        else
            print_message "$YELLOW" "No se pudo crear swapfile. Continuando sin swap."
            CREATE_SWAP="no"
            SWAP_SIZE=""
        fi
    fi
}

# =============================================================================
# FUNCIONES DE ENCRIPTACIÓN
# =============================================================================
setup_encryption() {
    local partition="$1"
    print_message "$CYAN" "Configuración de encriptación LUKS"
    local encrypt_choice
    encrypt_choice=$(prompt_yes_no "¿Encriptar el disco con LUKS?" "no")
    if [ "$encrypt_choice" = "yes" ]; then
        print_message "$YELLOW" "ADVERTENCIA: Se encriptará la partición $partition. Todos los datos serán borrados."
        local confirm
        confirm=$(prompt_yes_no "¿Está seguro?" "no")
        if [ "$confirm" != "yes" ]; then
            return 1
        fi
        
        print_message "$CYAN" "Seleccione versión de LUKS:"
        local luks_opts=""
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
        if ! cryptsetup luksFormat $luks_opts "$partition"; then
            print_message "$RED" "Error al formatear partición LUKS"
            return 1
        fi
        
        print_message "$GREEN" "Abriendo partición encriptada..."
        if ! cryptsetup open "$partition" "$ENCRYPTED_NAME"; then
            print_message "$RED" "Error al abrir partición encriptada"
            return 1
        fi
        
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
# FUNCIONES DE OPTIMIZACIONES DEL KERNEL
# =============================================================================
configure_grub_optimizations() {
    local hdd_ssd="$1"
    local resume_uuid="$2"
    local resume_offset="$3"
    
    local kernel_params="quiet splash"
    
    # Optimizaciones específicas para SSD
    if [[ "$hdd_ssd" == *"ssd"* ]]; then
        kernel_params+=" zswap.enabled=1 zswap.max_pool_percent=25"
    fi
    
    # Parámetros para encriptación
    if [ "$ENCRYPT_DISK" = "yes" ]; then
        kernel_params+=" rd.luks.name=$LUKS_UUID=$ENCRYPTED_NAME"
    fi
    
    # Soporte para hibernación si existe swapfile
    if [ -n "$resume_uuid" ] && [ -n "$resume_offset" ] && [ "$resume_offset" != "0" ]; then
        kernel_params+=" resume=UUID=$resume_uuid resume_offset=$resume_offset"
    fi
    
    echo "$kernel_params"
}

# =============================================================================
# FUNCIONES DE CONFIGURACIÓN DEL SISTEMA - MEJORADAS
# =============================================================================
generate_guix_config() {
    local config_file="$1"
    local hostname="$2"
    local timezone="$3"
    local keyboard="$4"
    local login_name="$5"
    local desktop="$6"
    local use_nonguix="$7"
    local create_swap="$8"
    local _encrypt_disk="$9"  # Variable intencionalmente no usada - se mantiene por compatibilidad
    
    # Obtener optimizaciones del kernel
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
             (gnu packages compression)
             (gnu packages kde-frameworks)
             (gnu packages kde-plasma)
             (gnu packages flatpak)
             (gnu packages bash)
             (gnu packages fish)
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
             (nongnu packages firmware))
EOF
    fi

    cat <<EOF

(operating-system
  (host-name "$hostname")
  (timezone "$timezone")
  (locale "es_CR.utf8")
EOF

    if [ "$use_nonguix" = "yes" ]; then
        cat <<EOF
  (kernel linux)
  (firmware (list linux-firmware))
  (initrd-modules (append (list "btrfs" "dm-crypt" "aes")
                         %base-initrd-modules))
EOF
    else
        cat <<EOF
  (kernel linux-libre)
  (firmware %base-firmware)
  (initrd-modules (append (list "btrfs")
                         %base-initrd-modules))
EOF
    fi

# shellcheck disable=SC2154
    cat <<EOF
  (bootloader (bootloader-configuration
               (bootloader grub-bootloader)
               (targets '("/dev/sda"))
               (keyboard-layout (keyboard-layout "$keyboard"))
               (bootloader-extra-arguments
                '(("GRUB_CMDLINE_LINUX_DEFAULT" . "\"$kernel_params\"")))))
  
  (keyboard-layout (keyboard-layout "$keyboard"))
  
  (file-systems (append (list 
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/")
                          (type "btrfs")
                          (options "subvol=@root,compress=zstd:3,$SSD_OPTION")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$ROOT_UUID" 'btrfs))
                          (mount-point "/home")
                          (type "btrfs")
                          (options "subvol=@home,compress=zstd:3,$SSD_OPTION")
                          (needed-for-boot? #t))
                        (file-system
                          (device (uuid "$EFI_UUID" 'fat))
                          (mount-point "/boot/efi")
                          (type "vfat")
                          (needed-for-boot? #t)))
                       %base-file-systems))
  
  (users (cons (user-account
                (name "$login_name")
                (comment "Usuario principal")
                (group "users")
                (supplementary-groups '("wheel" "netdev" "audio" "video"))
                (shell #~(string-append #$fish "/bin/fish")))
               %base-user-accounts))
  
  (sudoers-file (plain-file "sudoers"
                           "root ALL=(ALL) ALL
%wheel ALL=(ALL) ALL
"))
  
  (services (append (list 
                     (service network-manager-service-type)
                     (service openssh-service-type)
                     (service ntp-service-type)
                     (service dbus-service-type)
                     (service flatpak-service-type))
EOF

    case "$desktop" in
        "plasma")
            cat <<EOF
                     (service sddm-service-type)
                     (service plasma-desktop-service-type)
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
    esac

    cat <<EOF
                    ))
  
  (packages (append (list 
                     git curl wget nss-certs
                     firefox
                     neovim
                     btrfs-progs ntfs-3g exfat-utils
                     flatpak
                     discover
                     bash
                     fish)
EOF

    case "$desktop" in
        "plasma")
            cat <<EOF
                   (list plasma-framework
                         plasma-workspace
                         plasma-desktop
                         kate
                         konsole
                         dolphin
                         ark
                         okular
                         gwenview
                         spectacle
                         kcalc
                         systemsettings
                         plasma-systemmonitor
                         kdeconnect
                         discover)
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
                         gnome-system-monitor)
EOF
            ;;
    esac

    cat <<EOF
                   %base-packages))
)
EOF
    } > "$config_file"
}

generate_channels_config() {
    local channels_file="$1"
    local use_nonguix="$2"
    
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
# CONFIGURACIÓN DE DISCOS Y PARTICIONES - CORREGIDA
# =============================================================================
setup_disk() {
    local disk_device="$1"
    
    print_message "$GREEN" "Particionando el disco $disk_device..."
    
    # Detectar si es NVMe para el prefijo de particiones
    local part_prefix=""
    if [[ "$disk_device" =~ nvme ]]; then
        part_prefix="p"
    fi
    
    detect_ssd "$disk_device"
    
    # Crear tabla de particiones GPT
    parted "$disk_device" --script -- mklabel gpt
    
    # Partición EFI
    parted "$disk_device" --script -- mkpart ESP fat32 1MiB 551MiB
    parted "$disk_device" --script -- set 1 esp on
    
    # Partición root
    parted "$disk_device" --script -- mkpart root btrfs 551MiB 100%
    
    print_message "$GREEN" "Formateando particiones..."
    
    # Formatear EFI
    mkfs.fat -F 32 -n ESP "${disk_device}${part_prefix}1"
    
    # Configurar encriptación si se seleccionó
    if [ "$ENCRYPT_DISK_CHOICE" = "yes" ]; then
        if ! setup_encryption "${disk_device}${part_prefix}2"; then
            print_message "$RED" "Error en la configuración de encriptación"
            exit 1
        fi
        # Formatear el dispositivo desbloqueado
        mkfs.btrfs -f -L guix-root "$ROOT_PARTITION"
    else
        mkfs.btrfs -f -L guix-root "${disk_device}${part_prefix}2"
        ROOT_PARTITION="${disk_device}${part_prefix}2"
    fi
    
    print_message "$GREEN" "Montando y creando subvolúmenes..."
    
    # Montar y crear subvolúmenes
    mkdir -p "$MOUNT_POINT"
    mount "$ROOT_PARTITION" "$MOUNT_POINT"
    
    # Crear subvolúmenes Btrfs
    local subvolumes=("@root" "@home")
    for subvol in "${subvolumes[@]}"; do
        btrfs subvolume create "$MOUNT_POINT/$subvol"
    done
    
    # Snapshot inicial para "erase your darlings"
    btrfs subvolume snapshot -r "$MOUNT_POINT/@root" "$MOUNT_POINT/@root-blank"
    
    umount "$MOUNT_POINT"
    
    # Montar subvolúmenes con opciones
    local mount_opts="rw,relatime,compress=zstd:3,$SSD_OPTION"
    mount -o "$mount_opts,subvol=@root" "$ROOT_PARTITION" "$MOUNT_POINT"
    
    # Crear puntos de montaje y montar
    mkdir -p "$MOUNT_POINT/home"
    mount -o "$mount_opts,subvol=@home" "$ROOT_PARTITION" "$MOUNT_POINT/home"
    
    mkdir -p "$MOUNT_POINT/boot/efi"
    mount "${disk_device}${part_prefix}1" "$MOUNT_POINT/boot/efi"
    
    # Configurar swap si se seleccionó
    if [ "$CREATE_SWAP" = "yes" ] && [ -n "$SWAP_SIZE" ]; then
        mkdir -p "$MOUNT_POINT/swap"
        mount -o "$mount_opts,subvolid=5" "$ROOT_PARTITION" "$MOUNT_POINT/swap"
        configure_swap
        umount "$MOUNT_POINT/swap"
    fi
    
    # Obtener UUIDs
    EFI_UUID=$(get_partition_uuid "${disk_device}${part_prefix}1")
    ROOT_UUID=$(get_partition_uuid "$ROOT_PARTITION")
    
    print_message "$GREEN" "Estructura de discos configurada correctamente."
    print_message "$CYAN" "UUID EFI: $EFI_UUID"
    print_message "$CYAN" "UUID Root: $ROOT_UUID"
}

# =============================================================================
# CONFIGURACIÓN DEL SISTEMA Y USUARIO
# =============================================================================
configure_system() {
    print_message "$CYAN" "Configuración del sistema"
    
    local hostname
    hostname=$(get_user_input "Nombre del equipo" "${DEFAULTS[hostname]}")
    
    local timezone
    timezone=$(select_timezone)
    
    local keyboard
    keyboard=$(configure_keyboard_layout)
    
    local login_name
    login_name=$(get_user_input "Nombre de usuario" "${DEFAULTS[login_name]}")
    
    local desktop
    desktop=$(get_user_input "Entorno de escritorio (plasma/gnome/xfce)" "${DEFAULTS[desktop]}")
    
    local use_nonguix
    use_nonguix=$(prompt_yes_no "¿Usar canal nonguix para firmware no libre?" "${DEFAULTS[use_nonguix]}")
    
    # Configuración mejorada del swap
    configure_swap_settings
    
    # Opción de encriptación
    ENCRYPT_DISK_CHOICE=$(prompt_yes_no "¿Encriptar el disco con LUKS?" "no")
    
    if ! validate_desktop "$desktop"; then
        print_message "$RED" "Entorno de escritorio no válido. Usando valor por defecto: ${DEFAULTS[desktop]}"
        desktop="${DEFAULTS[desktop]}"
    fi
    
    # Guardar configuración
    mkdir -p "$GUIX_CONFIG_DIR"
    
    print_message "$GREEN" "Generando configuración de Guix..."
    generate_guix_config "$GUIX_CONFIG_DIR/system.scm" "$hostname" "$timezone" \
        "$keyboard" "$login_name" "$desktop" "$use_nonguix" "$CREATE_SWAP" "$ENCRYPT_DISK_CHOICE"
    
    print_message "$GREEN" "Generando configuración de canales..."
    generate_channels_config "$GUIX_CONFIG_DIR/channels.scm" "$use_nonguix"
    
    print_message "$GREEN" "Configuraciones generadas en $GUIX_CONFIG_DIR/"
}

setup_partitions() {
    print_message "$CYAN" "Configuración de discos"
    
    print_message "$CYAN" "Discos disponibles:"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE
    
    local disk_device=""
    while true; do
        disk_device=$(get_user_input "Ingrese el dispositivo de disco a usar (ej: /dev/sda, /dev/nvme0n1)" "")
        
        if [[ "$disk_device" =~ ^/dev/[a-z]+[0-9]*$ ]] && [ -b "$disk_device" ]; then
            break
        fi
        print_message "$RED" "Dispositivo no válido. Por favor ingrese un dispositivo de bloque válido."
    done
    
    print_message "$YELLOW" "ADVERTENCIA: Esto borrará todos los datos en ${disk_device}. ¿Está seguro de continuar?"
    local response
    response=$(prompt_yes_no "¿Continuar con la instalación?" "no")
    if [ "$response" != "yes" ]; then
        print_message "$RED" "Instalación cancelada."
        exit 1
    fi
    
    setup_disk "$disk_device"
}

# =============================================================================
# INSTALACIÓN DE GUIX - CORREGIDA
# =============================================================================
prepare_guix_installation() {
    print_message "$GREEN" "Preparando instalación de Guix..."
    
    # Crear directorios necesarios
    mkdir -p "$MOUNT_POINT/etc"
    mkdir -p "$MOUNT_POINT/var/guix/profiles/per-user/root"
    
    # Copiar configuraciones
    if [ -d "$GUIX_CONFIG_DIR" ]; then
        cp "$GUIX_CONFIG_DIR/system.scm" "$MOUNT_POINT/etc/system.scm"
        cp "$GUIX_CONFIG_DIR/channels.scm" "$MOUNT_POINT/etc/channels.scm"
        print_message "$GREEN" "Configuraciones copiadas a $MOUNT_POINT/etc/"
    else
        print_message "$RED" "Error: No se encontraron configuraciones en $GUIX_CONFIG_DIR"
        exit 1
    fi
    
    # Configurar sustitutos
    local substitute_urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    
    if [ "$use_nonguix" = "yes" ]; then
        print_message "$CYAN" "Configurando sustitutos nonguix..."
        if curl -sfI --max-time 3 https://substitutes.nonguix.org >/dev/null 2>&1; then
            substitute_urls="$substitute_urls https://substitutes.nonguix.org"
        else
            substitute_urls="$substitute_urls https://nonguix-proxy.ditigal.xyz"
        fi
        
        # Autorizar clave nonguix
        authorize_nonguix_key
    fi
    
    # Configurar daemon con sustitutos
    restart_guix_daemon_with_substitutes "$substitute_urls"
    
    # Verificar conexión
    if ! check_internet_connection; then
        print_message "$YELLOW" "No hay conexión a internet. La instalación será más lenta."
        local proceed
        proceed=$(prompt_yes_no "¿Continuar sin conexión a internet?" "yes")
        if [ "$proceed" != "yes" ]; then
            exit 1
        fi
    fi
}

install_guix_system() {
    print_message "$GREEN" "Iniciando instalación de Guix System..."
    
    if [ ! -f "$MOUNT_POINT/etc/system.scm" ]; then
        print_message "$RED" "Error: No se encontró el archivo de configuración del sistema."
        exit 1
    fi

    # URLs de sustitutos
    local substitute_urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    if [ "$use_nonguix" = "yes" ]; then
        if curl -sfI --max-time 3 https://substitutes.nonguix.org >/dev/null 2>&1; then
            substitute_urls="$substitute_urls https://substitutes.nonguix.org"
        else
            substitute_urls="$substitute_urls https://nonguix-proxy.ditigal.xyz"
        fi
    fi
    
    print_message "$YELLOW" "Usando servidores de sustitución: $substitute_urls"
    print_message "$CYAN" "Instalando Guix System. Esto puede tomar varios minutos..."
    
    # Intento de instalación con opciones de fallback
    if ! guix system init "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" \
        --substitute-urls="$substitute_urls" \
        --fallback; then

        print_message "$YELLOW" "Primer intento falló. Intentando con --no-grafts..."
        
        if ! guix system init "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" \
            --substitute-urls="$substitute_urls" \
            --no-grafts --fallback; then

            print_message "$RED" "Error durante la instalación."
            print_message "$YELLOW" "Intentando sin sustitutos..."
            
            if ! guix system init "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" \
                --no-substitutes; then
                
                print_message "$RED" "Error crítico: No se pudo instalar el sistema."
                exit 1
            fi
        fi
    fi

    print_message "$GREEN" "¡Instalación completada exitosamente!"
}

# =============================================================================
# VERIFICACIONES - CORREGIDAS
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
    
    # Verificar comandos esenciales
    local required_commands=("parted" "mkfs.fat" "mkfs.btrfs" "btrfs" "blkid" "lsblk" "connmanctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            print_message "$RED" "Comando requerido '$cmd' no encontrado"
            exit 1
        fi
    done
    
    # Verificar EFI (solo advertencia)
    if [ ! -d "/sys/firmware/efi" ]; then
        print_message "$YELLOW" "ADVERTENCIA: El sistema no parece estar arrancado en modo EFI"
        print_message "$YELLOW" "El script está configurado para instalación EFI. ¿Desea continuar?"
        local response
        response=$(prompt_yes_no "¿Continuar de todas formas?" "no")
        if [ "$response" != "yes" ]; then
            exit 1
        fi
    fi
    
    print_message "$GREEN" "✓ Verificaciones de requisitos completadas"
}

# =============================================================================
# LIMPIEZA ROBUSTA - MEJORADA
# =============================================================================
robust_cleanup() {
    print_message "$YELLOW" "Realizando limpieza..."
    
    # Desmontar puntos de montaje en orden inverso
    local mounts=(
        "$MOUNT_POINT/boot/efi"
        "$MOUNT_POINT/home"
        "$MOUNT_POINT"
    )
    
    for mount_point in "${mounts[@]}"; do
        if mountpoint -q "$mount_point"; then
            umount -l "$mount_point" 2>/dev/null || true
        fi
    done
    
    # Cerrar particiones encriptadas
    if [ "$ENCRYPT_DISK" = "yes" ] && [ -b "/dev/mapper/$ENCRYPTED_NAME" ]; then
        cryptsetup close "$ENCRYPTED_NAME" 2>/dev/null || true
    fi
    
    # Limpiar configuraciones temporales
    rm -rf "$GUIX_CONFIG_DIR" 2>/dev/null || true
    
    print_message "$GREEN" "✓ Limpieza completada"
}

# =============================================================================
# FUNCIÓN PRINCIPAL - CORREGIDA
# =============================================================================
main() {
    trap robust_cleanup EXIT
    
    print_message "$CYAN" "=============================================="
    print_message "$CYAN" "  INSTALADOR GUIX SYSTEM CON NONGUIX"
    print_message "$CYAN" "=============================================="
    
    check_requirements
    check_system_requirements
    
    # Configuración de red
    if ! setup_network_connection; then
        print_message "$YELLOW" "Continuando sin conexión a internet..."
    fi
    
    # Configuración del sistema
    configure_system
    setup_partitions
    prepare_guix_installation
    
    # Confirmación final
    print_message "$CYAN" "Configuración completada. Listo para instalar Guix System."
    print_message "$YELLOW" "Archivo de sistema: $MOUNT_POINT/etc/system.scm"
    print_message "$YELLOW" "Archivo de canales: $MOUNT_POINT/etc/channels.scm"
    
    local confirm
    confirm=$(prompt_yes_no "¿Desea comenzar la instalación?" "yes")
    if [ "$confirm" != "yes" ]; then
        print_message "$RED" "Instalación cancelada por el usuario."
        exit 0
    fi
    
    # Instalación
    install_guix_system
    
    # Configuración post-instalación
    print_message "$GREEN" "Configurando usuario..."
    
    # Montar sistemas de archivos virtuales para chroot
    mount -t proc proc "$MOUNT_POINT/proc" || true
    mount -t sysfs sys "$MOUNT_POINT/sys" || true
    mount -o bind /dev "$MOUNT_POINT/dev" || true
    
    # Establecer contraseñas
    print_message "$CYAN" "Estableciendo contraseña para el usuario ${DEFAULTS[login_name]}..."
    chroot "$MOUNT_POINT" passwd "${DEFAULTS[login_name]}" || true
    
    print_message "$CYAN" "Estableciendo contraseña para root..."
    chroot "$MOUNT_POINT" passwd root || true
    
    # Desmontar
    umount "$MOUNT_POINT/proc" 2>/dev/null || true
    umount "$MOUNT_POINT/sys" 2>/dev/null || true
    umount "$MOUNT_POINT/dev" 2>/dev/null || true
    
    print_message "$GREEN" "¡Instalación completada exitosamente!"
    
    # Mensaje final
    echo ""
    print_message "$CYAN" "=============================================="
    print_message "$GREEN" "  ¡INSTALACIÓN COMPLETADA!"
    print_message "$CYAN" "=============================================="
    echo ""
    print_message "$YELLOW" "Pasos siguientes:"
    echo ""
    print_message "$CYAN" "1. Reinicie el sistema:"
    echo "   sudo reboot"
    echo ""
    print_message "$CYAN" "2. Después del arranque, inicie sesión con:"
    echo "   Usuario: ${DEFAULTS[login_name]}"
    echo "   Contraseña: (la que configuró)"
    echo ""
    print_message "$CYAN" "3. Para actualizar el sistema:"
    echo "   guix pull"
    echo "   sudo guix system reconfigure /etc/system.scm"
    echo ""
    print_message "$GREEN" "¡Disfrute de su nuevo sistema Guix!"
}

# Verificar que estamos en el entorno live de Guix
if ! command -v guix >/dev/null 2>&1; then
    echo "ERROR: Este script debe ejecutarse desde el entorno de instalación de Guix."
    echo "Por favor, arranque desde el ISO de nonguix."
    exit 1
fi

# Ejecutar función principal
main "$@"
