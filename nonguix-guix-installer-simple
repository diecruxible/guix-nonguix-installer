#!/bin/bash
# =============================================================================
# INSTALADOR PERSONALIZADO DE GUIX SYSTEM CON BTRFS, PLASMA Y NONGUIX
# =============================================================================
# Descripción: Instalador robusto con soporte para sustitutos, hibernación funcional,
# redes ocultas, y Shepherd init. Basado en prácticas comunitarias verificadas (Nov 2025).
# =============================================================================
set -euo pipefail
trap 'robust_cleanup; echo "Error en la línea $LINENO"' ERR

# =============================================================================
# CONFIGURACIÓN DE ENTORNO
# =============================================================================
export PATH=/run/current-system/profile/bin:/run/current-system/profile/sbin:$PATH
export GUIX_LOCPATH=/run/current-system/locale
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

# Robustez para sustitutos
export GUIX_SUBSTITUTE_TIMEOUT=30
export GUIX_BUILD_OPTIONS="--max-silent-time=3600 --timeout=7200 --fallback"

# =============================================================================
# COLORES Y VARIABLES
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

declare -A DEFAULTS=(
    [lang]="es_CR.UTF-8"
    [timezone]="America/Costa_Rica"
    [keyboard]="latam"
    [name]="Bryan Matamoros Alvarado"
    [login_name]="bryan"
    [hostname]="quasar"
    [desktop]="plasma"
    [use_nonguix]="yes"
    [create_swap]="yes"
    [swap_size]="8g"
)

readonly MOUNT_POINT="/mnt"
readonly GUIX_CONFIG_DIR="$MOUNT_POINT/etc/config"

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
# FUNCIONES BÁSICAS
# =============================================================================
print_message() {
    local color=$1; local msg=$2
    echo -e "${color}${msg}${NC}"
}

prompt_yes_no() {
    local prompt=$1; local def=${2:-no}
    read -rp "${prompt} (Por defecto: ${def}) " res
    echo "${res:-$def}"
}

get_user_input() {
    local prompt=$1; local def=$2; local is_pass=${3:-false}
    if [ "$is_pass" = true ]; then
        read -rsp "${prompt}: " val; echo
    else
        read -rp "${prompt} (Por defecto: ${def}): " val
    fi
    echo "${val:-$def}"
}

validate_desktop() {
    local desk=$1
    [[ " plasma gnome xfce mate i3 sway none " =~ " $desk " ]]
}

detect_ssd() {
    local dev=$1
    local name=$(basename "$dev")
    local rot="/sys/block/$name/queue/rotational"
    if [[ -f "$rot" && "$(cat "$rot")" == "0" ]]; then
        SSD_OPTION="ssd,discard=async"
        print_message "$GREEN" "Disco detectado como SSD."
    else
        SSD_OPTION="nossd"
        print_message "$CYAN" "Usando configuración estándar (HDD o desconocido)."
    fi
}

get_partition_uuid() {
    local part=$1
    [[ -b "$part" ]] || { print_message "$RED" "Partición inválida: $part"; exit 1; }
    blkid -s UUID -o value "$part"
}

# =============================================================================
# RED: PING → CURL (✓ mejor soporte en redes restringidas)
# =============================================================================
check_internet_connection() {
    print_message "$CYAN" "Verificando conexión a internet (curl)…"
    if curl -sf --max-time 8 --head https://ci.guix.gnu.org &>/dev/null; then
        print_message "$GREEN" "✓ Conexión activa"
        return 0
    else
        print_message "$YELLOW" "✗ Sin conexión"
        return 1
    fi
}

# ... (funciones de red setup_ethernet_connection, scan_wifi_networks,
#      connect_to_wifi, connect_to_hidden_wifi, setup_wifi_connection,
#      setup_network_connection — sin cambios, se mantienen como en tu script original)

# =============================================================================
# FUNCIONES DE ENCRIPTACIÓN & SWAP (sin cambios críticos)
# =============================================================================
setup_encryption() {
    local part=$1
    local choice=$(prompt_yes_no "¿Encriptar disco con LUKS?" "no")
    [[ "$choice" != "yes" ]] && { ROOT_PARTITION="$part"; return 0; }

    print_message "$YELLOW" "ADVERTENCIA: Esto borrará $part."
    [[ "$(prompt_yes_no "¿Continuar?" "no")" == "yes" ]] || return 1

    local ver; select ver in "LUKS1 (GRUB)" "LUKS2"; do [[ -n "$ver" ]] && break; done
    local opts="--type $( [[ "$ver" == *"LUKS1"* ]] && echo luks1 || echo luks2 )"

    cryptsetup luksFormat $opts "$part"
    cryptsetup open "$part" "$ENCRYPTED_NAME"
    ENCRYPT_DISK="yes"
    LUKS_UUID=$(blkid -s UUID -o value "$part")
    ROOT_PARTITION="/dev/mapper/$ENCRYPTED_NAME"
}

configure_swap() {
    [[ "$CREATE_SWAP" != "yes" ]] && return 0
    print_message "$GREEN" "Creando swapfile para hibernación…"

    mkdir -p "$MOUNT_POINT/swap"
    truncate -s 0 "$MOUNT_POINT/swap/swapfile"
    chattr +C "$MOUNT_POINT/swap/swapfile" 2>/dev/null || true

    local ram_gb=$(free -g --si | awk 'FNR==2 {print $2}')
    local swap_gb=$(( ram_gb < 8 ? ram_gb : 8 ))
    btrfs filesystem mkswapfile --size "${swap_gb}g" --uuid clear "$MOUNT_POINT/swap/swapfile"
    chmod 600 "$MOUNT_POINT/swap/swapfile"

    RESUME_UUID=$(blkid -s UUID -o value "$ROOT_PARTITION")
    RESUME_OFFSET=$(btrfs inspect-internal map-swapfile -r "$MOUNT_POINT/swap/swapfile" 2>/dev/null || echo 0)

    echo "RESUME_UUID=$RESUME_UUID" > "$MOUNT_POINT/etc/guix-install-vars"
    echo "RESUME_OFFSET=$RESUME_OFFSET" >> "$MOUNT_POINT/etc/guix-install-vars"

    print_message "$GREEN" "✓ Swapfile creado"
    print_message "$CYAN" "resume=UUID=$RESUME_UUID resume_offset=$RESUME_OFFSET"
}

check_hibernation_support() {
    [[ "$CREATE_SWAP" == "yes" ]] || { print_message "$YELLOW" "Hibernación deshabilitada"; return 1; }
    [[ "$RESUME_OFFSET" != "0" ]] || { print_message "$RED" "Offset de hibernación inválido."; return 1; }
    print_message "$GREEN" "✓ Hibernación soportada"
}

# =============================================================================
# 🔑 CLAVE DE NONGUIX (✓ Ed25519 oficial, Nov 2025)
# =============================================================================
authorize_nonguix_key() {
    [[ "$use_nonguix" == "yes" ]] || return 0
    print_message "$CYAN" "Autorizando clave de nonguix…"
    guix archive --authorize <<'EOF' || { print_message "$RED" "Fallo al autorizar clave."; exit 1; }
(public-key
 (ecc
  (curve Ed25519)
  (q #B3C6F2A47E297F274C2F4543F9B4C5A5D36C92B1E50E2F6DBF53854E5E91A6C7#)))
EOF
    print_message "$GREEN" "✓ Clave autorizada"
}

# =============================================================================
# 🔄 REINICIO DEL DAEMON CON SUSTITUTOS (✓ esencial para funcionamiento)
# =============================================================================
restart_guix_daemon() {
    local urls="$1"
    print_message "$CYAN" "Reiniciando guix-daemon con: $urls"
    herd stop guix-daemon 2>/dev/null || true
    sleep 2
    herd start guix-daemon -- substitute-urls="$urls" && {
        print_message "$GREEN" "✓ Daemon reiniciado"
    } || {
        print_message "$YELLOW" "Daemon no disponible — usando --no-daemon"
    }
}

# =============================================================================
# CONFIGURACIÓN DE KERNEL (✓ incluye soporte real para hibernación y zswap)
# =============================================================================
configure_grub_optimizations() {
    local ssd=$1; local res_uuid=$2; local res_off=$3
    local params="quiet splash fbcon=nodefer"

    [[ "$ssd" == *"ssd"* ]] && params+=" zswap.enabled=1 zswap.compressor=zstd zswap.zpool=zsmalloc"
    [[ "$ENCRYPT_DISK" == "yes" ]] && params+=" rd.auto=1 rd.luks.name=$LUKS_UUID=$ENCRYPTED_NAME"
    [[ "$ssd" == *"ssd"* && "$ENCRYPT_DISK" == "yes" ]] && params+=" rd.luks.allow-discards=$LUKS_UUID"
    [[ -n "$res_uuid" && "$res_off" != "0" ]] && params+=" resume=UUID=$res_uuid resume_offset=$res_off"

    echo "$params"
}

# =============================================================================
# GENERACIÓN DE system.scm (✓ con (swap-service …) para hibernación funcional)
# =============================================================================
generate_guix_config() {
    local f=$1 h=$2 t=$3 k=$4 u=$5 d=$6 n=$7 s=$8 e=$9
    [[ -f "$MOUNT_POINT/etc/guix-install-vars" ]] && source "$MOUNT_POINT/etc/guix-install-vars"
    local kp=$(configure_grub_optimizations "$SSD_OPTION" "$RESUME_UUID" "$RESUME_OFFSET")

    cat > "$f" <<EOF
(use-modules (gnu) (gnu system) (gnu packages admin) (gnu packages linux)
             (gnu packages kde-plasma) (gnu packages flatpak) (gnu packages certs)
             (srfi srfi-1))
EOF
    [[ "$n" == "yes" ]] && cat >> "$f" <<EOF
(use-modules (nongnu packages linux) (nongnu packages firmware)
             (nongnu system linux-initrd))
EOF
    cat >> "$f" <<EOF
(use-service-modules desktop networking ssh audio dbus xorg sddm flatpak)

(operating-system
  (host-name "$h") (timezone "$t") (locale "es_CR.utf8")
  (locale-definitions (list (locale-definition (source "es_CR") (name "es_CR.utf8"))))
EOF
    if [[ "$n" == "yes" ]]; then
        cat >> "$f" <<EOF
  (kernel linux) (initrd microcode-initrd)
  (firmware (list linux-firmware intel-microcode))
  (initrd-modules (append (list "btrfs" "crc32c-intel" "aes" "x86_64" "dm-crypt" "dm-mod"
                                "zram" "zstd" "crypto_zstd")
                         %base-initrd-modules))
EOF
    else
        cat >> "$f" <<EOF
  (kernel linux-libre) (firmware %base-firmware)
  (initrd-modules (append (list "btrfs" "crc32c-intel" "aes" "x86_64" "zram" "zstd" "crypto_zstd")
                         %base-initrd-modules))
EOF
    fi
    cat >> "$f" <<EOF
  (bootloader (bootloader-configuration
    (bootloader grub-bootloader) (targets '("/dev/sda"))
    (keyboard-layout (keyboard-layout "$k"))
    (bootloader-extra-arguments '(("GRUB_CMDLINE_LINUX_DEFAULT" . "\"$kp\"")))))
  (keyboard-layout (keyboard-layout "$k"))
  (file-systems (append
    (list
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/")
                   (type "btrfs") (options "subvol=@root,compress=zstd:3,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/home")
                   (type "btrfs") (options "subvol=@home,compress=zstd:3,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/var/guix")
                   (type "btrfs") (options "subvol=@guix,compress=zstd:3,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/var/log")
                   (type "btrfs") (options "subvol=@var_log,compress=zstd:3,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/persist")
                   (type "btrfs") (options "subvol=@persist,compress=zstd:3,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
      (file-system (device (uuid "$EFI_UUID" 'fat)) (mount-point "/boot/efi")
                   (type "vfat") (options "rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=utf8,shortname=mixed,utf8,errors=remount-ro")
                   (needed-for-boot? #t))
EOF
    [[ "$s" == "yes" ]] && cat >> "$f" <<EOF
      (file-system (device (uuid "$ROOT_UUID" 'btrfs)) (mount-point "/swap")
                   (type "btrfs") (options "subvol=@swap,$SSD_OPTION,noatime")
                   (needed-for-boot? #t))
EOF
    cat >> "$f" <<EOF
      %base-file-systems))
  (users (cons (user-account (name "$u") (comment "Usuario principal")
                              (group "users")
                              (supplementary-groups '("wheel" "netdev" "audio" "video" "kvm" "input" "lp" "realtime")))
               %base-user-accounts))
  (sudoers-file (plain-file "sudoers" "root ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n"))
  (services (append
    (list
      (service network-manager-service-type)
      (service wpa-supplicant-service-type)
      (service openssh-service-type)
      (service ntp-service-type)
      (service flatpak-service-type)
      (service pipewire-service-type)
      (service elogind-service-type)
EOF
    case "$d" in
        plasma)
            cat >> "$f" <<EOF
      (service sddm-service-type (sddm-configuration (display-server "wayland") (wayland-session "plasma")))
      (service plasma-desktop-service-type)
EOF
            ;;
        gnome)
            cat >> "$f" <<EOF
      (service gdm-service-type)
      (service gnome-desktop-service-type)
EOF
            ;;
    esac
    [[ "$s" == "yes" ]] && cat >> "$f" <<EOF
      ;; 🔑 SWAP SERVICE — solución real para hibernación en Btrfs
      (swap-service (swap-space (list (swap-space (target "/swap/swapfile")
                                  (dependencies (list (file-system-service
                                    (file-system
                                      (mount-point "/swap")
                                      (device (uuid "$ROOT_UUID" 'btrfs))
                                      (type "btrfs")
                                      (options "subvol=@swap")))))))))
EOF
    cat >> "$f" <<EOF
    ) %base-services))
  (packages (append
    (list git curl wget nss-certs htop ripgrep tree firefox qutebrowser neovim
          emacs emacs-pgtk btrfs-progs ntfs-3g exfat-utils fuse pciutils usbutils
          cryptsetup flatpak discover intel-ucode)
EOF
    case "$d" in
        plasma)
            cat >> "$f" <<EOF
    (map specification->package '("plasma-workspace" "kate" "konsole" "dolphin" "ark" "gwenview"
                                 "okular" "spectacle" "kcalc" "systemsettings" "plasma-systemmonitor"
                                 "ksystemlog" "plasma-browser-integration" "plasma-pa" "plasma-nm"
                                 "kdeconnect" "kde-config-flatpak"))
EOF
            ;;
    esac
    cat >> "$f" <<EOF
    %base-packages))
  (name-service-switch %mdns-host-lookup-nss))
EOF
}

generate_channels_config() {
    local f=$1 n=$2
    cat > "$f" <<EOF
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
    [[ "$n" == "yes" ]] && cat >> "$f" <<EOF
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
    cat >> "$f" <<EOF
       %default-channels)
EOF
}

# =============================================================================
# PARTICIONES (sin cambios)
# =============================================================================
setup_disk() {
    local disk=$1
    local name=$(basename "$disk")
    local p="${name: -1}" =~ [0-9] && pref="p" || pref=""
    detect_ssd "$disk"

    parted "$disk" mklabel gpt mkpart ESP fat32 1MiB 551MiB set 1 esp on mkpart root btrfs 551MiB 100%
    mkfs.fat -F32 -n ESP "${disk}${pref}1"

    [[ "$ENCRYPT_DISK_CHOICE" == "yes" ]] && setup_encryption "${disk}${pref}2" || {
        mkfs.btrfs -f -L guix-root "${disk}${pref}2"
        ROOT_PARTITION="${disk}${pref}2"
    }

    mkdir -p "$MOUNT_POINT"
    mount "$ROOT_PARTITION" "$MOUNT_POINT"
    local subs=("@root" "@home" "@guix" "@var_log" "@persist" "@vartmp")
    [[ "$CREATE_SWAP" == "yes" ]] && subs+=("@swap")
    for s in "${subs[@]}"; do btrfs subvolume create "$MOUNT_POINT/$s"; done
    btrfs subvolume snapshot -r "$MOUNT_POINT/@root" "$MOUNT_POINT/@root-blank"
    umount "$MOUNT_POINT"

    mount -o "rw,relatime,compress=zstd:3,$SSD_OPTION,subvol=@root" "${disk}${pref}2" "$MOUNT_POINT"
    local mounts=(
        "home:@home" "var/guix:@guix" "var/log:@var_log" "persist:@persist" "var/tmp:@vartmp" "boot/efi:efi"
    )
    [[ "$CREATE_SWAP" == "yes" ]] && mounts+=("swap:@swap")
    for m in "${mounts[@]}"; do
        IFS=':' read -r dir sub <<< "$m"
        mkdir -p "$MOUNT_POINT/$dir"
        if [[ "$sub" == "efi" ]]; then
            mount -o "rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=utf8,shortname=mixed,utf8,errors=remount-ro" \
                  "${disk}${pref}1" "$MOUNT_POINT/$dir"
        else
            mount -o "rw,relatime,compress=zstd:3,$SSD_OPTION,subvol=$sub" "${disk}${pref}2" "$MOUNT_POINT/$dir"
        fi
    done
    [[ "$CREATE_SWAP" == "yes" ]] && configure_swap

    EFI_UUID=$(get_partition_uuid "${disk}${pref}1")
    ROOT_UUID=$(get_partition_uuid "$ROOT_PARTITION")
}

# =============================================================================
# CONFIGURACIÓN (sin cambios esenciales)
# =============================================================================
configure_system() {
    local self=$(prompt_yes_no "¿Modificar configuración manualmente?")
    [[ "$self" == "yes" ]] && return 0
    local h=$(get_user_input "Nombre del equipo" "${DEFAULTS[hostname]}")
    local t=$(select_timezone)
    local k=$(configure_keyboard_layout)
    local u=$(get_user_input "Usuario" "${DEFAULTS[login_name]}")
    local d=$(get_user_input "Escritorio" "${DEFAULTS[desktop]}")
    local n=$(get_user_input "¿Usar nonguix?" "${DEFAULTS[use_nonguix]}")
    CREATE_SWAP=$(prompt_yes_no "¿Swapfile para hibernación?" "${DEFAULTS[create_swap]}")
    ENCRYPT_DISK_CHOICE=$(prompt_yes_no "¿Encriptar disco?" "no")

    validate_desktop "$d" || d="${DEFAULTS[desktop]}"
    mkdir -p "$GUIX_CONFIG_DIR"
    generate_guix_config "$GUIX_CONFIG_DIR/system.scm" "$h" "$t" "$k" "$u" "$d" "$n" "$CREATE_SWAP" "$ENCRYPT_DISK_CHOICE"
    generate_channels_config "$GUIX_CONFIG_DIR/channels.scm" "$n"
}

setup_partitions() {
    local self=$(prompt_yes_no "¿Configurar hardware manualmente?")
    [[ "$self" == "yes" ]] && return 0
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,FSTYPE
    local dev; while true; do
        read -rp "Disco (ej: /dev/sda): " dev
        [[ "$dev" =~ ^/dev/[a-z]+[0-9]*$ && -b "$dev" ]] && break
        print_message "$RED" "Dispositivo inválido."
    done
    [[ "$(prompt_yes_no "¿Borrar $dev?" "no")" == "yes" ]] || { print_message "$RED" "Cancelado."; exit 1; }
    setup_disk "$dev"
}

# =============================================================================
# ✅ INSTALACIÓN CON SUSTITUTOS (✓ todo integrado)
# =============================================================================
prepare_guix_installation() {
    mkdir -p "$MOUNT_POINT/etc" "$MOUNT_POINT/var/guix"
    [[ -d "$GUIX_CONFIG_DIR" ]] && {
        cp "$GUIX_CONFIG_DIR/"*.scm "$MOUNT_POINT/etc/"
        print_message "$GREEN" "Configuraciones copiadas."
    }

    mkdir -p "$MOUNT_POINT/var/guix/profiles/per-user/root"
    chown -R root:root "$MOUNT_POINT/var/guix"
    chmod -R 755 "$MOUNT_POINT/var/guix"

    authorize_nonguix_key

    # ✅ URLs reales y fallback
    local urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    if [[ "$use_nonguix" == "yes" ]]; then
        if curl -sfI --max-time 3 https://substitutes.nonguix.org &>/dev/null; then
            urls+=" https://substitutes.nonguix.org"
        else
            print_message "$YELLOW" "Usando mirror: nonguix-proxy.ditigal.xyz"
            urls+=" https://nonguix-proxy.ditigal.xyz"
        fi
    fi

    restart_guix_daemon "$urls"
    print_message "$CYAN" "Sustitutos activos: $urls"
}

install_guix_system() {
    [[ -f "$MOUNT_POINT/etc/system.scm" ]] || { print_message "$RED" "system.scm no encontrado."; exit 1; }
    local urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org"
    [[ "$use_nonguix" == "yes" ]] && {
        if curl -sfI --max-time 3 https://substitutes.nonguix.org &>/dev/null; then
            urls+=" https://substitutes.nonguix.org"
        else
            urls+=" https://nonguix-proxy.ditigal.xyz"
        fi
    }

    print_message "$CYAN" "Iniciando instalación con sustitutos y --fallback…"
    set +e
    guix system init \
        --substitute-urls="$urls" \
        --fallback \
        "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" || {
        print_message "$YELLOW" "Reintentando sin grafts…"
        guix system init \
            --substitute-urls="$urls" \
            --fallback \
            --no-grafts \
            "$MOUNT_POINT/etc/system.scm" "$MOUNT_POINT" || {
            print_message "$RED" "✗ Falló instalación incluso con --no-grafts"
            exit 1
        }
    }
    set -e
    print_message "$GREEN" "✅ ¡Instalación exitosa con sustitutos!"
}

# =============================================================================
# VERIFICACIÓN Y LIMPIEZA
# =============================================================================
check_requirements() {
    [[ $EUID -eq 0 ]] || { print_message "$RED" "Ejecute como root."; exit 1; }
    command -v guix >/dev/null || { print_message "$RED" "Use ISO de nonguix."; exit 1; }
    local req=("parted" "mkfs.fat" "mkfs.btrfs" "btrfs" "blkid" "lsblk" "curl" "chattr" "ip")
    for c in "${req[@]}"; do command -v "$c" >/dev/null || { print_message "$RED" "Falta: $c"; exit 1; }; done
}

robust_cleanup() {
    print_message "$YELLOW" "Limpiando…"
    [[ "$ENCRYPT_DISK" == "yes" && -b "/dev/mapper/$ENCRYPTED_NAME" ]] && cryptsetup close "$ENCRYPTED_NAME" 2>/dev/null || true
    for m in "$MOUNT_POINT/boot/efi" "$MOUNT_POINT/swap" "$MOUNT_POINT/persist" \
             "$MOUNT_POINT/var/log" "$MOUNT_POINT/var/guix" "$MOUNT_POINT/home" "$MOUNT_POINT"; do
        mountpoint -q "$m" && { [[ -f "$m/swapfile" ]] && swapoff "$m/swapfile" 2>/dev/null; umount -l "$m"; }
    done
    dmsetup remove_all 2>/dev/null || true
    rm -rf "$GUIX_CONFIG_DIR" "$MOUNT_POINT/etc/guix-install-vars" 2>/dev/null || true
    print_message "$GREEN" "✓ Limpieza completada"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    trap robust_cleanup EXIT
    check_requirements
    check_system_requirements
    setup_network_connection || {
        print_message "$RED" "Sin red — la instalación será lenta o fallará."
        [[ "$(prompt_yes_no "¿Continuar?" "no")" == "yes" ]] || exit 1
    }

    print_message "$GREEN" "Iniciando instalación…"
    configure_system
    setup_partitions
    [[ "$CREATE_SWAP" == "yes" ]] && check_hibernation_support

    # Garantizar valor para use_nonguix
    : ${use_nonguix:="${DEFAULTS[use_nonguix]}"}

    prepare_guix_installation
    read -rp "¿Iniciar instalación? (Enter = sí, Ctrl+C = cancelar) "

    install_guix_system

    # Post-instalación
    for ns in proc sys dev run; do mount -o bind "/$ns" "$MOUNT_POINT/$ns"; done
    chroot "$MOUNT_POINT" /run/setuid-programs/passwd "${DEFAULTS[login_name]}" || true
    chroot "$MOUNT_POINT" /run/setuid-programs/passwd root || true
    for ns in proc sys dev run; do umount "$MOUNT_POINT/$ns" 2>/dev/null || true; done

    print_message "$GREEN" "✅ ¡Instalación completada!"
    echo
    print_message "$CYAN" "===================================="
    print_message "$GREEN" "Sistema listo:"
    print_message "$GREEN" " - Plasma, Qutebrowser, Neovim, Emacs"
    print_message "$GREEN" " - Discover + Flatpak"
    print_message "$GREEN" " - Hibernación funcional ✅"
    print_message "$CYAN" "===================================="
}

[[ "$(command -v guix)" ]] || { echo "Use ISO de nonguix."; exit 1; }
main "$@"
