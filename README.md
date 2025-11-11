# 🌱 nonguix-guix-installer

Instalador automatizado de **Guix System** con soporte para hardware moderno (vía `nonguix`), Btrfs, hibernación, Flatpak + Discover para Plasma-desktop y flatpak + gnome-software para los otros escritorios. Los escritorios Plasma, gnome, cinnamon, lxqt, xfce, mate, sway, i3 o ninguno.

> ✅ Diseñado para ejecutarse **directamente desde el ISO live de Nonguix**  
> ✅ Incluye soporte robusto para **sustitutos precompilados** (¡instalación rápida!)  
> ✅ Compatible con **Shepherd init** y **GRUB**

---

## 🔧 Características

- ✅ **Btrfs con subvolúmenes**: `@root`, `@home`, `@guix`, `@var_log`, `@persist`, `@swap`
- ✅ **Hibernación funcional** con swapfile en Btrfs (soluciona `herd start swap` no automático [[26]])
- ✅ **Canales**: Guix + Nonguix (firmware no libre, drivers, kernel `linux`)
- ✅ **Sustitutos optimizados**: `ci.guix.gnu.org`, `bordeaux.guix.gnu.org`, `substitutes.nonguix.org`, fallback a `nonguix-proxy.ditigal.xyz`
- ✅ **Redes ocultas WiFi** vía `connmanctl`
- ✅ **Configuración "erase your darlings"**: `/persist` para datos persistentes
- ✅ **Flatpak + Discover** integrado y listo para usar

---

## ⚡ Requisitos

- Hardware: ≥2GB RAM, ≥20GB disco (SSD recomendado)
- Arranque: **UEFI**
- Medio: ISO live de **Nonguix** (recomendado: [versión más reciente](https://gitlab.com/nonguix/nonguix/-/releases)) o la versión de SystemCrafters (revisar las release pues en el último año no han generado un iso, solamente agregado archivos source.code) (https://github.com/SystemCrafters/guix-installer/releases)

---

## 🚀 Uso

```bash
# 1. Descargar y copiar al ISO live
chmod +x nonguix-guix-installer.sh
sudo ./nonguix-guix-installer.sh
