#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

GEARSYSTEM_VERSION="3.9.14"
GEARSYSTEM_SHA256="a36b657b815ec6b90f208f07c5ee563cc38a1a3da52818f601b853836b20d8c8"
GEARSYSTEM_URL="https://github.com/drhelius/Gearsystem/releases/download/${GEARSYSTEM_VERSION}/Gearsystem-${GEARSYSTEM_VERSION}-desktop-ubuntu24.04-arm64.zip"
SDL_COMMIT="f87239e71e42da91ca317a12eefb82cfbf3393eb"

case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    echo "This setup is pinned for the S25U ARM64 environment." >&2
    exit 1
    ;;
esac

if ! command -v proot-distro >/dev/null 2>&1; then
  pkg install -y proot-distro
fi
if ! proot-distro login ubuntu -- true >/dev/null 2>&1; then
  proot-distro install ubuntu
fi

proot-distro login ubuntu -- bash -s -- \
  "$GEARSYSTEM_VERSION" \
  "$GEARSYSTEM_SHA256" \
  "$GEARSYSTEM_URL" \
  "$SDL_COMMIT" <<'SFKR_UBUNTU'
set -euo pipefail
version="$1"
expected_sha="$2"
download_url="$3"
sdl_commit="$4"
install_dir="/opt/sfkr-gearsystem"
archive="/tmp/sfkr-gearsystem.zip"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl unzip libstdc++6 libgl1 libegl1 libglx0

if [ -x "$install_dir/gearsystem" ] &&
   [ -f "$install_dir/.sfkr-version" ] &&
   [ "$(cat "$install_dir/.sfkr-version")" = "$version" ] &&
   ! ldd "$install_dir/gearsystem" | grep -q 'not found'; then
  printf 'Gearsystem %s is already ready at %s\n' "$version" "$install_dir"
  exit 0
fi

if ! ldconfig -p 2>/dev/null | grep -q 'libSDL3\.so\.0'; then
  sdl_package=""
  for candidate in libsdl3-0 libsdl3-0.2 libsdl3-0.0; do
    if apt-cache show "$candidate" >/dev/null 2>&1; then
      sdl_package="$candidate"
      break
    fi
  done
  if [ -n "$sdl_package" ]; then
    apt-get install -y "$sdl_package"
  else
    apt-get install -y build-essential cmake git ninja-build pkg-config
    rm -rf /tmp/sfkr-sdl3
    git clone --filter=blob:none https://github.com/libsdl-org/SDL.git /tmp/sfkr-sdl3
    git -C /tmp/sfkr-sdl3 checkout --detach "$sdl_commit"
    cmake \
      -S /tmp/sfkr-sdl3 \
      -B /tmp/sfkr-sdl3/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DSDL_SHARED=ON \
      -DSDL_STATIC=OFF \
      -DSDL_TEST_LIBRARY=OFF \
      -DSDL_TESTS=OFF \
      -DSDL_EXAMPLES=OFF
    cmake --build /tmp/sfkr-sdl3/build
    cmake --install /tmp/sfkr-sdl3/build
    ldconfig
    rm -rf /tmp/sfkr-sdl3
  fi
fi

curl --fail --location --retry 3 "$download_url" --output "$archive"
printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check -
rm -rf "$install_dir"
mkdir -p "$install_dir"
unzip -q "$archive" -d "$install_dir"
chmod 0755 "$install_dir/gearsystem"
printf '%s\n' "$version" > "$install_dir/.sfkr-version"
rm -f "$archive"

if ldd "$install_dir/gearsystem" | grep -q 'not found'; then
  ldd "$install_dir/gearsystem" >&2
  exit 1
fi
printf 'Gearsystem %s is ready at %s\n' "$version" "$install_dir"
SFKR_UBUNTU

echo "S25U Gearsystem MCP runtime is ready."
