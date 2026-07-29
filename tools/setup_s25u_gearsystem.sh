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

retry_command() {
  attempt=1
  while [ "$attempt" -le 3 ]; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      sleep "$((attempt * 2))"
    fi
    attempt="$((attempt + 1))"
  done
  return 1
}

fail_stage() {
  echo "SFKR setup failed: $1" >&2
  exit "$2"
}

export DEBIAN_FRONTEND=noninteractive

if [ -x "$install_dir/gearsystem" ] &&
   [ -f "$install_dir/.sfkr-version" ] &&
   [ "$(cat "$install_dir/.sfkr-version")" = "$version" ] &&
   ! ldd "$install_dir/gearsystem" | grep -q 'not found'; then
  printf 'Gearsystem %s is already ready at %s\n' "$version" "$install_dir"
  exit 0
fi

echo "SFKR setup stage: apt-repair"
dpkg --configure -a ||
  fail_stage "apt-configure" 110
retry_command apt-get -o Acquire::Retries=5 update ||
  fail_stage "apt-update" 111
retry_command apt-get \
  -o Dpkg::Options::=--force-confold \
  --fix-broken \
  --no-install-recommends \
  -y install ||
  fail_stage "apt-repair" 112
retry_command apt-get \
  --no-install-recommends \
  -y install ca-certificates curl unzip libstdc++6 ||
  fail_stage "apt-runtime-packages" 113

echo "SFKR setup stage: verified-gearsystem-archive"
curl \
  --fail \
  --location \
  --retry 5 \
  --retry-all-errors \
  "$download_url" \
  --output "$archive" ||
  fail_stage "gearsystem-download" 114
printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check - ||
  fail_stage "gearsystem-sha256" 115
rm -rf "$install_dir"
mkdir -p "$install_dir"
unzip -q "$archive" -d "$install_dir" ||
  fail_stage "gearsystem-extract" 116
chmod 0755 "$install_dir/gearsystem" ||
  fail_stage "gearsystem-mode" 117
rm -f "$archive"

if ! ldconfig -p 2>/dev/null | grep -q 'libSDL3\.so\.0'; then
  sdl_package=""
  for candidate in libsdl3-0 libsdl3-0.2 libsdl3-0.0; do
    if apt-cache show "$candidate" >/dev/null 2>&1; then
      sdl_package="$candidate"
      break
    fi
  done
  if [ -n "$sdl_package" ]; then
    retry_command apt-get --no-install-recommends -y install "$sdl_package" ||
      fail_stage "sdl-runtime-package" 118
  else
    echo "SFKR setup stage: pinned-sdl-build"
    retry_command apt-get \
      --no-install-recommends \
      -y install build-essential cmake git ninja-build pkg-config ||
      fail_stage "sdl-build-packages" 119
    rm -rf /tmp/sfkr-sdl3
    retry_command git clone \
      --filter=blob:none \
      https://github.com/libsdl-org/SDL.git \
      /tmp/sfkr-sdl3 ||
      fail_stage "sdl-clone" 120
    git -C /tmp/sfkr-sdl3 checkout --detach "$sdl_commit" ||
      fail_stage "sdl-checkout" 121
    cmake \
      -S /tmp/sfkr-sdl3 \
      -B /tmp/sfkr-sdl3/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DSDL_SHARED=ON \
      -DSDL_STATIC=OFF \
      -DSDL_TEST_LIBRARY=OFF \
      -DSDL_TESTS=OFF \
      -DSDL_EXAMPLES=OFF ||
      fail_stage "sdl-configure" 122
    cmake --build /tmp/sfkr-sdl3/build ||
      fail_stage "sdl-build" 123
    cmake --install /tmp/sfkr-sdl3/build ||
      fail_stage "sdl-install" 124
    ldconfig ||
      fail_stage "sdl-ldconfig" 125
    rm -rf /tmp/sfkr-sdl3
  fi
fi

if ldd "$install_dir/gearsystem" | grep -q 'not found'; then
  ldd "$install_dir/gearsystem" >&2
  fail_stage "gearsystem-dependencies" 126
fi
printf '%s\n' "$version" > "$install_dir/.sfkr-version"
printf 'Gearsystem %s is ready at %s\n' "$version" "$install_dir"
SFKR_UBUNTU

echo "S25U Gearsystem MCP runtime is ready."
