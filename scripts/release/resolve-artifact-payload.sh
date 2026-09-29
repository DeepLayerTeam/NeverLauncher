#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-}"
VERSION="${2:-}"
MARKER="${3:-}"
LABEL="${4:-production artifact}"

fail() {
  printf 'Ошибка: %s\n' "$*" >&2
  exit 1
}

[[ -n "${ROOT_DIR}" && -n "${VERSION}" && -n "${MARKER}" ]] || \
  fail "resolve-artifact-payload требует ROOT VERSION MARKER [LABEL]"
[[ "${VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || \
  fail "${LABEL}: некорректная версия для artifact layout: ${VERSION}"
[[ "${MARKER}" != */* && "${MARKER}" != "." && "${MARKER}" != ".." ]] || \
  fail "${LABEL}: marker должен быть именем файла без пути: ${MARKER}"
[[ -d "${ROOT_DIR}" && ! -L "${ROOT_DIR}" ]] || \
  fail "${LABEL}: artifact root отсутствует или является symlink: ${ROOT_DIR}"

EXPECTED_DIR="${ROOT_DIR}/release-${VERSION}"
DIRECT_MARKER="${ROOT_DIR}/${MARKER}"
NESTED_MARKER="${EXPECTED_DIR}/${MARKER}"

shopt -s nullglob
release_dirs=("${ROOT_DIR}"/release-*)
shopt -u nullglob

if [[ -f "${DIRECT_MARKER}" && ! -L "${DIRECT_MARKER}" ]]; then
  if (( ${#release_dirs[@]} != 0 )); then
    fail "${LABEL}: неоднозначный mixed artifact layout: flat marker и release-* directory присутствуют одновременно"
  fi
  if find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 -type l -print -quit | grep -q .; then
    fail "${LABEL}: flat artifact payload содержит symlink"
  fi
  printf '%s\n' "${ROOT_DIR}"
  exit 0
fi

(( ${#release_dirs[@]} == 1 )) || \
  fail "${LABEL}: ожидался ровно один release-${VERSION} payload directory, найдено ${#release_dirs[@]}"
[[ "${release_dirs[0]}" == "${EXPECTED_DIR}" ]] || \
  fail "${LABEL}: artifact payload относится не к ${VERSION}: ${release_dirs[0]}"
[[ -d "${EXPECTED_DIR}" && ! -L "${EXPECTED_DIR}" ]] || \
  fail "${LABEL}: release-${VERSION} payload отсутствует или является symlink"
[[ -f "${NESTED_MARKER}" && ! -L "${NESTED_MARKER}" ]] || \
  fail "${LABEL}: обязательный marker отсутствует в release-${VERSION}: ${MARKER}"

if find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) -print -quit | grep -q .; then
  fail "${LABEL}: nested artifact layout содержит неожиданные top-level files/symlinks"
fi
if find "${EXPECTED_DIR}" -mindepth 1 -maxdepth 1 -type l -print -quit | grep -q .; then
  fail "${LABEL}: release-${VERSION} payload содержит symlink"
fi

printf '%s\n' "${EXPECTED_DIR}"
