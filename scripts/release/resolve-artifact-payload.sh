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
  fail "Для команды resolve-artifact-payload укажите ROOT VERSION MARKER [LABEL]"
[[ "${VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || \
  fail "${LABEL}: некорректная версия для структуры артефакта: ${VERSION}"
[[ "${MARKER}" != */* && "${MARKER}" != "." && "${MARKER}" != ".." ]] || \
  fail "${LABEL}: маркер должен быть именем файла без пути: ${MARKER}"
[[ -d "${ROOT_DIR}" && ! -L "${ROOT_DIR}" ]] || \
  fail "${LABEL}: корневой каталог артефакта отсутствует или является символической ссылкой: ${ROOT_DIR}"

EXPECTED_DIR="${ROOT_DIR}/release-${VERSION}"
DIRECT_MARKER="${ROOT_DIR}/${MARKER}"
NESTED_MARKER="${EXPECTED_DIR}/${MARKER}"

shopt -s nullglob
release_dirs=("${ROOT_DIR}"/release-*)
shopt -u nullglob

if [[ -f "${DIRECT_MARKER}" && ! -L "${DIRECT_MARKER}" ]]; then
  if (( ${#release_dirs[@]} != 0 )); then
    fail "${LABEL}: неоднозначная структура артефакта: одновременно присутствуют маркер плоского размещения и каталог release-*"
  fi
  if find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 -type l -print -quit | grep -q .; then
    fail "${LABEL}: плоский пакет артефакта содержит символическую ссылку"
  fi
  printf '%s\n' "${ROOT_DIR}"
  exit 0
fi

(( ${#release_dirs[@]} == 1 )) || \
  fail "${LABEL}: ожидался ровно один каталог данных release-${VERSION}, найдено ${#release_dirs[@]}"
[[ "${release_dirs[0]}" == "${EXPECTED_DIR}" ]] || \
  fail "${LABEL}: содержимое артефакта относится не к ${VERSION}: ${release_dirs[0]}"
[[ -d "${EXPECTED_DIR}" && ! -L "${EXPECTED_DIR}" ]] || \
  fail "${LABEL}: данные выпуска release-${VERSION} отсутствуют или являются символической ссылкой"
[[ -f "${NESTED_MARKER}" && ! -L "${NESTED_MARKER}" ]] || \
  fail "${LABEL}: обязательный файл-маркер отсутствует в release-${VERSION}: ${MARKER}"

if find "${ROOT_DIR}" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) -print -quit | grep -q .; then
  fail "${LABEL}: вложенная структура артефакта содержит неожиданные файлы или символические ссылки на верхнем уровне"
fi
if find "${EXPECTED_DIR}" -mindepth 1 -maxdepth 1 -type l -print -quit | grep -q .; then
  fail "${LABEL}: данные выпуска release-${VERSION} содержат символическую ссылку"
fi

printf '%s\n' "${EXPECTED_DIR}"
