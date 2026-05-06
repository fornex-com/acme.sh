#!/usr/bin/env sh
# shellcheck disable=SC2034

dns_fornex_info='Fornex.com
Site: Fornex.com
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_fornex
Options:
 FORNEX_API_KEY API Key
 FORNEX_API_URL Optional API base URL (default: https://fornex.com/api)
Issues: github.com/acmesh-official/acme.sh/issues/3998
Author: Timur Umarov <inbox@tumarov.com>
Patched for redirect-safe Authorization handling, exact root-domain detection,
correct subdomain TXT host handling, and reliable TXT cleanup.
'

FORNEX_API_URL_DEFAULT="https://fornex.com/api"

########  Public functions #####################

# Usage: dns_fornex_add _acme-challenge.www.domain.com "txt-value"
dns_fornex_add() {
  fulldomain=$1
  txtvalue=$2

  if ! _Fornex_API; then
    return 1
  fi

  if ! _get_root "$fulldomain"; then
    _err "Unable to determine root domain"
    return 1
  else
    _debug _domain "$_domain"
    _debug _sub_domain "$_sub_domain"
  fi

  _info "Adding TXT record"
  if _rest POST "dns/domain/$_domain/entry_set/" "{\"host\":\"${_sub_domain}\",\"type\":\"TXT\",\"value\":\"${txtvalue}\",\"ttl\":null}"; then
    _debug _response "$response"
    _info "Added, OK"
    return 0
  fi

  _err "Add txt record error."
  return 1
}

# Usage: dns_fornex_rm _acme-challenge.www.domain.com "txt-value"
dns_fornex_rm() {
  fulldomain=$1
  txtvalue=$2

  if ! _Fornex_API; then
    return 1
  fi

  if ! _get_root "$fulldomain"; then
    _err "Unable to determine root domain"
    return 1
  else
    _debug _domain "$_domain"
    _debug _sub_domain "$_sub_domain"
  fi

  _debug "Getting TXT records"
  if ! _rest GET "dns/domain/$_domain/entry_set?type=TXT"; then
    return 1
  fi

  _record_id="$(_fornex_find_txt_record_id "$response" "$_sub_domain" "$txtvalue")"
  _debug _record_id "$_record_id"

  if [ -z "$_record_id" ]; then
    _err "Txt record not found"
    return 1
  fi

  if ! _rest DELETE "dns/domain/$_domain/entry_set/$_record_id/" ""; then
    _err "Delete record error."
    return 1
  fi

  return 0
}

####################  Private functions below ##################################

# Input:  _acme-challenge.www.domain.com
# Output:
#   _sub_domain=_acme-challenge.www
#   _domain=domain.com
_get_root() {
  domain=$1
  i=1

  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f "$i"-100)
    _debug h "$h"

    if [ -z "$h" ]; then
      return 1
    fi

    if _fornex_zone_exists "$h"; then
      _domain="$h"
      if [ "$i" -gt 1 ]; then
        _sub_domain=$(printf "%s" "$domain" | cut -d . -f "1-$((i - 1))")
      else
        _sub_domain=""
      fi
      return 0
    fi

    i=$(_math "$i" + 1)
  done

  return 1
}

_fornex_zone_exists() {
  candidate=$1

  if ! _rest GET "dns/domain/?q=$candidate"; then
    return 1
  fi

  if _contains "$response" "\"detail\":\"No Domain matches the given query.\""; then
    return 1
  fi

  if _contains "$response" "\"detail\":\"Not found\""; then
    return 1
  fi

  if _contains "$response" "\"detail\":\"Authentication credentials were not provided.\""; then
    _err "Fornex API authentication failed. Check FORNEX_API_KEY and FORNEX_API_URL."
    return 1
  fi

  printf "%s" "$response" | grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"$candidate\""
}

_fornex_find_txt_record_id() {
  entries_json=$1
  host=$2
  value=$3

  printf "%s" "$entries_json" \
    | tr '{' '\n' \
    | grep "\"host\":\"$host\"" \
    | grep '"type":"TXT"' \
    | grep "\"value\":\"$value\"" \
    | sed -n 's#.*"id":\([0-9][0-9]*\).*#\1#p' \
    | head -n 1
}

_Fornex_API() {
  FORNEX_API_KEY="${FORNEX_API_KEY:-$(_readaccountconf_mutable FORNEX_API_KEY)}"
  FORNEX_API_URL="${FORNEX_API_URL:-$(_readaccountconf_mutable FORNEX_API_URL)}"

  if [ -z "$FORNEX_API_KEY" ]; then
    _err "You didn't specify the Fornex API key yet."
    _err "Please create your key and try again."
    return 1
  fi

  if [ -z "$FORNEX_API_URL" ]; then
    FORNEX_API_URL="$FORNEX_API_URL_DEFAULT"
  fi

  _saveaccountconf_mutable FORNEX_API_KEY "$FORNEX_API_KEY"
  _saveaccountconf_mutable FORNEX_API_URL "$FORNEX_API_URL"
  return 0
}

# method endpoint data
_rest() {
  m=$1
  ep="$2"
  data="$3"
  url="$FORNEX_API_URL/$ep"
  AUTH_HEADER="Authorization: Api-Key $FORNEX_API_KEY"

  _debug "$ep"
  _debug url "$url"

  if ! _exists curl; then
    _err "curl is required for dns_fornex"
    return 1
  fi

  if [ "$m" = "GET" ]; then
    response="$(curl --silent --show-error \
      --location \
      --location-trusted \
      --proto-redir =https \
      --max-redirs 5 \
      -H "$AUTH_HEADER" \
      -H "Accept: application/json" \
      "$url")"
  else
    _debug data "$data"
    response="$(curl --silent --show-error \
      --location \
      --location-trusted \
      --proto-redir =https \
      --max-redirs 5 \
      -X "$m" \
      -H "$AUTH_HEADER" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$data" \
      "$url")"
  fi
  _ret=$?

  if [ "$_ret" != "0" ]; then
    _err "error $ep"
    return 1
  fi

  response="$(printf "%s" "$response" | _normalizeJson)"
  _debug2 response "$response"

  if _contains "$response" "\"detail\":\"Authentication credentials were not provided.\""; then
    _err "Fornex API authentication failed: credentials were not provided."
    return 1
  fi

  return 0
}
