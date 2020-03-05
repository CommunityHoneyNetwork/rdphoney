#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o errexit
set -o nounset
set -o pipefail

main () {

    DEBUG=${DEBUG:-false}
    if [[ ${DEBUG} == "true" ]]
    then
      set -o xtrace
    fi

    # Register this host with CHN if needed
    chn-register.py \
        -p rdphoney \
        -d "${DEPLOY_KEY}" \
        -u "http://${CHN_SERVER}" -k \
        -o "${RDPHONEY_JSON}" \
        -i "${IP_ADDRESS}"

    local uid="$(cat ${RDPHONEY_JSON} | jq -r .identifier)"
    local secret="$(cat ${RDPHONEY_JSON} | jq -r .secret)"

    # Keep old var names, but create also create some new ones that
    # containedenv can understand

    export RDPHONEY_output_hpfeeds__server="${FEEDS_SERVER}"
    export RDPHONEY_output_hpfeeds__port="${FEEDS_SERVER_PORT:-10000}"
    export RDPHONEY_output_hpfeeds__identifier="${uid}"
    export RDPHONEY_output_hpfeeds__secret="${secret}"
    export RDPHONEY_output_hpfeeds__tags="${TAGS}"

    # Write out custom conpot config
    containedenv-config-writer.py \
      -p RDPHONEY_ \
      -f ini \
      -r /opt/rdphoney.cfg.dist \
      -o /opt/rdphoney.cfg

    python /opt/rdphoney/rdp_honeyscript.py --config /opt/rdphoney.cfg
}

main "$@"
