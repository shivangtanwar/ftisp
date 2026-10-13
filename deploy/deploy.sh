#!/usr/bin/env bash
# Deploy the FTISP dashboard to sad.shivang.me.
#
# Idempotent: safe to re-run for an update. It never overwrites the nginx site file once TLS is
# installed, because certbot rewrites that file and re-copying the template would drop the
# certificate lines. Pass --nginx to force the template back (then re-run certbot).
#
#   ./deploy/deploy.sh                 # update code and restart
#   ./deploy/deploy.sh --nginx         # also (re)install the nginx template
#   ./deploy/deploy.sh --first-time    # provision the host from scratch
set -euo pipefail

HOST="${FTISP_HOST:-gr19-remote}"
APP_DIR=/srv/ftisp/app
VENV_DIR=/srv/ftisp/venv
DATA_DIR=/srv/ftisp/data/unsw-nb15
REPO="${FTISP_REPO:-https://github.com/shivangtanwar/ftisp.git}"
DOMAIN="${FTISP_DOMAIN:-sad.shivang.me}"
SERVICE=ftisp
SITE=/etc/nginx/sites-available/ftisp

remote() { ssh "$HOST" "$@"; }

first_time() {
  echo "==> provisioning packages"
  remote 'export DEBIAN_FRONTEND=noninteractive
          apt-get update -qq
          apt-get install -y -qq python3-venv python3-pip nginx certbot python3-certbot-nginx git apache2-utils >/dev/null'

  echo "==> creating service user and directories"
  remote 'id -u ftisp >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin ftisp
          mkdir -p /srv/ftisp/app /srv/ftisp/venv /srv/ftisp/data
          chown -R ftisp:ftisp /srv/ftisp'
}

sync_code() {
  echo "==> fetching $REPO"
  remote "if [ -d $APP_DIR/.git ]; then
            git -C $APP_DIR fetch --quiet origin main && git -C $APP_DIR reset --hard --quiet origin/main
          else
            rm -rf $APP_DIR && git clone --quiet $REPO $APP_DIR
          fi
          git -C $APP_DIR log -1 --format='    %h %s'"
}

install_python() {
  echo "==> installing python dependencies"
  # requirements.txt first: `pip install -e .` installs the package itself and does not pull the
  # runtime dependencies, since pyproject declares none.
  remote "test -d $VENV_DIR || python3 -m venv $VENV_DIR
          $VENV_DIR/bin/pip install --quiet --upgrade pip
          $VENV_DIR/bin/pip install --quiet -r $APP_DIR/requirements.txt
          $VENV_DIR/bin/pip install --quiet -e $APP_DIR
          chown -R ftisp:ftisp /srv/ftisp"
}

fetch_data() {
  echo "==> ensuring dataset"
  remote "sudo -u ftisp $VENV_DIR/bin/python $APP_DIR/scripts/fetch_data.py --dest $DATA_DIR"
}

install_service() {
  echo "==> installing systemd unit"
  scp -q "deploy/$SERVICE.service" "$HOST:/etc/systemd/system/$SERVICE.service"
  remote "systemctl daemon-reload
          systemctl enable --quiet $SERVICE
          systemctl restart $SERVICE
          sleep 4
          systemctl is-active --quiet $SERVICE && echo '    service active' || {
            journalctl -u $SERVICE -n 30 --no-pager; exit 1; }"
}

install_nginx() {
  # Choose the template by whether a certificate already exists: the post-TLS file references
  # certificate paths that would make `nginx -t` fail before issuance.
  local template=deploy/nginx-ftisp-pre-tls.conf
  if remote "test -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem"; then
    template=deploy/nginx-ftisp.conf
  fi
  echo "==> installing nginx site ($(basename "$template"))"
  scp -q "$template" "$HOST:$SITE"
  remote "ln -sf $SITE /etc/nginx/sites-enabled/ftisp
          rm -f /etc/nginx/sites-enabled/default
          nginx -t && systemctl reload nginx && echo '    nginx reloaded'"
}

setup_tls() {
  echo "==> obtaining certificate for $DOMAIN"
  remote "test -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem" && { echo "    certificate already present"; return; }
  echo "    nginx must serve the template without the TLS block first; running certbot"
  remote "certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect"
}

main() {
  local nginx=0 first=0
  for arg in "$@"; do
    case "$arg" in
      --nginx) nginx=1 ;;
      --first-time) first=1 ;;
      *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
  done

  [ "$first" = 1 ] && first_time
  sync_code
  install_python
  fetch_data
  install_service
  if [ "$nginx" = 1 ]; then install_nginx; setup_tls; fi

  echo "==> deployed"
  remote "systemctl is-active $SERVICE; curl -fsS -o /dev/null -w '    local http %{http_code}\n' http://127.0.0.1:8100/ || true"
  echo "    https://$DOMAIN"
}

main "$@"
