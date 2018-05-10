#!/usr/bin/env bash

# -- HELPER FUNCTIONS, PT. 1 --------------------------------------------------
DEBUG=NotEmpty
DEBUG=
NOW="$(date '+%Y-%m-%d_%H-%M-%S')"

# Echo to strerr
function errcho() {
  >&2 echo "$@"
}

# Die with message to stderr and exit code
function die() {
  errcho "$1"
  exit "$2"
}

# Quiet it all
function qt() {
  "$@" > /dev/null 2>&1
}

# Quiet only errors
function qte() {
  "$@" 2> /dev/null
}
# -- CHECKS RUNNING IN BASH ---------------------------------------------------
INVOKED_AS="$(basename "$BASH")"
if [[ -z "$INVOKED_AS" ]] || [[ "$INVOKED_AS" != 'bash' ]]; then
  die "Please invoke this script thusly: bash $0" 127
fi
# -- DON'T RUN AS SUDO --------------------------------------------------------
if [[ $UID -eq 0 ]]; then
  if [[ ! -z "$SUDO_USER" ]]; then
    cat <<EOT
It looks like you're running this script via sudo.
That's OK. I'll re-run it as: $SUDO_USER
EOT
    exec sudo -u "$SUDO_USER" bash -c "$0"
  else
    die "Yikes! Please don't run this as root!" 127
  fi
fi
# -- CHECK OS VERSION ---------------------------------------------------------
pkg_manager=""
if [[ $OSTYPE == linux-gnu* ]]; then
  [[ -z "$pkg_manager" ]] && pkg_manager="$(basename "$(command -v apt-get)")"
  [[ -z "$pkg_manager" ]] && pkg_manager="$(basename "$(command -v pacman)")"
  [[ -z "$pkg_manager" ]] && pkg_manager="$(basename "$(command -v yum)")"

  if [[ -z "$pkg_manager" ]]; then
    cat <<EOT
Sorry! This script is currently only compatible with:

  apt-get based distributions, tested on:

    Xubuntu

  pacman based distributions, tested on:

    Antergos
    Manjaro

  yum based distributions, tested on:

    Fedora

You're running:

$(
  if [[ -e /proc/version ]]; then
    cat /proc/version
  elif [[ -e /etc/issue ]]; then
    cat /etc/issue
  fi
)

EOT
    exit 127
  fi
else
  die "Oops! This script is not compatibile or test for your OS" 127
fi
# -- HELPER FUNCTIONS, PT. 2 --------------------------------------------------
# Parse out .data sections of this file
function get_pkgs() {
 sed -n "/Start: $1/,/End: $1/p" "$0"
}

# Clean-up!
function clean_up() {
  errcho "Cleaning up! Bye!"
  exit
}

trap clean_up EXIT INT QUIT TERM
# -----------------------------------------------------------------------------
# Strip out comments, beginning and trailing whitespace, [ :].*$, and blank lines
function clean() {
  sed 's/#.*$//;s/^[[:blank:]][[:blank:]]*//g;s/[[:blank:]][[:blank:]]*$//;s/[ :].*$//;/^$/d' "$1" | sort -u
}

# Process install
function process() {
  local brew_php_linked debug line pecl_pkg num_ver

  export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"

  debug="$([[ ! -z "$DEBUG" ]] && echo echo)"

  # Compare what is already installed with what we want installed
  while read -r -u3 -a line && [[ ! -z "$line" ]]; do
    show_status "($1) $line"
    case "$1" in
      'apt-get')
        $debug sudo apt-get install -y "${line[@]}";;
      'pacman')
        $debug sudo pacman -S --noconfirm "${line[@]}";;
      'yum')
        $debug sudo yum -y install "${line[@]}";;
      'brew tap')
        $debug brew tap "${line[@]}";;
      'brew leaves')
        # Quick hack to allow for extra --args
        line="$(grep -E "^$line[ ]*.*$" <(clean <(get_pkgs "$1")))"
        $debug brew install "${line[@]}";;
      'brew php')
        [[ -z "$BREW_PREFIX" ]] && die "Brew is either not yet installed, or \$BREW_PREFIX not yet set" 127

        brew_php_linked="$(qte cd "$BREW_PREFIX/var/homebrew/linked" && qte ls -d php php@[57].[0-9]*)"
        num_ver="$(grep -E -o '[0-9]+\.[0-9]+' <<< "$line" || brew info php | head -1 | grep -E -o '[0-9]+\.[0-9]+')"

        if [[ ! -z "$brew_php_linked" ]]; then
          if [[ "$line" != "$brew_php_linked" ]]; then
            brew unlink "$brew_php_linked"
          fi
        fi

        # Wipe the slate clean
        if [[ -f "$BREW_PREFIX/etc/php/$num_ver/php.ini" ]]; then
          show_status "Found old php.ini, backed up to: $BREW_PREFIX/etc/php/$num_ver/php.ini-$NOW"
          mv "$BREW_PREFIX/etc/php/$num_ver/php.ini"{,-"$NOW"}
        fi
        rm -rf "$BREW_PREFIX/share/${line/php/pear}"

        # configure: error: DBA: Could not find necessary header file(s).
        # https://gist.github.com/ElliottLandsborough/b960736a071fb79d8a45532315c6170b
        #   [remove line with "--with-ndbm"]
        sed -i '/--with-ndbm/d'     "$BREW_PREFIX/Homebrew/Library/Taps/homebrew/homebrew-core/Formula/${line}.rb"
        # For pacman
        sed -i '/--enable-dtrace/d' "$BREW_PREFIX/Homebrew/Library/Taps/homebrew/homebrew-core/Formula/${line}.rb"
        $debug brew install "$line"
        qt pushd "$BREW_PREFIX/Homebrew/Library/Taps/homebrew/homebrew-core/Formula/"
        git checkout -- "${line}.rb"
        qt popd
        $debug brew link --overwrite --force "$line"

        show_status "Installing PECLs for: $line"

        $debug "$BREW_PREFIX/opt/$line/bin/pecl" channel-update pecl.php.net

        # This inner loop to install pecl packages for specific php versions'
        # only run when the brew install for the specific version's run, i.e.,
        # pecl installation's not separate/standalone, currently.
        while read -r -u4 pecl_pkg; do
          if pecl_pkg="$(sed 's/#.*$//' <<< "$pecl_pkg")" && [[ ! -z "$pecl_pkg" ]]; then
            # We're not checking to see if it's already installed

            # This entire block is to accommodate php@5.6 :/
            if [[ "$line" =~ @ ]] && [[ "$pecl_pkg" =~ $line ]]; then
              # TODO: refine this for multiple versions
              pecl_pkg="$(sed "s/:$line//" <<< "$pecl_pkg")"
            else
              pecl_pkg="$(sed 's/:.*$//' <<< "$pecl_pkg")"
            fi

            show_status "PECL: Installing: $pecl_pkg"
            qt "$BREW_PREFIX/opt/$line/bin/pecl" install "$pecl_pkg" <<< ''
          fi
        done 4< <(get_pkgs "pecl")

        # Pin them since they take a loooong time to compile
        $debug brew pin "$line"
        ;;
      npm)
        SUDO=
        $debug $SUDO npm install -g "${line[@]}";;
      gem)
        SUDO=sudo
        # shellcheck disable=SC2012
        if [[ "$(ls -ld "$(command -v gem)" | awk '{print $3}')" != 'root' ]]; then
          SUDO=
        fi

        line=( $(grep -E "^$line[ ]*.*$" <(get_pkgs "$1")) )
        $debug $SUDO "$1" install -f "${line[@]}";;
      *)
        ;;
    esac
  done 3< <(get_diff "$@")

  qt hash
}

# Get list of installed packages
function get_installed() {
  case "$1" in
    'apt-get')
      qte apt list --installed | sed 's;/.*$;;' | sort -u;;
    'pacman')
      qte pacman -Qn | sed 's/ .*$//' | sort -u;;
    'yum')
      qte yum list installed | sed 's/\..*$//' | sort -u;;
    'brew tap')
      brew tap | sort -u;;
    'brew leaves'|'brew php')
      brew list | sort -u;;
    npm)
      qte npm -g list | iconv -c -f utf-8 -t ascii | grep -v -e '^/' -e '^  ' | sed 's/@.*$//;/^$/d;s/ //g' | sort -u;;
    gem)
      $1 list | sed 's/ .*$//' | sort -u;;
    *)
      echo;;
  esac
}

# Get difference of these sets
function get_diff() {
  comm -13 <(get_installed "$1") <(clean <(get_pkgs "$1"))
}

# Colorized output status
function show_status() {
  echo "$(tput setaf 3)Working on: $(tput setaf 5)${*}$(tput sgr0)"
}

# Git commit /etc changes via sudo
function etc_git_commit() {
  local msg

  msg="$2"
  show_status 'Committing to git'
  qt pushd "$BREW_PREFIX/etc"
  $1
  git commit -m "[Slipstream] $msg"
  qt popd
}

# Generate self-signed SSL
function genssl() {
  # http://www.jamescoyle.net/how-to/1073-bash-script-to-create-an-ssl-certificate-key-and-request-csr
  # http://www.freesoftwaremagazine.com/articles/generating_self_signed_test_certificates_using_one_single_shell_script
  # http://www.akadia.com/services/ssh_test_certificate.html
  local domain C ST L O OU CN emailAddress password

  domain=server

  # Change to your company details (NOTE: CN should match Apache ServerName value
  C=US;  ST=Oregon;  L=Portland; O=$domain; # Country, State, Locality, Organization
  OU=IT; CN=127.0.0.1; emailAddress="$USER@localhost"
  # Common Name, Email Address, Organizational Unit

  #Optional
  password=dummypassword
  # Step 1: Generate a Private Key
  openssl genrsa -des3 -passout pass:$password -out "${domain}.key" 2048 -noout
  # Step 2: Generate a CSR (Certificate Signing Request)
  openssl req -new -key "${domain}.key" -out "${domain}.csr" -passin pass:"$password" \
    -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN/emailAddress=$emailAddress"
  # Step 3: Remove Passphrase from Key. Comment the line out to keep the passphrase
  openssl rsa -in "${domain}.key" -passin pass:"$password" -out "${domain}.key"
  # Step 4: Generating a Self-Signed Certificate
  openssl x509 -req -days 3650 -in "${domain}.csr" -signkey "${domain}.key" -out "${domain}.crt"
}
# -- OVERVIEW OF CHANGES THAT WILL BE MADE ------------------------------------
# .text
cat <<EOT

OK. It looks like we're ready to go.
*******************************************************************************
***** NOTE: This script assumes a "pristine" installation of Ubuntu,      *****
***** If you've already made changes to files in /etc, then all bets      *****
***** are off. You have been WARNED!                                      *****
*******************************************************************************
If you wish to continue, then this is what I'll be doing:
  - Git-ifying your /etc folder with etckeeper
  - Allow for password-less sudo by adding /etc/sudoers.d/10-local-users
  - Install linux brew, and some brew packages
  - Install Ruby if necessary (via 'rbenv/ruby-build') and install some gems
  - Install NodeJs if necessary (via 'n') some npm packages
  -- Configure:
    - Postfix (Disable outgoing mail)
    - MariaDB (InnoDB tweaks, etc.)
    - Php.ini (Misc. configurations)
    - Apache2 (Enable modules, and add wildcard vhost conf)
      [including ServerAlias for *.localhost.metaltoad-sites.com, and *.xip.io]
    - Dnsmasq (Resolve *.localhost domains w/OUT /etc/hosts editing)
EOT

# shellcheck disable=SC2034
read -r -p "Hit [enter] to start or control-c to quit: " dummy
# -- VERSION CONTROL /etc -----------------------------------------------------
if [[ ! -d /etc/.git ]]; then
  show_status "Git init-ing /etc [you may be prompted for sudo password]: "

  if [[ "$pkg_manager" = "apt-get" ]]; then
    sudo apt-get update
    # apt-cache depends etckeeper
    sudo apt-get install -y etckeeper
  elif [[ "$pkg_manager" = "pacman" ]]; then
    sudo pacman -Syy --noconfirm # The -Syu seems to do entire system upgrade
    sudo pacman -S --noconfirm etckeeper
    sudo etckeeper init
  elif [[ "$pkg_manager" = "yum" ]]; then
    sudo yum -y install etckeeper
    sudo etckeeper init
  fi

  sudo -H bash -c "
[[ -z '$(git config --get user.name)'  ]] && git config --global user.name 'System Administrator'
[[ -z '$(git config --get user.email)' ]] && git config --global user.email '$USER@localhost'"
fi

# -- PRIME THE PUMP -----------------------------------------------------------
echo "== Processing $pkg_manager =="
show_status "$pkg_manager"
process "$pkg_manager"

qt hash

if [[ ! -L /Users ]]; then
  show_status "Symlinking /home to /Users"
  sudo ln -nfs /home /Users
fi
# -- PASSWORDLESS SUDO --------------------------------------------------------
echo "== Processing Sudo Password =="
if [[ ! -e /etc/sudoers.d/10-local-users ]]; then
  [[ ! -d /etc/sudoers.d ]] && sudo mkdir -p /etc/sudoers.d
  cat <<EOT | qt sudo tee /etc/sudoers.d/10-local-users
# User rules for $USER
$USER ALL=(ALL) NOPASSWD:ALL
EOT

  sudo chmod 640 /etc/sudoers.d/10-local-users
  sudo etckeeper commit -m "[Slipstream] Password-less sudo for '$USER'"
fi
# -- HOMEBREW -----------------------------------------------------------------
echo "== Processing Homebrew =="

export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"

if ! qt command -v brew; then
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/Linuxbrew/install/master/install.sh)"
  qt hash

  # TODO: test for errors
  brew doctor

  # https://brew.sh/2018/01/19/homebrew-1.5.0/
  currentBrewVersion="$(brew --version | grep -E -o '[0-9]+\.[0-9]+')"

  if [[ "$(echo -e "$currentBrewVersion\\n1.4" | sort -t '.' -k 1,1 -k 2,2 -g | tail -1)" = '1.4' ]]; then
    errcho "In brew version 1.5 (http://bit.ly/2q9wcoI / http://bit.ly/2qcXiem) the php tap was merged into core."
    die "This script will not work with the older version" 127
  fi
fi

BREW_PREFIX="$(brew --prefix)"
export BREW_PREFIX

show_status "Ensure brew gcc is installed"
qt brew list gcc || brew install gcc

[[ ! -d "$BREW_PREFIX/etc" ]] && mkdir -p "$BREW_PREFIX/etc"
if [[ ! -d "$BREW_PREFIX/etc/.git" ]]; then
  show_status "Git init-ing $BREW_PREFIX/etc"

  etc_git_commit "git init"
  etc_git_commit "git add ." "Initial commit"
fi

show_status "brew tap"
process "brew tap"

# -- START SPECIAL CONFIGS FOR LINUXBREW PHP ----------------------------------
# TODO: determine if this is necessary for Arch Linux flavors
if [[ $OSTYPE == linux-gnu* ]] && [[ "$pkg_manager" = "apt-get" ]]; then
  #   https://gist.github.com/ElliottLandsborough/b960736a071fb79d8a45532315c6170b
  qt brew list libxml2 || brew install libxml2
  qt brew list libxslt || brew install libxslt

  # 'brew install php' config complained about these not being in path. Quick+dirty workaround hack
  for i in xml2-config xslt-config; do
    [[ ! -e "/usr/bin/$i" ]] && sudo ln -nfs "$BREW_PREFIX/bin/$i" /usr/bin/
  done

  qt pushd /usr/lib/x86_64-linux-gnu/
  for i in libldap* liblber*; do
    [[ ! -e "/usr/lib/$i" ]] && sudo ln -nfs "/usr/lib/x86_64-linux-gnu/$i" /usr/lib/
  done
  qt popd
  #   The "[remove line with "--with-ndbm"]" step is done in process()
fi
# -- END SPECIAL CONFIGS FOR LINUXBREW PHP ------------------------------------

show_status "brew php"
process "brew php"

show_status "brew leaves"
process "brew leaves"
# -- UPDATE AND INSTALL GEMS --------------------------------------------------
echo "== Processing Gem =="

if ! qt command -v ruby; then
  # https://github.com/rbenv/rbenv
  [[ ! -d "$HOME/.rbenv" ]] && git clone https://github.com/rbenv/rbenv.git "$HOME/.rbenv"
  export PATH="$PATH:$HOME/.rbenv/bin"
  qt hash
  eval "$(rbenv init -)"

  # https://github.com/rbenv/ruby-build#readme
  #   As an rbenv plugin
  [[ ! -d "$(rbenv root)"/plugins ]] && mkdir -p "$(rbenv root)"/plugins
  [[ ! -d "$(rbenv root)"/plugins/ruby-build ]] && git clone https://github.com/rbenv/ruby-build.git "$(rbenv root)"/plugins/ruby-build
  if ! qt command -v ruby; then
    # Latest stable version
    rbenv install 2.5.1
    rbenv global 2.5.1
    qt hash
  fi
fi

show_status "gem"
process "gem"
# -- INSTALL NPM PACKAGES -----------------------------------------------------
echo "== Processing Npm =="

if ! qt command -v node; then
  # https://github.com/mklement0/n-install
  curl -L https://git.io/n-install | bash -s -- -y
  export PATH="$HOME/n/bin:$PATH"
  n lts
fi

show_status "npm"
process "npm"
# -- DISABLE OUTGOING MAIL ----------------------------------------------------
echo "== Processing Postfix =="

if [[ "$pkg_manager" = "apt-get" ]]; then
  if ! qte apt list --installed | sed 's;/.*$;;' | qt grep postfix; then
    sudo debconf-set-selections <<< "postfix postfix/mailname string $(hostname)"
    sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    sudo apt-get install -y bsd-mailx postfix
  fi
elif [[ "$pkg_manager" = "pacman" ]]; then
  if !  qte pacman -Qn | sed 's/ .*$//' | qt grep postfix; then
    sudo pacman -S --noconfirm postfix
  fi
fi

if ! qt grep '^virtual_alias_maps' /etc/postfix/main.cf; then
  show_status "Disabling outgoing mail"
  cat <<EOT | qt sudo tee -a /etc/postfix/main.cf

virtual_alias_maps = regexp:/etc/postfix/virtual
EOT
fi

if ! qt grep "$USER" /etc/postfix/virtual; then
  cat <<EOT | qt sudo tee -a /etc/postfix/virtual

/.*/ $USER@localhost
EOT
fi

qt pushd /etc/
if sudo git status | qt grep -E 'postfix/main.cf|postfix/virtual'; then
  sudo etckeeper commit -m "[Slipstream] Disable outgoing mail (postfix tweaks)"
fi
qt popd
# -- INSTALL MARIADB (MYSQL) --------------------------------------------------
echo "== Processing MariaDB =="

# TODO: figure out how to start automatically
[[ ! -d "$BREW_PREFIX/etc/my.cnf.d" ]] && sudo mkdir -p "$BREW_PREFIX/etc/my.cnf.d"
if [[ ! -f "$BREW_PREFIX/etc/my.cnf.d/mysqld_innodb.cnf" ]]; then
  show_status "Creating: $BREW_PREFIX/etc/my.cnf.d/mysqld_innodb.cnf"
  cat <<EOT > "$BREW_PREFIX/etc/my.cnf.d/mysqld_innodb.cnf"
[mysqld]
innodb_file_per_table = 1
socket = /tmp/mysql.sock

query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 2M
max_allowed_packet = 64M

default_storage_engine = InnoDB
innodb_flush_method=O_DIRECT
innodb_buffer_pool_size = 512M
innodb_log_buffer_size = 16M
innodb_flush_log_at_trx_commit = 0
# Deprecated: innodb_locks_unsafe_for_binlog = 1
innodb_log_file_size = 256M

tmp_table_size = 32M
max_heap_table_size = 32M
thread_cache_size = 4
query_cache_limit = 2M
join_buffer_size = 8M
bind-address = 127.0.0.1
key_buffer_size = 256M
EOT
fi

# Start MariaDB
if ! qt mysql.server status; then
  (qt mysql.server start &)
  show_status 'Setting mysql root password... waiting for mysqld to start'
  # Just sleep, waiting for mariadb to start
  sleep 7
  mysql -u root mysql <<< "SET SQL_SAFE_UPDATES = 0; UPDATE user SET password=PASSWORD('root') WHERE User='root'; FLUSH PRIVILEGES; SET SQL_SAFE_UPDATES = 1;"
fi
# -- SETUP APACHE -------------------------------------------------------------
echo "== Processing Apache =="

HTTPD_CONF="$BREW_PREFIX/etc/httpd/httpd.conf"

show_status 'Updating httpd.conf settings'
for i in \
  'LoadModule socache_shmcb_module ' \
  'LoadModule ssl_module ' \
  'LoadModule cgi_module ' \
  'LoadModule vhost_alias_module ' \
  'LoadModule actions_module ' \
  'LoadModule rewrite_module ' \
  'LoadModule proxy_fcgi_module ' \
  'LoadModule proxy_module ' \
; do
  sed -i.bak "s;#.*${i}\\(.*\\);${i}\\1;" "$HTTPD_CONF"
done

sed -i.bak "s;^Listen 80.*$;Listen 80;"     "$HTTPD_CONF"
sed -i.bak "s;^User .*$;User $USER;"        "$HTTPD_CONF"
sed -i.bak "s;^Group .*$;Group $(id -gn);"  "$HTTPD_CONF"

DEST_DIR="/Users/$USER/Sites"

[[ ! -d "$DEST_DIR" ]] && mkdir -p "$DEST_DIR"

if [[ ! -d "$BREW_PREFIX/etc/httpd/ssl" ]]; then
  mkdir -p "$$/ssl"
  qt pushd "$$/ssl"
  genssl
  qt popd
  mv "$$/ssl" "$BREW_PREFIX/etc/httpd"
  rmdir "$$"

  etc_git_commit "git add httpd/ssl" "Add httpd/ssl files"
fi

# Set a default value, if not set as an env
PHP_FPM_PORT="${PHP_FPM_PORT:-9009}"

# We'd use these if we want to use localhost:some_port, but the default port is 9000
PHP_FPM_LISTEN="localhost:${PHP_FPM_PORT}"
PHP_FPM_HANDLER="fcgi://${PHP_FPM_LISTEN}"
PHP_FPM_PROXY="fcgi://${PHP_FPM_LISTEN}"

# Since port 9000 is also the default port for xdebug, so lets use...
PHP_FPM_LISTEN="$BREW_PREFIX/var/run/php-fpm.sock"
PHP_FPM_HANDLER="proxy:unix:$PHP_FPM_LISTEN|fcgi://localhost/"
PHP_FPM_PROXY="fcgi://localhost/"

[[ ! -d "$BREW_PREFIX/var/run" ]] && mkdir -p "$BREW_PREFIX/var/run"

if [[ ! -f "$BREW_PREFIX/etc/httpd/extra/localhost.conf" ]] || ! qt grep "$PHP_FPM_HANDLER" "$BREW_PREFIX/etc/httpd/extra/localhost.conf" || ! qt grep \\.localhost\\.metaltoad-sites\\.com "$BREW_PREFIX/etc/httpd/extra/localhost.conf" || ! qt grep \\.xip\\.io "$BREW_PREFIX/etc/httpd/extra/localhost.conf"; then
  cat <<EOT > "$BREW_PREFIX/etc/httpd/extra/localhost.conf"
<VirtualHost *:80>
  ServerAdmin $USER@localhost
  ServerAlias *.localhost *.vmlocalhost *.localhost.metaltoad-sites.com *.xip.io
  VirtualDocumentRoot $DEST_DIR/%1/webroot

  UseCanonicalName Off

  LogFormat "%V %h %l %u %t \"%r\" %s %b" vcommon
  CustomLog "/var/log/apache2/access_log" vcommon
  ErrorLog "/var/log/apache2/error_log"

  # With the switch to php-fpm, the apache2/other/php5.conf is not "Include"-ed, so need to...
  AddType application/x-httpd-php .php
  AddType application/x-httpd-php-source .phps

  <IfModule dir_module>
    DirectoryIndex index.html index.php
  </IfModule>

  # Depends on: 'LoadModule proxy_fcgi_module lib/httpd/modules/mod_proxy_fcgi.so' in $HTTPD_CONF
  #   http://serverfault.com/a/672969
  #   https://httpd.apache.org/docs/2.4/mod/mod_proxy_fcgi.html
  # This is to forward all PHP to php-fpm.
  <FilesMatch \\.php$>
    SetHandler "${PHP_FPM_HANDLER}"
  </FilesMatch>

  <Proxy ${PHP_FPM_PROXY}>
    ProxySet connectiontimeout=5 timeout=1800
  </Proxy>

  <Directory "$DEST_DIR">
    AllowOverride All
    Options +Indexes +FollowSymLinks +ExecCGI
    Require all granted
    RewriteBase /
  </Directory>
</VirtualHost>

Listen 443
<VirtualHost *:443>
  ServerAdmin $USER@localhost
  ServerAlias *.localhost *.vmlocalhost *.localhost.metaltoad-sites.com
  VirtualDocumentRoot $DEST_DIR/%1/webroot

  SSLEngine On
  SSLCertificateFile    $BREW_PREFIX/etc/httpd/ssl/server.crt
  SSLCertificateKeyFile $BREW_PREFIX/etc/httpd/ssl/server.key

  UseCanonicalName Off

  LogFormat "%V %h %l %u %t \"%r\" %s %b" vcommon
  CustomLog "/var/log/apache2/access_log" vcommon
  ErrorLog "/var/log/apache2/error_log"

  # With the switch to php-fpm, the apache2/other/php5.conf is not "Include"-ed, so need to...
  AddType application/x-httpd-php .php
  AddType application/x-httpd-php-source .phps

  <IfModule dir_module>
    DirectoryIndex index.html index.php
  </IfModule>

  # Depends on: 'LoadModule proxy_fcgi_module lib/httpd/modules/mod_proxy_fcgi.so' in $HTTPD_CONF
  #   http://serverfault.com/a/672969
  #   https://httpd.apache.org/docs/2.4/mod/mod_proxy_fcgi.html
  # This is to forward all PHP to php-fpm.
  <FilesMatch \\.php$>
    SetHandler "${PHP_FPM_HANDLER}"
  </FilesMatch>

  <Proxy ${PHP_FPM_PROXY}>
    ProxySet connectiontimeout=5 timeout=240
  </Proxy>

  <Directory "$DEST_DIR">
    AllowOverride All
    Options +Indexes +FollowSymLinks +ExecCGI
    Require all granted
    RewriteBase /
  </Directory>
</VirtualHost>
EOT

  if ! qt grep '^# Local vhost and ssl, for \*.localhost$' "$HTTPD_CONF"; then
    cat <<EOT >> "$HTTPD_CONF"

# Local vhost and ssl, for *.localhost
Include $BREW_PREFIX/etc/httpd/extra/localhost.conf
EOT
  fi

  etc_git_commit "git add httpd/extra/localhost.conf" "Add httpd/extra/localhost.conf"
else
  if qt grep ' ProxySet connectiontimeout=5 timeout=240$' "$BREW_PREFIX/etc/httpd/extra/localhost.conf"; then
    sed -i.bak 's/ ProxySet connectiontimeout=5 timeout=240/ ProxySet connectiontimeout=5 timeout=1800/' "$BREW_PREFIX/etc/httpd/extra/localhost.conf"
    rm "$BREW_PREFIX/etc/httpd/extra/localhost.conf.bak"

    etc_git_commit "git add httpd/extra/localhost.conf" "Update httpd/extra/localhost.conf ProxySet timeout value to 1800"
  fi
fi

if ! qt grep '^# To avoid: Gateway Timeout, during xdebug session (analogous changes made to the php.ini files)$' "$HTTPD_CONF"; then
  cat <<EOT >> "$HTTPD_CONF"

# To avoid: Gateway Timeout, during xdebug session (analogous changes made to the php.ini files)
Timeout 1800
EOT
fi

# Have ServerName match CN in SSL Cert
sed -i.bak 's/#ServerName www.example.com:80/ServerName 127.0.0.1/' "$HTTPD_CONF"
if qt diff "$HTTPD_CONF" "${HTTPD_CONF}.bak"; then
  echo "No change made to: apache2/httpd.conf"
else
  etc_git_commit "git add httpd/httpd.conf" "Update httpd/httpd.conf"
fi
rm "${HTTPD_CONF}.bak"
# TODO: automatically start apache
# -- WILDCARD DNS -------------------------------------------------------------
echo "== Processing Dnsmasq =="

conffile="/etc/NetworkManager/dnsmasq.d/10-slipstream.conf"
if [[ ! -f "$conffile" ]] || ! qt grep -E '^address=/.localhost/127.0.0.1$' "$conffile"; then
  show_status "Updating: $conffile"
  [[ ! -d "${conffile%/*}" ]] && sudo mkdir -p "${conffile%/*}"
  cat <<EOT | qt sudo tee -a "$conffile"
address=/.localhost/127.0.0.1
EOT

  sudo etckeeper commit -m "[Slipstream] Updating $conffile"
  qt sudo systemctl restart dnsmasq
fi

conffile="/etc/NetworkManager/NetworkManager.conf"
# TODO: should really test for "[main]" and "dns=dnsmasq"
if [[ ! -f "$conffile" ]] || ! qt grep -E -e '^dns=dnsmasq$' "$conffile"; then
  show_status "Updating: $conffile"
  [[ ! -d "${conffile%/*}" ]] && sudo mkdir -p "${conffile%/*}"
  cat <<EOT | qt sudo tee -a "$conffile"
[main]
dns=dnsmasq
EOT

  sudo etckeeper commit -m "[Slipstream] Updating $conffile"
  qt sudo systemctl restart dnsmasq
  qt sudo systemctl restart NetworkManager
fi

if ! qt grep -i dnsmasq /etc/hosts; then
  cat <<EOT | qt sudo tee -a /etc/hosts

# NOTE: dnsmasq is managing *.localhost domains (foo.localhost) so there's no need to add such here
# Use this hosts file for non-.localhost domains like: foo.bar.com
EOT

  sudo etckeeper commit -m "[Slipstream] Add dnsmasq note to hosts file"
fi
# -- SETUP BREW PHP / PHP.INI / XDEBUG ----------------------------------------
echo "== Processing Brew PHP / php.ini / Xdebug =="

for i in "$BREW_PREFIX/etc/php/"*/php.ini; do
  dir_path="${i%/*}"
  version="$(grep -E -o '[0-9]+\.[0-9]+' <<< "$i")"

  # Process php.ini for $version
  show_status "Updating some $i settings"
  sed -i.bak '
    s|max_execution_time = 30|max_execution_time = 0|
    s|max_input_time = 60|max_input_time = 1800|
    s|; *max_input_vars = 1000|max_input_vars = 10000|
    s|memory_limit = 128M|memory_limit = 256M|
    s|display_errors = Off|display_errors = On|
    s|display_startup_errors = Off|display_startup_errors = On|
    s|;error_log = php_errors.log|error_log = /var/log/apache2/php_errors.log|
    s|;date.timezone =|date.timezone = America/Los_Angeles|
    s|pdo_mysql.default_socket=.*|pdo_mysql.default_socket="/tmp/mysql.sock"|
    s|mysql.default_socket =.*|mysql.default_socket = "/tmp/mysql.sock"|
    s|mysqli.default_socket =.*|mysqli.default_socket = "/tmp/mysql.sock"|
    s|upload_max_filesize = 2M|upload_max_filesize = 100M|
  ' "$i"
  mv "${i}.bak" "${i}.${NOW}-post-process"
  show_status "Original saved to: ${i}.${NOW}-post-process"

  # Process ext-xdebug.ini
  if [[ -f "$dir_path/conf.d/ext-xdebug.ini" ]]; then
    show_status "Found old ext-xdebug.ini, backed up to: $dir_path/conf.d/ext-xdebug.ini"
    mv "$dir_path/conf.d/ext-xdebug.ini"{,-"$NOW"}
  fi
  show_status "Updating: $dir_path/conf.d/ext-xdebug.ini"
  cat <<EOT > "$dir_path/conf.d/ext-xdebug.ini"
[xdebug]
 xdebug.remote_enable=On
 xdebug.remote_host=127.0.0.1
 xdebug.remote_port=9000
 xdebug.remote_handler="dbgp"
 xdebug.remote_mode=req;

 xdebug.profiler_enable_trigger=1;
 xdebug.trace_enable_trigger=1;
 xdebug.trace_output_name = "trace.out.%t-%s.%u"
 xdebug.profiler_output_name = "cachegrind.out.%t-%s.%u"
EOT

  # Process php-fpm.conf for $version
  #   This is the path for 7.x, and we need to check for it 1st, because it's easier this way
  if [[ -f "$BREW_PREFIX/etc/php/$version/php-fpm.d/www.conf" ]]; then
    php_fpm_conf="$BREW_PREFIX/etc/php/$version/php-fpm.d/www.conf"
  elif [[ -f "$BREW_PREFIX/etc/php/$version/php-fpm.conf" ]]; then
    php_fpm_conf="$BREW_PREFIX/etc/php/$version/php-fpm.conf"
  else
    php_fpm_conf=""
  fi

  if [[ ! -z "$php_fpm_conf" ]] && ! qt grep -E "^listen[[:space:]]*=[[:space:]]*$PHP_FPM_LISTEN" "$php_fpm_conf"; then
    show_status "Updating $php_fpm_conf"
    sed -i.bak "
      s|^listen[[:space:]]*=[[:space:]]*.*|listen = $PHP_FPM_LISTEN|
      s|[;]*listen.mode[[:space:]]*=[[:space:]]*.*|listen.mode = 0666|
      s|[;]*pm.max_children[[:space:]]*=[[:space:]]*.*|pm.max_children = 10|
      /^user[[:space:]]*=[[:space:]]*.*/ s|^|;|
      /^group[[:space:]]*=[[:space:]]*.*/ s|^|;|
    " "$php_fpm_conf"
    mv "${php_fpm_conf}.bak" "${php_fpm_conf}-${NOW}"
    show_status "Original saved to: ${php_fpm_conf}-${NOW}"
  fi
done

qte killall php-fpm

[[ ! -d "$BREW_PREFIX/var/log/" ]] && mkdir -p "$BREW_PREFIX/var/log/"

brew_php_linked="$(qte cd "$BREW_PREFIX/var/homebrew/linked" && qte ls -d php php@[57].[0-9]*)"
# Only link if brew php is not linked. If it is, we assume it was intentionally done
if [[ -z "$brew_php_linked" ]]; then
  brew link --overwrite --force php@5.6
fi

("$BREW_PREFIX/sbin/php-fpm" &)
[[ ! -d "/var/log/apache2/" ]] && { sudo mkdir "/var/log/apache2/"; sudo chown "$USER:$(id -ng)" "/var/log/apache2/"; }
sudo "$(brew --prefix)"/bin/apachectl -k restart
sleep 3
# -- SETUP ADMINER ------------------------------------------------------------
show_status 'Setting up adminer'
[[ -d   "$DEST_DIR/adminer/webroot" ]] && mkdir -p  "$DEST_DIR/adminer/webroot"
[[ ! -w "$DEST_DIR/adminer/webroot" ]] && chmod u+w "$DEST_DIR/adminer/webroot"
latest="$(curl -IkLs https://github.com/vrana/adminer/releases/latest | col -b | grep Location | grep -E -o '[^/]+$')"

if [[ -e "$DEST_DIR/adminer/webroot/index.php" ]]; then
  if [[ "$(grep '\* @version' "$DEST_DIR/adminer/webroot/index.php" | grep -E -o '[0-9]+.*')" != "${latest/v/}" ]]; then
    rm -f  "$DEST_DIR/adminer/webroot/index.php"
    show_status 'Updating adminer to latest version'
    curl -L -o "$DEST_DIR/adminer/webroot/index.php" "https://github.com/vrana/adminer/releases/download/$latest/adminer-${latest/v/}-en.php"
  fi
else
  rm -f  "$DEST_DIR/adminer/webroot/index.php" # could be dead symlink
  curl -L -o "$DEST_DIR/adminer/webroot/index.php" "https://github.com/vrana/adminer/releases/download/$latest/adminer-${latest/v/}-en.php"
fi
# -- SHOW THE USER CONFIRMATION PAGE ------------------------------------------
if [[ ! -d "$DEST_DIR/slipstream/webroot" ]]; then
  mkdir -p "$DEST_DIR/slipstream/webroot"
fi

cat <<EOT > "$DEST_DIR/slipstream/webroot/index.php"
<div style="width: 600px; margin-bottom: 16px; margin-left: auto; margin-right: auto;">
  <h4>If you're seeing this, then it's a good sign that everything's working</h4>
<?php
  if( ! empty(\$_SERVER['HTTPS']) && strtolower(\$_SERVER['HTTPS']) !== 'off') {
    \$prefix = 'non-';
    \$url = "http://{\$_SERVER['HTTP_HOST']}/";
  } else {
    \$prefix = '';
    \$url = "https://{\$_SERVER['HTTP_HOST']}/";
  }
  print '<p>[test ' . \$prefix . 'SSL: <a href="' . \$url . '">' . \$url . '</a>]</p>';
?>

<p>
  Your ~/Sites folder will now automatically serve websites from folders that
  contain a "webroot" folder/symlink, using the .localhost TLD. This means that there
  is no need to edit the /etc/hosts file for *.localhost domains. For example, if you:
</p>
<pre>
  cd ~/Sites
  git clone git@github.com:username/your-website.git
</pre>
<p>
  the website will be served at:
  <ul>
    <li>http://your-website.localhost/ and</li>
    <li>http://your-site.localhost.metaltoad-sites.com/</li>
  </ul>
  automatically.
</p>
<p>
  Because of the way the apache vhost file VirtualDocumentRoot is configured,
  git clones that contain a "." will fail.
</p>
<p>
  Note that the mysql (MariaDB) root password is: root. You can confirm it by running:
</p>
<pre>
  mysql -p -u root mysql
</pre>

<p>
  You can now access Adminer at: <a href="http://adminer.localhost/">http://adminer.localhost/</a>
  using the same mysql credentials.
  Optionally, you can download a
  <a href="https://www.adminer.org/#extras" target="_blank">custom theme</a> adminer.css
  to "$DEST_DIR/adminer/webroot/adminer.css"
</p>

<h4>These are the packages were installed</h4>
<p>
  <strong>Brew:</strong>
  $(clean <(get_pkgs "brew php")) $(clean <(get_pkgs "brew leaves"))
</p>

<p>
  <strong>Gems:</strong>
  $(clean <(get_pkgs "gem"))
</p>

<p>
  <strong>NPM:</strong>
  $(clean <(get_pkgs "npm"))
</p>
</div>

<?php
  phpinfo();
?>
EOT

qt xdg-open http://slipstream.localhost/
# -----------------------------------------------------------------------------
# We're done! Now,...
# clean_up (called automatically, since we're trap-ing EXIT signal)

# This is necessary to allow for the .data section(s)
exit

# -- LIST OF PACKAGES TO INSTALL ----------------------------------------------
# .data
# -----------------------------------------------------------------------------
# Start: apt-get
build-essential
curl
default-jdk
git
sshuttle
# For linuxbrew php
libbz2-dev
libedit-dev
libldap2-dev
libldap2-dev
libsasl2-dev
systemtap-sdt-dev
zlib1g-dev
# End: apt-get
# -----------------------------------------------------------------------------
# Start: yum
dnsmasq
java-1.8.0-openjdk
sshuttle
# End: yum
# -----------------------------------------------------------------------------
# Start: pacman
dnsmasq
dnsutils
git
jdk9-openjdk
sshuttle
# For linuxbrew php
libmemcached
# End: pacman
# -----------------------------------------------------------------------------
# Start: brew tap
# End: brew tap
# -----------------------------------------------------------------------------
# Start: brew php
# Php 7.2 dropped mcrypt support. Previous versions now have it built in: php -m | grep mcrypt
httpd
php
php@5.6
php@7.0
php@7.1
# End: brew php
# -----------------------------------------------------------------------------
# Start: pecl
# some_module:php@5.6-1.2.3:php@7.1-2.3.4
#   if      php@5.6 then use some_module-1.2.3
#   else if php@7.1 then use some_module-2.3.4
#   else use current version of some_module
#   end if
igbinary
imagick
memcached:php@5.6-2.2.0
xdebug:php@5.6-2.5.5
# End: pecl
# -----------------------------------------------------------------------------
# Start: brew leaves
# Development Envs
# Database
mariadb
# Network
# Shell
bash-completion
bash-git-prompt
# Utilities
apachetop
composer
php-cs-fixer
pngcrush
the_silver_searcher
wp-cli
# End: brew leaves
# -----------------------------------------------------------------------------
# Start: gem
bundler
compass
capistrano -v 2.15.5
# End: gem
# -----------------------------------------------------------------------------
# Start: npm
csslint
fixmyjs
grunt-cli
js-beautify
jshint
# End: npm
# -----------------------------------------------------------------------------
