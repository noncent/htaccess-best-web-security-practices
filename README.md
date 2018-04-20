# htaccess-best-web-security-practices
Hi Folks, This is the htaccess settings to use within your application. No one can assure you that any Settings could make an Application 100% Safe. But we can make it much.. much.. much tedious &amp; hard to break.... :) So let them work...

```sh
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
#    PROD- HTACCESS: APACHE Config - By Neeraj Singh <neeraj.singh@digitaslbi.com>
#
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


#  ____       _   _                           _        ____       _   _              ____                       _ _
# | __ )  ___| |_| |_ ___ _ __  __      _____| |__    | __ )  ___| |_| |_ ___ _ __  / ___|  ___  ___ _   _ _ __(_) |_ _   _
# |  _ \ / _ \ __| __/ _ \ '__| \ \ /\ / / _ \ '_ \   |  _ \ / _ \ __| __/ _ \ '__| \___ \ / _ \/ __| | | | '__| | __| | | |
# | |_) |  __/ |_| ||  __/ |     \ V  V /  __/ |_) |  | |_) |  __/ |_| ||  __/ |     ___) |  __/ (__| |_| | |  | | |_| |_| |
# |____/ \___|\__|\__\___|_|      \_/\_/ \___|_.__( ) |____/ \___|\__|\__\___|_|    |____/ \___|\___|\__,_|_|  |_|\__|\__, |
#                                                 |/                                                                  |___/
#           |___/


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# TO ENABLE DEFLATE COMPRESSION ENABLE *filter_module
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_deflate.c>
<FilesMatch "\.(html|php|txt|xml|js|css)$">
SetOutputFilter DEFLATE
</FilesMatch>
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# ENABLE GZIP? ENABLE *filter_module
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_deflate.c>
  # Compress HTML, CSS, JavaScript, Text, XML and fonts
  AddOutputFilterByType DEFLATE application/javascript
  AddOutputFilterByType DEFLATE application/rss+xml
  AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
  AddOutputFilterByType DEFLATE application/x-font
  AddOutputFilterByType DEFLATE application/x-font-opentype
  AddOutputFilterByType DEFLATE application/x-font-otf
  AddOutputFilterByType DEFLATE application/x-font-truetype
  AddOutputFilterByType DEFLATE application/x-font-ttf
  AddOutputFilterByType DEFLATE application/x-javascript
  AddOutputFilterByType DEFLATE application/xhtml+xml
  AddOutputFilterByType DEFLATE application/xml
  AddOutputFilterByType DEFLATE font/opentype
  AddOutputFilterByType DEFLATE font/otf
  AddOutputFilterByType DEFLATE font/ttf
  AddOutputFilterByType DEFLATE image/svg+xml
  AddOutputFilterByType DEFLATE image/x-icon
  AddOutputFilterByType DEFLATE text/css
  AddOutputFilterByType DEFLATE text/html
  AddOutputFilterByType DEFLATE text/javascript
  AddOutputFilterByType DEFLATE text/plain
  AddOutputFilterByType DEFLATE text/xml

  # Remove browser bugs (only needed for really old browsers)
  BrowserMatch ^Mozilla/4 gzip-only-text/html
  BrowserMatch ^Mozilla/4\.0[678] no-gzip
  BrowserMatch \bMSIE !no-gzip !gzip-only-text/html
  Header append Vary User-Agent
</IfModule>

# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# EXPIREATION SETTINGS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_headers.c>
<FilesMatch "\.(?i:gif|jpe?g|png|ico|css|js|swf|css|js|ico|pdf|jpg|jpeg|png|gif|html|htm|xml|txt|xsl|svg|ttf|otf)$">
    Header set Cache-Control "max-age=2592000, public"
</FilesMatch>
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# LEVERAGE BROWSER CACHING
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpg "access 1 year"
  ExpiresByType image/jpeg "access 1 year"
  ExpiresByType image/gif "access 1 year"
  ExpiresByType image/png "access 1 year"
  ExpiresByType text/css "access 1 month"
  ExpiresByType text/html "access 1 month"
  ExpiresByType application/javascript "access plus 1 year"
  ExpiresByType application/pdf "access 1 month"
  ExpiresByType text/x-javascript "access 1 month"
  ExpiresByType application/x-shockwave-flash "access 1 month"
  ExpiresByType image/x-icon "access plus 1 year"
  ExpiresDefault "access 1 month"
</IfModule>

<IfModule mod_headers.c>
  <filesmatch "\.(ico|flv|jpg|jpeg|png|gif|css|swf)$">
  Header set Cache-Control "max-age=2678400, public"
  </filesmatch>
  <filesmatch "\.(html|htm)$">
  Header set Cache-Control "max-age=7200, private, must-revalidate"
  </filesmatch>
  <filesmatch "\.(pdf)$">
  Header set Cache-Control "max-age=86400, public"
  </filesmatch>
  <filesmatch "\.(js)$">
  Header set Cache-Control "max-age=2678400, private"
  </filesmatch>
</IfModule>

<ifmodule mod_expires.c>
<Filesmatch "\.(jpg|jpeg|png|gif|js|css|swf|ico|woff|mp3)$">
    ExpiresActive on
    ExpiresDefault "access plus 1 month"
</Filesmatch>
</ifmodule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# SET THE DEFAULT LANGUAGE # SET THE DEFAULT CHARACTER SET
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

DefaultLanguage en-US
AddDefaultCharset UTF-8


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# INDEX FILE CAN BE INDEX.PHP, HOME.PHP, DEFAULT.PHP ETC.
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

DirectoryIndex index.php index.html


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# SET YOUR DEVELOPMENT ENVIRONMENT
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

SetEnv CI_ENV production
SetEnv CI_COMPRESS on


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# REWRITE ENGINE
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

RewriteEngine On


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# DISABLE UNAUTHORIZED DIRECTORY BROWSING | DISABLE THE SERVER SIGNATURE
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

ServerSignature Off
Options -Indexes


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# CODEIGNITER SETTINGS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.php/$0 [PT,L]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# .HTACCESS - REWRITECOND: BAD FLAG DELIMITERS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#css rule
# Block out any script that includes a <script> tag in URL.
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
# Block out use of illegal or unsafe characters in the HTTP Request
RewriteCond %{THE_REQUEST} ^.*(\\r|\\n|%0A|%0D).* [NC,OR]
# Block out use of illegal or unsafe characters in the Referer Variable of the HTTP Request
RewriteCond %{HTTP_REFERER} ^(.*)(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]
# Block out use of illegal or unsafe characters in any cookie associated with the HTTP Request
RewriteCond %{HTTP_COOKIE} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]
# Block out use of illegal characters in URI or use of malformed URI
RewriteCond %{REQUEST_URI} ^/(,|;|:|<|>|">|"<|/|\\\.\.\\).{0,9999}.* [NC,OR]
# Block out  use of illegal or unsafe characters in the Query String variable
RewriteCond %{QUERY_STRING} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC]

# Return 403 Forbidden header and show the content of the root homepage
RewriteRule .* index.php [F]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# REDIRECT HTTP TRAFFIC TO HTTPS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Normal Server
# - RewriteCond %{HTTPS} off
# - RewriteRule (.*) https://%{SERVER_NAME}%{REQUEST_URI} [R,L]

# Load Balancing Server
RewriteEngine On
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# NON WWW TO WWW REDIRECTION
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#RewriteCond %{SERVER_NAME}/ !^www\.
#RewriteRule ^(.*)$ http://www.%{HTTP_HOST}/$1 [R=301,L]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# HTACCESS REMOVE QUERY STRING
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#RewriteCond %{QUERY_STRING} .
#RewriteRule ^$ /? [R,L]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# PHP ERROR HANDLING FOR DEVELOPMENT SERVERS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule php5_module>
  php_flag display_startup_errors off
  php_flag display_errors off
  php_flag html_errors off
  php_flag log_errors off
  php_flag ignore_repeated_errors off
  php_flag ignore_repeated_source off
  php_flag report_memleaks off
  php_flag track_errors off
  php_flag docref_root 0
  php_flag docref_ext 0
  php_flag error_reporting 0
  php_flag log_errors_max_len 0
  </IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# RE_WRITE SETTINGS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# DELETE FILE EXTENSIONS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^([^\.]+)$ $1.php [NC,L]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# ONLY ALLOW GET & POST REQUEST
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<LimitExcept GET POST>
  Order Allow,Deny
  Deny from all
</LimitExcept>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# BLOCK ACCESS TO LOG FILE
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<files Site_Error.php>
Order allow,deny
Deny from all
</files>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# DENY ACCESS TO MULTIPLE FILES IN HTACCESS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<FilesMatch "(Site_Error|log|error)\.php$">
Deny from all
</FilesMatch>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# BLOCK ACCESS TO MULTIPLE FILE TYPES
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<FilesMatch "\.(sql|bat|htaccess|htpasswd|ini|psd|log|sh|error|error|error|info|php_info|info_php|bkp|backup|src|exe|dll|src|msi|\.[hH][tT])$">
Order allow,deny
Deny from all
</FilesMatch>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# DISABLE ETAGS:
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

FileETag None


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Protect against page-framing and click-jacking
# BLOCK IFRAME CALL
# ENABLE APACHE SETTING,
# LOADMODULE HEADERS_MODULE MODULES/MOD_HEADERS.SO
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_headers.c>
  Header always append X-Frame-Options SAMEORIGIN
  Header set X-Frame-Options "SAMEORIGIN"
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Protect against content-sniffing
# SECURITY HEADERS - X-CONTENT-TYPE: NOSNIFF
# ENABLE APACHE SETTING, PREVENT MIME BASED ATTACKS
# LOADMODULE HEADERS_MODULE MODULES/MOD_HEADERS.SO
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_headers.c>
  Header set X-Content-Type-Options "nosniff"
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Protect against XSS attacks
# HTTP HEADER X-XSS-PROTECTION
# ENABLE APACHE SETTING,
# LOADMODULE HEADERS_MODULE MODULES/MOD_HEADERS.SO
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule mod_headers.c>
    Header set X-XSS-Protection: "1; mode=block"
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# SESSION COOKIES HTTP & SECURE FLAG
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule php5_module>
    php_flag session.cookie_httponly on
    php_flag session.cookie_secure on
</IfModule>


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Avoid HTTP method
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK|OPTIONS)
RewriteRule ^ - [F]


# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# FORM POST AND UPLOAD SETTINGS
# =-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<IfModule php5_module>
  php_flag upload_max_filesize 128M
  php_flag post_max_size 128M
  php_flag max_input_time 3600
  php_flag max_execution_time 3600
  php_flag default_socket_timeout 6000
  php_flag set_time_limit 0
</IfModule>

#  +++++++++++++++++++++++++++++++++++ END HTACCESS SCRIPT ++++++++++++++++++++++++++++++++++++++++++
```
