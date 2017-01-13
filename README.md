# htaccess-best-web-security
Apace Web Application .htaccess code to secure your web site


Here is some .htaccess code to just put in your server root folder. You can # Comment the unwanted code and use it :)

```sh
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #
# - HTACCESS code for a Secure Web Application | Neeraj Singh | 13-Jan-2017
# <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><> #

# +-------------------------------------------------------------------------+
# DISABLE UNAUTHORIZED DIRECTORY BROWSING
# +-------------------------------------------------------------------------+

# Prevent a Directory Listing of Your Website with .htaccess
# Block a Directory Index from Being Shown

Options -Indexes


# +-------------------------------------------------------------------------+
# DISABLE THE SERVER SIGNATURE
# +-------------------------------------------------------------------------+

# For a server running Apache web server in a production environment, 
# it is advisable to disable Server Signatures. These signatures displayed 
# on error pages, and in other communications with the web server, 
# may reveal sensitive information about the software versions running on the web server.

ServerSignature Off


# +-------------------------------------------------------------------------+
# SET YOUR DEVELOPMENT ENVIRONMENT
# +-------------------------------------------------------------------------+

# SetEnv, used in Apache's configuration (be it a .htaccess file, 
# or a VirtualHost), defines an environment variable.

SetEnv APPLICATION_ENV production


# +-------------------------------------------------------------------------+
# DISABLE ETAGS:
# +-------------------------------------------------------------------------+

# First off let’s try to understand what ETAGs actually are. If you have ETAGs turned on for 
# your site then each asset sent from your server to a client is sent with an ETAG in 
# it’s header. For Apache this key is constructed from the files inode, size and last modified datetime.
# So what does the client actually do with an ETAG for a particular asset? 
# If the client has the asset cached then the expire header of the asset is checked first to see 
# if the server needs to be contacted at all. If the asset has not expired then the ETAG has no effect at all, 
# the locally cached version will be used. If the asset has indeed expired then the client will send a request 
# for the asset with the ETAG stored by the client to the server. The server performs a comparison between 
# the ETAG of the asset and the ETAG sent by the client, if the ETAGs match then the server will 
# return a 304 not modified header which instructs the browser to use it’s cached version of the asset. 
# If they do not match the server will return the asset.
# As you might have deduced, if any of the properties that make up an ETAG for the assets web server change then a different 
# ETAG will be generated which will force the users browser to re cache the file, this will only 
# happen however if the clients cached version of the asset has expired though as noted above. 
# So ETAGs will not magically force clients to re cache assets when you make changes to them.
# 
# When ETAGs go bad
# 
# So far ETAGs certainly sound like a useful tool for assets caching. 
# Things aren’t so simple however due to an issue that arises when ETAGs are used in load balanced environments.
# As noted above for Apache (and for other web servers as well) an assets location on disk 
# is taken into account when generating an ETAG, this includes information about the actual server that the file is located on. 
# This means that in a load balanced environment each server will generate a different ETAG for the same file, 
# making ETAGs pretty useless in such circumstances. This is the issue that causes a lot of people to 
# disable ETAGs completely and opt for using cache control headers only for their assets.
# 
# There is a suggested solution for this, and that involves removing the inode part from ETAGs entirely 
# so they will be based on a files size and last modified time .
# 
# But, to increase page loading speed, my advice is YSlow. 
# perfect tool & Yslow recommends to use ETAGs instead of setting off.

Header unset Pragma
FileETAG None
Header unset ETAG 
FileETag MTime Size

<ifmodule mod_expires.c>
  <filesmatch "\.(jpg|gif|png|css|js)$">
       ExpiresActive on
       ExpiresDefault "access plus 1 year"
   </filesmatch>
</ifmodule>


# +-------------------------------------------------------------------------+
# SET THE DEFAULT LANGUAGE
# +-------------------------------------------------------------------------+

# DefaultLanguage is intended for set the default language when a directory contains multiple language files, 
# e.g.: index.html.en, index.html.fr. They need to be set with AddLanguage in Apache configuration somewhere:
# 
# AddLanguage en .en
# AddLanguage fr .fr
# 
# Files will these extensions will be delivered with the Content-Language HTTP header. 
# If no extension is provided, can be a coincidence to have both methods generating the 
# Content-Language header but if you want to explicitly set the document Content-Language may 
# run slightly faster with explicit header definition, as it does not need to check the
# file extension and fallback to a default language if set.

DefaultLanguage en-US


# +-------------------------------------------------------------------------+
# SET THE DEFAULT CHARACTER SET
# +-------------------------------------------------------------------------+

# Setting charset information in .htaccess
# it is important to ensure that any information about character encoding sent by the server 
# is correct, since information in the HTTP header overrides information in the document itself.
# AddCharset UTF-8 .html
# Many Apache servers are configured to send files using the ISO-8859-1 (Latin-1) encoding

AddDefaultCharset UTF-8


# +-------------------------------------------------------------------------+
# SET DEFAULT EXECUTED FILE
# +-------------------------------------------------------------------------+

# The directoryindex command allows you to specify a default page to display when a directory is accessed. 
# For instance, if a visitor requests a directory on your web site, you can specify the 
# file to load when the directory is accessed (if a filename is not specified in the initial request). 
# For example, to display a 'index.html' file rather than showing directory listings or to 
# load a 'index.php' file rather than an 'index.html' file.
# 
# To set-up a directoryindex, create a .htaccess file following the main instructions 
# and guidance which includes the following text:

DirectoryIndex index.php index.html


# +-------------------------------------------------------------------------+
# SET MODE RE-WRITE
# +-------------------------------------------------------------------------+

# The Apache module mod_rewrite allows you to rewrite URL requests that come into 
# your server and is based on a regular-expression parser

RewriteEngine On


# +-------------------------------------------------------------------------+
# REDIRECT HTTP TRAFFIC TO HTTPS
# +-------------------------------------------------------------------------+

# if server has https vars

RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{SERVER_NAME}%{REQUEST_URI} [R,L]

# if server dont have https vars, in case load balancing servers or proxy servers
# and you are getting redirect loop by above code

RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule .* https://%{HTTP_HOST}%{REQUEST_URI} [R=302,L]


# +-------------------------------------------------------------------------+
# ENSURE - WWW IN URL
# +-------------------------------------------------------------------------+

# re direct url on www if not exist

RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteRule ^ https://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]


# +-------------------------------------------------------------------------+
# REMOVE ALL QUERY STRING FROM URLS
# +-------------------------------------------------------------------------+

# remove all url query string fro url and clean them

RewriteCond %{QUERY_STRING} .
RewriteRule ^$ /? [R,L]


# +-------------------------------------------------------------------------+
# GET ALL REQUEST ON INDEX FILE
# +-------------------------------------------------------------------------+

# get all request on index file only

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.php/$0 [PT,L]


# +-------------------------------------------------------------------------+
# REWRITECOND: BAD FLAG DELIMITERS
# +-------------------------------------------------------------------------+

# block out any script that includes a <script> tag in url.
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]

# block out use of illegal or unsafe characters in the http request
RewriteCond %{THE_REQUEST} ^.*(\\r|\\n|%0A|%0D).* [NC,OR]

# block out use of illegal or unsafe characters in the referer variable of the http request
RewriteCond %{HTTP_REFERER} ^(.*)(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]

# block out use of illegal or unsafe characters in any cookie associated with the http request
RewriteCond %{HTTP_COOKIE} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]

# block out use of illegal characters in uri or use of malformed uri
RewriteCond %{REQUEST_URI} ^/(,|;|:|<|>|">|"<|/|\\\.\.\\).{0,9999}.* [NC,OR]

# block out  use of illegal or unsafe characters in the query string variable
RewriteCond %{QUERY_STRING} ^.*(<|>|'|"|%0A|%0D|%27|%3C|%3E|%00|%20).* [NC]

# return 403 forbidden header and show the content of the root homepage
RewriteRule .* index.php [F]


# +-------------------------------------------------------------------------+
# PHP ENVIRONMENT SETUP
# +-------------------------------------------------------------------------+

# PHP Server Setup and Application Settings

# PHP Flags
php_flag display_startup_errors on
php_flag display_errors on
php_flag html_errors on
php_flag log_errors on
php_flag ignore_repeated_errors on
php_flag ignore_repeated_source on
php_flag report_memleaks on
php_flag track_errors on

# PHP Values
php_value docref_root 0
php_value docref_ext 0
php_value error_log %{DOCUMENT_ROOT}/logs/full_stack_error.log
php_value error_reporting -1
php_value log_errors_max_len 0

# +-------------------------------------------------------------------------+
# FORM POST AND UPLOAD SETTINGS
# +-------------------------------------------------------------------------+
php_value upload_max_filesize 128M  
php_value post_max_size 128M  
php_value max_input_time 3600  
php_value max_execution_time 3600

# +-------------------------------------------------------------------------+
# SESSION COOKIES HTTP & SECURE FLAG
# +-------------------------------------------------------------------------+
php_flag session.cookie_httponly on
php_value session.cookie_secure on


# +-------------------------------------------------------------------------+
# DELETE FILE EXTENSIONS
# +-------------------------------------------------------------------------+
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^([^\.]+)$ $1.php [NC,L]


# +-------------------------------------------------------------------------+
# ONLY ALLOW GET & POST REQUEST
# +-------------------------------------------------------------------------+
<LimitExcept GET POST>
Order Allow,Deny
Deny from all
</LimitExcept>


# +-------------------------------------------------------------------------+
# BLOCK ACCESS TO LOG FILE
# +-------------------------------------------------------------------------+
<files site_error.php>
Order allow,deny
Deny from all
</files>


# +-------------------------------------------------------------------------+
# BLOCK ACCESS TO MULTIPLE FILE TYPES
# +-------------------------------------------------------------------------+
<FilesMatch "\.(sql|bat|htaccess|htpasswd|ini|psd|log|sh|error|error|error|info|php_info|info_php|bkp|backup|src|exe|dll|src|msi|\.[hH][tT])$">
Order allow,deny
Deny from all
</FilesMatch>


# +-------------------------------------------------------------------------+
# DENY ACCESS TO ONE SPECIFIC FOLDER
# +-------------------------------------------------------------------------+
Deny from all


# +-------------------------------------------------------------------------+
# EXPIREATION SETTINGS
# +-------------------------------------------------------------------------+
<FilesMatch "\.(?i:gif|jpe?g|png|ico|css|js|swf|css|js|ico|pdf|jpg|jpeg|png|gif|html|htm|xml|txt|xsl|svg|ttf|otf)$">
  <IfModule mod_headers.c>
    Header set Cache-Control "max-age=2592000, public"
  </IfModule>
</FilesMatch>


# +-------------------------------------------------------------------------+
# LEVERAGE BROWSER CACHING
# +-------------------------------------------------------------------------+
<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpg "access 1 year"
  ExpiresByType image/jpeg "access 1 year"
  ExpiresByType image/gif "access 1 year"
  ExpiresByType image/png "access 1 year"
  ExpiresByType text/css "access 1 month"
  ExpiresByType text/html "access 1 month"
  ExpiresByType application/pdf "access 1 month"
  ExpiresByType text/x-javascript "access 1 month"
  ExpiresByType application/x-shockwave-flash "access 1 month"
  ExpiresByType image/x-icon "access 1 year"
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
    ExpiresDefault "access plus 2 days"
</Filesmatch>
</ifmodule>


# +-------------------------------------------------------------------------+
# HTTP Strict Transport Security (HSTS) header
# +-------------------------------------------------------------------------+

# HSTS is an acronym for HTTP Strict Transport Security
# It is a security enhancement which ensures only secure pages from your domain are shown by a browser
# Automatically redirects HTTP requests to HTTPS for the target domain
# Does not allow a user to override the invalid certificate message
# Enabled through the use of a special response header
# Can be preloaded via browsers by listing your domain

<IfModule mod_headers.c>   
Header set Strict-Transport-Security "max-age=10886400; includeSubDomains; preload" env=HTTPS
<FilesMatch "\.(css|gif|ico|jpeg|jpg|js|png|woff)$">
Header unset Strict-Transport-Security
</FilesMatch>
</IfModule>


# +-------------------------------------------------------------------------+
# BLOCK IFRAME CALL
# +-------------------------------------------------------------------------+

# The X-Frame-Options HTTP response header can be used to indicate whether or not a browser 
# should be allowed to render a page in a <frame> or <iframe>. This can be used to 
# avoid clickjacking attacks, by ensuring that your content is not embedded into other sites

<IfModule mod_headers.c>
Header set X-Frame-Options "SAMEORIGIN"
</IfModule>


# +-------------------------------------------------------------------------+
# SECURITY HEADERS - X-CONTENT-TYPE: NOSNIFF
# +-------------------------------------------------------------------------+
<IfModule mod_headers.c>
Header set X-Content-Type-Options "nosniff"
</IfModule>


# +-------------------------------------------------------------------------+
# HTTP HEADER X-XSS-PROTECTION
# +-------------------------------------------------------------------------+
<IfModule mod_headers.c>    
Header append X-XSS-Protection: "1; mode=block;"
</IfModule>


# +-------------------------------------------------------------------------+
# Avoid HTTP method
# +-------------------------------------------------------------------------+
RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK|OPTIONS)
RewriteRule ^ - [F]
```
