# WHOIS / web-WHOIS fallback service built from the reg233/whois-domain-lookup
# git submodule (third_party/whois-domain-lookup), passed in as the named
# build context "upstream" (see docker-compose.yml).
#
# Upstream ships its PHP dependencies in vendor/, so no composer step is needed.
FROM php:8.4-apache

RUN a2enmod rewrite \
 && mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && sed -ri 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf \
 && sed -ri 's#CustomLog .*#CustomLog /dev/null combined#' /etc/apache2/sites-available/000-default.conf \
 && { echo 'max_execution_time = 90'; echo 'expose_php = Off'; } > "$PHP_INI_DIR/conf.d/pslmon.ini"

COPY --from=upstream --chown=www-data:www-data . /var/www/html/

# Fail the build early if the submodule was never checked out.
RUN test -f /var/www/html/src/index.php -a -f /var/www/html/vendor/autoload.php \
 || { echo >&2 "third_party/whois-domain-lookup is empty: run 'git submodule update --init'"; exit 1; } \
 && rm -rf /var/www/html/.git /var/www/html/api /var/www/html/.github

# Our client calls src/index.php directly, which works with or without the
# upstream .htaccess rewrites.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD php -r 'exit(str_contains((string)@file_get_contents("http://127.0.0.1/src/index.php?json=1"), "\"code\"") ? 0 : 1);'

EXPOSE 80
CMD ["apache2-foreground"]
