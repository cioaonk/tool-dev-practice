# =============================================================================
# Vulnerable Web Application Container
# =============================================================================
# This container provides an intentionally vulnerable web application
# for testing web security tools including:
# - Web directory enumeration
# - Credential validation (HTTP Basic/Form auth)
# - SQL injection points
# - File upload vulnerabilities
#
# WARNING: This container is intentionally insecure. Do not expose to
# untrusted networks.
# =============================================================================

FROM php:8.1-apache

LABEL maintainer="CPTC11 Team"
LABEL description="Vulnerable web application for security testing"
LABEL cptc11.role="vulnerable-web"

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install gd mysqli pdo pdo_mysql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers ssl

# Create SSL certificate (self-signed for testing)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/apache-selfsigned.key \
    -out /etc/ssl/certs/apache-selfsigned.crt \
    -subj "/C=US/ST=Test/L=Test/O=CPTC11/CN=vulnerable-web.testlab.local"

# Configure Apache
COPY apache/default.conf /etc/apache2/sites-available/000-default.conf
COPY apache/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
RUN a2ensite default-ssl

# Create vulnerable web application structure
RUN mkdir -p /var/www/html/admin \
    /var/www/html/api \
    /var/www/html/uploads \
    /var/www/html/backup \
    /var/www/html/config \
    /var/www/html/.git \
    /var/www/html/private

# Copy application files
COPY www/ /var/www/html/

# Set intentionally weak permissions (for testing)
RUN chmod -R 755 /var/www/html \
    && chmod -R 777 /var/www/html/uploads

# Create .htpasswd for basic auth testing
RUN htpasswd -cb /etc/apache2/.htpasswd admin admin123 \
    && htpasswd -b /etc/apache2/.htpasswd testuser testpass

# Expose HTTP and HTTPS
EXPOSE 80 443

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

CMD ["apache2-foreground"]
