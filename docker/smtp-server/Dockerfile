# =============================================================================
# SMTP Server Container - Email Testing
# =============================================================================
# This container provides an SMTP server for testing email-related
# security tools including credential validation and relay testing.
#
# Features:
# - SMTP AUTH support
# - Multiple authentication mechanisms
# - Weak default credentials
# - Open relay configuration (for testing)
#
# WARNING: This container is intentionally insecure.
# =============================================================================

FROM alpine:3.18

LABEL maintainer="CPTC11 Team"
LABEL description="SMTP server for email security testing"
LABEL cptc11.role="smtp-server"

# Install Postfix and related packages
RUN apk add --no-cache \
    postfix \
    postfix-pcre \
    cyrus-sasl \
    cyrus-sasl-plain \
    cyrus-sasl-login \
    dovecot \
    openssl \
    supervisor \
    && rm -rf /var/cache/apk/*

# Create mail users
RUN adduser -D -h /home/smtpuser -s /sbin/nologin smtpuser \
    && echo "smtpuser:smtppass123" | chpasswd \
    && adduser -D -h /home/mailuser -s /sbin/nologin mailuser \
    && echo "mailuser:mailpass456" | chpasswd \
    && adduser -D -h /home/admin -s /sbin/nologin admin \
    && echo "admin:admin123" | chpasswd

# Create mail directories
RUN mkdir -p /var/mail \
    && mkdir -p /var/spool/postfix \
    && mkdir -p /etc/postfix/sasl

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/mail.key \
    -out /etc/ssl/certs/mail.crt \
    -subj "/C=US/ST=Test/L=Test/O=CPTC11/CN=mail.testlab.local"

# Copy configuration files
COPY postfix/main.cf /etc/postfix/main.cf
COPY postfix/master.cf /etc/postfix/master.cf
COPY sasl/smtpd.conf /etc/postfix/sasl/smtpd.conf
COPY supervisord.conf /etc/supervisord.conf

# Set up SASL
RUN mkdir -p /var/run/saslauthd \
    && chown root:root /var/run/saslauthd

# Initialize postfix
RUN postfix set-permissions \
    && newaliases || true

EXPOSE 25 587

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 25 || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
