# =============================================================================
# DNS Server Container - Enumeration Testing
# =============================================================================
# This container provides a DNS server configured for testing DNS
# enumeration tools including subdomain discovery and zone transfers.
#
# Features:
# - Zone transfer enabled (AXFR)
# - Multiple DNS records for enumeration
# - Subdomain configuration
# - Intentionally discoverable internal hostnames
#
# WARNING: This container is intentionally insecure.
# =============================================================================

FROM alpine:3.18

LABEL maintainer="CPTC11 Team"
LABEL description="DNS server for enumeration testing"
LABEL cptc11.role="dns-server"

# Install BIND
RUN apk add --no-cache \
    bind \
    bind-tools \
    && rm -rf /var/cache/apk/*

# Create directories
RUN mkdir -p /etc/bind/zones \
    && mkdir -p /var/cache/bind \
    && mkdir -p /var/log/bind

# Copy configuration files
COPY config/named.conf /etc/bind/named.conf
COPY config/zones/ /etc/bind/zones/

# Set permissions
RUN chown -R named:named /etc/bind \
    && chown -R named:named /var/cache/bind \
    && chown -R named:named /var/log/bind

EXPOSE 53/udp 53/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nslookup testlab.local 127.0.0.1 || exit 1

CMD ["/usr/sbin/named", "-f", "-c", "/etc/bind/named.conf", "-u", "named"]
