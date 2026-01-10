# =============================================================================
# FTP Server Container - Credential Testing
# =============================================================================
# This container provides an FTP server with intentionally weak configuration
# for testing FTP credential validation tools.
#
# Features:
# - Anonymous FTP access enabled
# - Weak default credentials
# - Multiple user accounts for testing
#
# WARNING: This container is intentionally insecure.
# =============================================================================

FROM alpine:3.18

LABEL maintainer="CPTC11 Team"
LABEL description="FTP server for credential testing"
LABEL cptc11.role="ftp-server"

# Install vsftpd
RUN apk add --no-cache \
    vsftpd \
    openssl \
    shadow \
    && rm -rf /var/cache/apk/*

# Create FTP users with weak passwords
RUN adduser -D -h /home/ftpuser ftpuser && echo "ftpuser:ftppass123" | chpasswd \
    && adduser -D -h /home/admin admin && echo "admin:admin123" | chpasswd \
    && adduser -D -h /home/backup backup && echo "backup:backup2024" | chpasswd \
    && adduser -D -h /home/anonymous anonymous && echo "anonymous:" | chpasswd

# Create FTP directories
RUN mkdir -p /var/ftp/pub \
    && mkdir -p /home/ftpuser/files \
    && mkdir -p /home/admin/private \
    && mkdir -p /home/backup/archives

# Create test files
RUN echo "Welcome to the FTP server" > /var/ftp/pub/welcome.txt \
    && echo "Confidential data here" > /home/admin/private/secret.txt \
    && echo "Backup manifest" > /home/backup/archives/manifest.txt \
    && echo "User files" > /home/ftpuser/files/readme.txt

# Set permissions
RUN chown -R ftp:ftp /var/ftp \
    && chmod 755 /var/ftp/pub \
    && chown -R ftpuser:ftpuser /home/ftpuser \
    && chown -R admin:admin /home/admin \
    && chown -R backup:backup /home/backup

# Copy configuration
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf

# Create passive mode port range directory
RUN mkdir -p /var/run/vsftpd/empty

EXPOSE 21 30000-30009

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 21 || exit 1

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]
