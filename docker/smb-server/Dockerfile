# =============================================================================
# SMB Server Container - Share Enumeration Testing
# =============================================================================
# This container provides a Samba server for testing SMB enumeration
# tools including share discovery and null session attacks.
#
# Features:
# - Multiple shares with different permissions
# - Null session access enabled
# - Guest access to public shares
# - Weak default credentials
#
# WARNING: This container is intentionally insecure.
# =============================================================================

FROM alpine:3.18

LABEL maintainer="CPTC11 Team"
LABEL description="SMB server for enumeration testing"
LABEL cptc11.role="smb-server"

# Install Samba
RUN apk add --no-cache \
    samba \
    samba-common-tools \
    shadow \
    && rm -rf /var/cache/apk/*

# Create SMB users
RUN adduser -D -H -s /sbin/nologin smbuser \
    && adduser -D -H -s /sbin/nologin admin \
    && adduser -D -H -s /sbin/nologin backup \
    && adduser -D -H -s /sbin/nologin guest \
    && adduser -D -H -s /sbin/nologin nobody

# Set SMB passwords
RUN echo -e "smbpass123\nsmbpass123" | smbpasswd -a -s smbuser \
    && echo -e "admin123\nadmin123" | smbpasswd -a -s admin \
    && echo -e "backup2024\nbackup2024" | smbpasswd -a -s backup

# Create share directories
RUN mkdir -p /share/public \
    && mkdir -p /share/private \
    && mkdir -p /share/backup \
    && mkdir -p /share/it \
    && mkdir -p /share/hr \
    && mkdir -p /share/finance \
    && mkdir -p /share/admin

# Create test files in shares
RUN echo "Public share - Read access for everyone" > /share/public/readme.txt \
    && echo "Employee list 2024" > /share/public/employees.txt \
    && echo "Company policies" > /share/public/policies.txt \
    && echo "Private data - Authenticated access only" > /share/private/confidential.txt \
    && echo "Database credentials: mysql:mysql123" > /share/private/db_config.txt \
    && echo "Backup manifest - system1, system2, system3" > /share/backup/manifest.txt \
    && echo "IT documentation" > /share/it/runbooks.txt \
    && echo "Network diagram v2.1" > /share/it/network.txt \
    && echo "Password policy: 8 chars, 90 day expiry" > /share/it/password_policy.txt \
    && echo "HR records - confidential" > /share/hr/records.txt \
    && echo "Salary information" > /share/hr/salaries.xlsx \
    && echo "Financial reports Q4" > /share/finance/q4_report.txt \
    && echo "Budget 2024" > /share/finance/budget.xlsx \
    && echo "Admin scripts" > /share/admin/scripts.txt \
    && echo "Server credentials" > /share/admin/creds.txt

# Set permissions
RUN chmod -R 755 /share/public \
    && chmod -R 750 /share/private \
    && chmod -R 750 /share/backup \
    && chmod -R 750 /share/it \
    && chmod -R 750 /share/hr \
    && chmod -R 750 /share/finance \
    && chmod -R 700 /share/admin \
    && chown -R smbuser:smbuser /share/public /share/private \
    && chown -R backup:backup /share/backup \
    && chown -R admin:admin /share/it /share/admin \
    && chown -R smbuser:smbuser /share/hr /share/finance

# Copy Samba configuration
COPY smb.conf /etc/samba/smb.conf

# Create required directories
RUN mkdir -p /var/lib/samba/private \
    && mkdir -p /var/log/samba \
    && mkdir -p /var/run/samba

EXPOSE 139 445

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD smbclient -L localhost -N || exit 1

CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
