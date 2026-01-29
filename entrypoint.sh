#!/bin/sh
# Ensure the entire app directory is owned by whoisuser
# This is especially important for mounted volumes
chown -R whoisuser:whoisgroup /app
# Execute the main application using su-exec to drop privileges
exec su-exec whoisuser:whoisgroup ./whois-app