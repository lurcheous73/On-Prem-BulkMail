# Deployment

## Fresh installation

On a new Debian 12 machine, inspect the configuration and run sudo bash install.sh. An existing /var/lib/bulkmail/bulkmail.sqlite causes an immediate refusal. The current entry point is plain app/index.php; the obsolete compressed version is removed.

Only app files go under the document root. Both worker PHP programs go under /usr/local/sbin. Keep font licence notices with the assets. Document conversion needs LibreOffice, Poppler and ImageMagick; spellcheck uses hunspell en_GB.

A full fresh-machine installation was not rehearsed in this source reconciliation. Installer syntax, packaging, schema restoration and isolated HTTP regressions are checked separately.

## Existing installation: code-only upgrade

1. Take a consistent SQLite backup and retain the old application, CLI tools and service configuration.
2. Compare local configuration and public URLs with the repository. Do not run the fresh installer on an existing database.
3. Deploy app files to the existing public document root and the two worker PHP programs to /usr/local/sbin.
4. Preserve data, drafts, attachments, messages, sender configuration, credentials and the existing database. Never import the fresh schema over live data.
5. Validate PHP syntax and reload PHP-FPM. Restart the delivery worker only when replacing its code and after any current message finishes processing.
6. Check login, contact editing, saved drafts, history, queue health and logs.

The application creates its additional October draft/attachment tables as their modules load. The 20 October contact fix requires no database migration.

## Grange Sent-copy integration

The Python synchroniser and timer run on the Proxmox host; the private PHP exporter runs as www-data in CT300. The host script expects the existing OnlyOffice mail container in CT400 and the sender's existing Sent folder. A deterministic marker prevents duplicate filing. Filing failures cannot requeue SMTP.

The IMAP policy belongs in CT400 and is called by the existing local mail policy. It validates and reloads Dovecot without restarting the container. Inspect site-specific IDs and paths before deploying these integrations elsewhere.

## Rollback

Restore the previous code and reload PHP-FPM. Disable the host Sent timer before rolling back that integration. Keep new data tables and retained files so drafts remain recoverable. Do not overwrite a live database with an older backup after new work has been created.
