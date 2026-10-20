# Source reconciliation — 20 October 2026

GitHub previously stopped at 3 September. This update reconciles the current public application and private CLI tools with the deployed Grange version, preserving repository history.

Includes contact and group maintenance, shared and per-recipient attachments, UK English spellcheck, inline images, locally hosted fonts, templates/Use Again, complete drafts/recovery, preview/send idempotency, controlled delivery, Sent filing and deployment scripts.

The latest contact fix checks active and archived address clashes, retains failed form input/groups, hides PDO internals and commits the audit with the contact/group transaction.

Packaging uses plain index.php, keeps CLI scripts outside the webroot, updates schema-only initialization, retains font licences and refuses existing databases in the fresh installer. This Git synchronization does not change the running application.
