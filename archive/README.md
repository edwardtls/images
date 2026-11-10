# Archived images

Nothing here is built by the workflow or deployed.

- `backup-image/`: the `d00s/pg-backup` image of the hourly `pg_dump`
  CronJobs. They were replaced on 2026-11-10 by the CloudNativePG Barman Cloud
  Plugin, which backs every cluster up continuously with its own images; the
  Harbor repository was deleted. The d00s manifests are in
  `archive/retired-applications/database-backups/` of the d00s repository.
