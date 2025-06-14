# info:
this image contains all the tools required for "me" to push my backups to an S3 bucket and run my python tagging and retention script over it.

# build images
```
docker build -t edwardtls1/pg-backup:latest -t edwardtls1/pg-backup:1.03 .
```

# push images
```
docker push edwardtls1/pg-backup:latest
docker push edwardtls1/pg-backup:1.03
```