#!/bin/bash
for f in *
do
 echo "Processing $f"
 curl -s --form file=@$f --form press=Upload localhost:8000/upload_done
done