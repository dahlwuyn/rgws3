# rgws3
a simple s3 tool for radosgw

# config:
## show basic conf
        python s3.py -x
## save basic conf
        python s3.py -o rgw.conf -x
## build config and save
        python s3.py -n rgw -p 7000 -k access -s secret -o rgw.conf -x
# s3 operations:
##  list buckets
        python s3.py -c rgw.conf get /
##  create bucket
        python s3.py -c rgw.conf put /bucket
##  delete bucket
        python s3.py -c rgw.conf delete /bucket
##  list objects in bucket
        python s3.py -c rgw.conf get /bucket
##  create object
        python s3.py -c rgw.conf put /bucket/obj -f local_file
##  download object
        python s3.py -c rgw.conf get /bucket/obj -o local_file
##  delete object
        python s3.py -c rgw.conf delete /bucket/obj
