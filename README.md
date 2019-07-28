# rgws3
a simple s3 tool for radosgw

# config:
    ## show basic conf
        s3 -x
    ## save basic conf
        s3 -o rgw.conf -x
    ## build config and save
        s3 -n rgw -p 7000 -k access -s secret -o rgw.conf -x
# s3 support:
    list buckets
        s3 -c rgw.conf get /
    create bucket
        s3 -c rgw.conf put /bucket
    delete bucket
        s3 -c rgw.conf delete /bucket
    list objects in bucket
        s3 -c rgw.conf get /bucket
    create object
        s3 -c rgw.conf put /bucket/obj -f local_file
    download object
        s3 -c rgw.conf get /bucket/obj -o local_file
    delete object
        s3 -c rgw.conf delete /bucket/obj
