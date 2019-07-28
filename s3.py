#!/usr/bin/env python

import sys
import json
import argparse
import urlparse
import os
import errno
import ConfigParser
import textwrap

from RgwConn import RgwConn, RgwAdminConn, RgwError, RGWURLError

# 1GB, simple put object if file size < 1GB
MAX_SIMPLE_PUT_OBJECT_SIZE = 1 << 30


def log_error(msg):
    print "ERROR:", msg


class S3Cmd(object):
    def __init__(self, args):
        if args.verbose:
            print "args:", args
        self.args = args
        self.rgw = RgwConn(host=args.host,
                           port=args.port,
                           access_key=args.access,
                           secret_key=args.secret,
                           )
        self.method = args.method
        assert isinstance(self.method, str)
        self.url = args.url
        assert isinstance(self.url, str)
        self.headers_list = args.headers or []
        assert isinstance(self.headers_list, list)
        self.ex_http_headers = dict()
        self.verbose = args.verbose or False
        self.show_time = args.show_time
        self.output = args.output
        assert isinstance(self.output, str)
        self.local_file = args.local_file
        assert isinstance(self.local_file, str)
        # extract from url
        self.path = ""
        self.query_params = {}
        self.bucket = ""
        self.key = ""
        self._split_url()
        # coordinate headers
        for h in self.headers_list:
            key, val = h.split(":", 1)
            assert isinstance(key, str)
            key = key.strip().lower()
            self.ex_http_headers[key] = val

    def _split_url(self):
        parsed = urlparse.urlparse(self.url)
        self.path = parsed.path
        query = parsed.query
        if query:
            query_params = urlparse.parse_qs(query, keep_blank_values=True)
            for key, val in query_params.iteritems():
                assert isinstance(val, list)
                self.query_params[key] = val[0]
        path_splits = self.path.split("/", 2)
        if len(path_splits) > 1:
            self.bucket = path_splits[1]
            if len(path_splits) > 2:
                self.key = path_splits[2]

    def do_get(self):
        if self.key:
            return self._get_object_op()
        elif self.bucket:
            return self._get_bucket_op()
        else:
            return self._list_buckets()

    def do_put(self):
        if self.key:
            return self._put_object_op()
        elif self.bucket:
            return self._put_bucket_op()
        else:
            print "ERROR: bucket and object not specified"
            return 1

    def do_post(self):
        pass

    def do_delete(self):
        if self.key:
            return self._delete_object_op()
        elif self.bucket:
            return self._delete_bucket_op()
        else:
            print "ERROR: bucket and object not specified"
            return 1

    def _put_bucket_op(self):
        if "acl" in self.query_params:
            raise NotImplementedError()
        elif "lifecycle" in self.query_params:
            raise NotImplementedError()
        elif "policy" in self.query_params:
            raise NotImplementedError()
        elif "tagging" in self.query_params:
            raise NotImplementedError()
        elif "versioning" in self.query_params:
            raise NotImplementedError()
        elif self.query_params:
            raise NotImplementedError()
        else:
            return self._create_bucket()

    def _put_object_op(self):
        if "acl" in self.query_params:
            raise NotImplementedError()
        elif "uploadId" in self.query_params:
            raise NotImplementedError()
        elif "tagging" in self.query_params:
            raise NotImplementedError()
        else:
            return self._create_object()

    def _list_buckets(self):
        buckets = self.rgw.list_buckets()
        line_fmt = "%4s %-20s %-s"
        print line_fmt % ("No.", "Name", "Creation")
        for i, bkt in enumerate(buckets):
            print line_fmt % (i + 1, bkt["name"], bkt["creation"])
        # print buckets
        return 0

    def _get_bucket_op(self):
        if "acl" in self.query_params:
            raise NotImplementedError()
        elif "lifecycle" in self.query_params:
            raise NotImplementedError()
        elif "policy" in self.query_params:
            raise NotImplementedError()
        elif "tagging" in self.query_params:
            raise NotImplementedError()
        elif "versioning" in self.query_params:
            raise NotImplementedError()
        # elif self.query_params:
        #     raise NotImplementedError()
        else:
            return self._list_objects()

    def _get_object_op(self):
        if "acl" in self.query_params:
            raise NotImplementedError()
        elif "tagging" in self.query_params:
            raise NotImplementedError()
        else:
            return self._download_object()

    def _delete_bucket_op(self):
        special_bucket_subparams = {
            "analytics", "cors", "inventory",
            "lifecycle", "metrics", "policy",
            "replication", "tagging", "website"
        }
        if special_bucket_subparams & set(self.query_params.keys()):
            raise NotImplementedError()
        else:
            return self._delete_bucket()

    def _delete_object_op(self):
        if "tagging" in self.query_params:
            raise NotImplementedError()
        elif "uploadId" in self.query_params:
            raise NotImplementedError()
        else:
            return self._delete_object()

    def _create_bucket(self):
        if self.ex_http_headers:
            self.rgw._put(path=self.path, headers=self.ex_http_headers)
        else:
            self.rgw.create_bucket(bucket=self.bucket)
        return 0

    def _create_object(self):
        if self.local_file:
            input_file = file(self.local_file, "rb")
            input_file.seek(0, os.SEEK_END)
            file_size = input_file.tell()
            input_file.seek(0, os.SEEK_SET)
            if file_size == 0:
                input_file.close()
                input_file = None
        else:
            input_file = None
            file_size = 0
        if file_size <= MAX_SIMPLE_PUT_OBJECT_SIZE:
            return self._simple_create_object(input_file)
        else:
            return self._multipart_create_object(input_file, file_size)

    def _simple_create_object(self, input_file):
        if input_file:
            data = input_file.read()
            input_file.close()
        else:
            data = ""
        if self.ex_http_headers:
            self.rgw._put(path=self.path, headers=self.ex_http_headers, data=data)
        else:
            self.rgw.create_object(bucket=self.bucket, obj=self.key, data=data)
        return 0

    def _multipart_create_object(self, input_file, file_size):
        PART_SIZE = 512 << 20
        # init, POST /ObjectName?uploads
        # <?xml version="1.0" encoding="UTF-8"?>
        # <InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        #   <Bucket>example-bucket</Bucket>
        #   <Key>example-object</Key>
        #   <UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>
        # </InitiateMultipartUploadResult>
        path = "/%s/%s" % (self.bucket, self.key)
        headers, result = self.rgw._request("POST", path=path, query={"uploads": ""})
        id_start = result.find("<UploadId>") + len("<UploadId>")
        id_end = result.find("</UploadId>")
        upload_id = result[id_start:id_end]
        print "UploadId=%s" % upload_id

        # part, PUT /ObjectName?partNumber=PartNumber&uploadId=UploadId
        part_num = file_size / PART_SIZE
        etag_list = []
        for i in range(part_num):
            if i < part_num - 1:
                buf = input_file.read(PART_SIZE)
            else:
                buf = input_file.read()
            headers, result = self.rgw._request("PUT", path=path, body=buf,
                                                query={"uploadId": upload_id, "partNumber": str(i + 1)},
                                                )
            etag = headers["etag"]
            etag_list.append(etag)
            print "upload %d bytes" % len(buf)
            del buf
        input_file.close()
        # complete, POST /ObjectName?uploadId=UploadId
        complete_xml = "<CompleteMultipartUpload>"
        for i, etag in enumerate(etag_list):
            complete_xml += " <Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (i + 1, etag)
        complete_xml += "</CompleteMultipartUpload>"
        headers, result = self.rgw._request("POST", path=path, query={"uploadId": upload_id}, body=complete_xml)
        print result
        # raise NotImplementedError()
        pass

    def _list_objects(self):
        query_params = self.query_params.copy()
        marker = query_params.pop("marker", "")
        keys = int(query_params.pop("max-keys", 1000))
        if query_params:
            objects_data = self.rgw._get(path=self.path, query=self.query_params, headers=self.ex_http_headers)
            raise NotImplementedError()
        else:
            objects = self.rgw.list_objects(bucket=self.bucket, max_keys=keys, marker=marker)
        # display
        line_fmt = "%4s %-20s %10s %-s"
        print line_fmt % ("No.", "Name", "Size", "Creation")
        for i, obj in enumerate(objects):
            print line_fmt % (i + 1, obj["key"], obj["size"], obj["mtime"])
        return 0

    def _download_object(self):
        if self.ex_http_headers or self.query_params:
            data = self.rgw._get(path=self.path, query=self.query_params, headers=self.ex_http_headers)
        else:
            data = self.rgw.get_object(bucket=self.bucket, obj=self.key)
        # print or save
        if self.output:
            with open(self.output, "wb") as out:
                out.write(data)
        else:
            sys.stdout.write(data)
        return 0

    def _delete_bucket(self):
        if self.rgw.delete_bucket(bucket=self.bucket):
            return 0
        sys.stderr.write("ERROR: bucket %s not empty\n" % self.bucket)
        return errno.EBUSY

    def _delete_object(self):
        self.rgw.delete_object(bucket=self.bucket, obj=self.key)
        return 0

    def main(self):
        if self.verbose:
            print "url parsed: path=%s, bucket=%s, key=%s, params=%s" % (
                self.path, self.bucket, self.key, self.query_params
            )
        if not self.path or not self.path.startswith("/"):
            print "ERROR: path not start with /"
            return 1
        # if key not empty, bucket must not be empty too
        if self.key and not self.bucket:
            log_error("bucket empty")
            return 1

        # get => do_get()
        # put => do_put()
        # method => do_method()
        func = getattr(self, "do_%s" % self.method, None)
        if not func:
            print "ERROR: not supported method"
            return 2
        try:
            return func()
        except RgwError as error:
            try:
                print json.dumps(json.loads(error.body), indent=2)
            except ValueError:
                print error.body
            return error.code / 100
        except RGWURLError as error:
            print "ERROR:", error.message
            return error.errno


SECTION = "rgw"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 7480


def parse_args():
    class ShowConfAction(argparse.Action):
        def __init__(self, option_strings, dest="", default=False, required=False, help=""):
            super(ShowConfAction, self).__init__(option_strings, dest, nargs=0,
                                                 default=default, required=required, const=True, help=help)

        def __call__(self, parser, namespace, values, option_string=None):
            host = getattr(namespace, "host", DEFAULT_HOST)
            port = getattr(namespace, "port", DEFAULT_PORT)
            access_key = getattr(namespace, "access", "")
            secret_key = getattr(namespace, "secret", "")
            basic = """
                [{}]
                host = {}
                port = {}
                access_key = {}
                secret_key = {}
            """.format(SECTION, host, port, access_key, secret_key)
            basic = textwrap.dedent(basic).strip()
            if getattr(namespace, "output", ""):
                with open(namespace.output, "wb") as f:
                    f.write(basic)
                    print "save config to file %s" % namespace.output
            else:
                print basic
            sys.exit(0)

    parser = argparse.ArgumentParser(
        prog="s3",
        description=textwrap.dedent("""
        simple s3 tool.
        ----------------------------------------------------------------
        config:
            show basic conf
                s3 -x
            save basic conf
                s3 -o rgw.conf -x
            build config and save
                s3 -n rgw -p 7000 -k access -s secret -o rgw.conf -x
        s3 support:
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
            """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        version="v1.0.1"
    )
    parser.add_argument("-n", "--host", action="store", dest="host", default=DEFAULT_HOST,
                        help="rgw server host")
    parser.add_argument("-p", "--port", action="store", dest="port", default=DEFAULT_PORT, type=int,
                        help="rgw server port")
    parser.add_argument("-k", "--access", action="store", dest="access", default="",
                        help="s3 user access key")
    parser.add_argument("-s", "--secret", action="store", dest="secret", default="",
                        help="s3 user secret key")
    parser.add_argument("-c", "--conf", action="store", dest="conf", default="rgw.conf",
                        help="rgw conf file, default is rgw.conf")
    parser.add_argument("-e", "--header", action="store", dest="headers", nargs='+',
                        help="extra HTTP headers, head1:val1 head2:val2 ...")
    parser.add_argument("-b", "--verbose", action="store_true", dest="verbose",
                        help="show details while running")
    parser.add_argument("-t", "--show-time", action="store_true", dest="show_time",
                        help="show time cost")
    parser.add_argument("-o", "--output", action="store", dest="output", default="",
                        help="output file path")
    parser.add_argument("-f", "--file", action="store", dest="local_file", default="",
                        help="local input file path")
    parser.add_argument("-x", action=ShowConfAction,
                        help="show basic rgw conf, or save conf to file specified by -o. "
                             "this argument had better be last one")
    parser.add_argument("method", choices=['get', 'put', 'delete', 'post', 'head'],
                        help="HTTP methods")
    parser.add_argument("url", help="HTTP url")

    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    if args.conf:
        p = ConfigParser.ConfigParser()
        p.read(args.conf)
        if p.has_section(SECTION):
            if p.has_option(SECTION, "host"):
                args.host = p.get(SECTION, "host")
            if p.has_option(SECTION, "port"):
                args.port = p.getint(SECTION, "port")
            if p.has_option(SECTION, "access_key"):
                args.access = p.get(SECTION, "access_key")
            if p.has_option(SECTION, "secret_key"):
                args.secret = p.get(SECTION, "secret_key")
    cmd = S3Cmd(args)
    return cmd.main()


if __name__ == "__main__":
    exit(main())
