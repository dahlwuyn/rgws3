# coding: utf-8

"""
S3 api for radosgw
"""

import time
import datetime
import json
import hmac
import hashlib
import logging
import urllib2
import urllib
import xml.etree.ElementTree as ET

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
NS = {"default": XMLNS}

logger = logging.getLogger()


class RGWURLError(Exception):
    def __init__(self, errno, message):
        super(RGWURLError, self).__init__(message)
        self.errno = errno


class RgwError(Exception):
    """ radosgw response error
    
    """

    def __init__(self, resource, code, headers, message, body):
        super(RgwError, self).__init__(message)
        self.resource = resource
        self.code = code
        self.headers = headers
        self.body = body

    def __str__(self):
        return "%s %s, code=%s, reason: %s" % (self.resource, self.message, self.code, self.body)


class InvalidRequest(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(InvalidRequest, self).__init__(resource, 400, headers, "invalid request", body)


class AccessDenied(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(AccessDenied, self).__init__(resource, 403, headers, "denied", body)


class NotFound(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(NotFound, self).__init__(resource, 404, headers, "not found", body)


class NotAllowed(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(NotAllowed, self).__init__(resource, 405, headers, "not allowed", body)


class Conflict(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(Conflict, self).__init__(resource, 409, headers, "conflict", body)


class InternalError(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(InternalError, self).__init__(resource, 500, headers, "radosgw error", body)


class ServiceUnavailableError(RgwError):
    def __init__(self, resource, headers=None, body=""):
        super(ServiceUnavailableError, self).__init__(resource, 503, headers, "radosgw not available", body)


class CannedACL(object):
    PRIVATE = "private"
    PUBLIC_READ = "public-read"
    PUBLIC_READ_WRITE = "public-read-write"
    AUTHENTICATED_READ = "authenticated-read"
    BUCKET_OWNER_READ = "bucket-owner-read"
    BUCKET_OWNER_FULL_CONTROL = "bucket-owner-full-control"

    @staticmethod
    def is_valid(acl):
        return not acl or acl in {CannedACL.PRIVATE, CannedACL.PUBLIC_READ,
                                  CannedACL.PUBLIC_READ_WRITE, CannedACL.AUTHENTICATED_READ,
                                  CannedACL.BUCKET_OWNER_READ, CannedACL.BUCKET_OWNER_FULL_CONTROL}


class Permission(object):
    READ = "READ"
    READ_ACP = "READ_ACP"
    WRITE = "WRITE"
    WRITE_ACP = "WRITE_ACP"
    FULL_CONTROL = "FULL_CONTROL"

    _ALL_PERM = {READ, READ_ACP, WRITE, WRITE_ACP, FULL_CONTROL}

    @staticmethod
    def is_valid(perm):
        return perm in Permission._ALL_PERM


def _translate_error(func):
    def _func_(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RgwError as error:
            error_map = {
                400: InvalidRequest,
                403: AccessDenied,
                404: NotFound,
                405: NotAllowed,
                409: Conflict,
                500: InternalError,
                503: ServiceUnavailableError,
            }
            if error.code in error_map:
                raise error_map[error.code](error.resource, error.headers, error.body)
            raise

    return _func_


class RgwConn(object):
    """s3 api for radosgw
    """

    __slots__ = ["host", "port", "access_key", "secret_key", "_aws_auth", "_last_time", "_last_strftime",
                 "_last_isotime"]

    def __init__(self, host, port, access_key, secret_key):
        self.host = str(host)
        self.port = int(port)
        self.access_key = str(access_key)
        self.secret_key = str(secret_key)
        self._aws_auth = "AWS %s:" % str(access_key)
        self._last_time = int(time.time())
        # self._last_strftime = time.asctime(time.gmtime())
        self._last_strftime = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        self._last_isotime = datetime.datetime.now().isoformat()

    def __str__(self):
        return "[host=%s, port=%s, access_key=%s, secret_key=%s]" % (
            self.host, self.port, self.access_key, self.secret_key
        )

    def get_zonegroup_zone(self):
        try:
            self._get("/0", expect_json=True)
        except RgwError as error:
            body = error.body
            logger.debug("body: %s", body)
            body = json.loads(body)
            req_id = str(body["RequstId"])
            id_zone = req_id[35:]
            _, zone = id_zone.split("-", 1)
            host_id = str(body["HostId"])
            zonegroup = host_id[len(id_zone) + 1:]
            return zonegroup, zone

    def create_bucket(self, bucket, canned_acl=""):
        # TODO: check bucket name
        if canned_acl and not CannedACL.is_valid(canned_acl):
            raise InvalidRequest("acl", {}, "illegal canned acl")
        headers = {}
        if canned_acl:
            headers["x-amz-acl"] = canned_acl
        return self._put("/" + bucket, headers=headers)

    def create_object(self, bucket, obj, data="", metadata=None, canned_acl=""):
        # TODO: check bucket name and object name
        if canned_acl and not CannedACL.is_valid(canned_acl):
            raise InvalidRequest("acl", {}, "illegal canned acl")
        path = "/%s/%s" % (bucket, obj)
        headers = {}
        if canned_acl:
            headers["x-amz-acl"] = canned_acl
        if metadata:
            for key, val in metadata.iteritems():
                headers["x-amz-meta-" + str.lower(key)] = val
        return self._put(path, headers=headers, data=data)

    def get_object(self, bucket, obj):
        path = "/%s/%s" % (bucket, obj)
        return self._get(path)

    def get_object_acl(self, bucket, obj):
        path = "/%s/%s" % (bucket, obj)
        acl = self._get(path, query=dict(acl=""))
        return self._parse_acl(acl)

    @staticmethod
    def _parse_acl(data):
        ns = {
            "default": XMLNS,
            "xsi": "http://www.w3.org/2001/XMLSchema-instance"
        }
        acl = {}
        root = ET.fromstring(data)
        owner = root.find("default:Owner", ns)
        acl["owner"] = owner.find("default:ID", ns).text
        acl["display-name"] = owner.find("default:DisplayName", ns).text
        acl["access-control-list"] = []
        acl_list = root.find("default:AccessControlList", ns)
        for grant in acl_list.findall("default:Grant", ns):
            access = {"permission": grant.find("default:Permission", ns).text}
            account = grant.find("default:Grantee", ns).find("default:ID", ns)
            if account:
                account = account.text
                access["uid"] = account
            else:
                account = grant.find("default:Grantee", ns).find("default:URI", ns).text
                access["uri"] = account
            acl["access-control-list"].append(access)
        return acl

    def delete_bucket(self, bucket):
        try:
            return self._delete("/" + bucket)
        except Conflict:
            return False

    def delete_object(self, bucket, obj):
        path = "/%s/%s" % (bucket, obj)
        return self._delete(path)

    def list_buckets(self):
        """

        :return: bucket list
        [
            {"name": "bkt1", "creation": "2006-02-03T16:45:09.000Z"},
            {"name": "bkt2", "creation": "2016-02-03T16:45:09.000Z"}
        ]
        """
        result = self._get("/", expect_json=False)
        try:
            result = json.loads(result, object_pairs_hook=self._json_hook)
            # return [r["Name"] for r in result[1]]
            return result
        except ValueError:
            return self._parse_bucket_list_results(result)

    @staticmethod
    def _parse_bucket_list_results(data):
        ns = {
            "default": XMLNS,
            "xsi": "http://www.w3.org/2001/XMLSchema-instance"
        }
        buckets = []
        root = ET.fromstring(data)
        contents = root.find("default:Buckets", ns).findall("default:Bucket", ns)
        for ct in contents:
            name = ct.find("default:Name", ns).text
            create = ct.find("default:CreationDate", ns).text
            buckets.append({"name": name, "creation": create})
        return buckets

    def list_objects(self, bucket, marker="", max_keys=1000):
        """

        :param bucket:
        :param marker:
        :param max_keys:
        :return: objects list
        [
            {"key": "key", "size": 12, "mtime": "2009-10-12T17:50:30.000Z"},
            {"key": "key2", "size": 122, "mtime": "2019-10-12T17:50:30.000Z"}
        ]
        """
        query = {"marker": marker, "max-keys": str(max_keys)}
        result = self._get("/" + bucket, query=query, expect_json=True)
        try:
            parsed_result = self._parse_obj_list_json(result)
            objects = [
                dict(key=obj[0], size=obj[3], mtime=obj[1])
                for obj in parsed_result["Contents"]
                ]
            return objects
            # obj_list = [c[0] for c in objects["Contents"]]
            # return [str(objects["IsTruncated"]).lower() == "true"] + obj_list
        except ValueError:
            return self._parse_objects(result)

    @staticmethod
    def _parse_objects(data):
        ns = {
            "default": XMLNS,
            "xsi": "http://www.w3.org/2001/XMLSchema-instance"
        }
        objects = []
        root = ET.fromstring(data)
        contents = root.findall("default:Contents", ns)
        for ct in contents:
            key = ct.find("default:Key", ns).text
            size = ct.find("default:Size", ns).text
            mtime = ct.find("default:LastModified", ns).text
            objects.append({"key": key, "size": size, "mtime": mtime})
        """
        owner = root.find("default:k", ns)
        acl["owner"] = owner.find("default:ID", ns).text
        acl["display-name"] = owner.find("default:DisplayName", ns).text
        acl["access-control-list"] = []
        acl_list = root.find("default:AccessControlList", ns)
        for grant in acl_list.findall("default:Grant", ns):
            access = {"permission": grant.find("default:Permission", ns).text}
            account = grant.find("default:Grantee", ns).find("default:ID", ns)
            if account:
                account = account.text
                access["uid"] = account
            else:
                account = grant.find("default:Grantee", ns).find("default:URI", ns).text
                access["uri"] = account
            acl["access-control-list"].append(access)
        return acl
        """
        return objects

    def get_bucket_info(self, bucket):
        headers = self._head("/" + bucket)
        info = {
            "x-rgw-object-count": int(headers.get("x-rgw-object-count", 0)),
            "x-rgw-bytes-used": int(headers.get("x-rgw-bytes-used", 0)),
        }
        return info

    def is_bucket_exist(self, bucket):
        try:
            self.get_bucket_info(bucket)
            return True
        except AccessDenied:
            return True
        except NotFound:
            return False

    def get_object_info(self, bucket, obj):
        path = "/%s/%s" % (bucket, obj)
        headers = self._head(path)
        info = {
            "last-modified": headers["last-modified"],
            "etag": headers["etag"],
            "size": int(headers["content-length"]),
        }
        for key, val in headers.iteritems():
            if str.startswith(key, "x-amz-meta-"):
                info[key] = val
        return info

    @staticmethod
    def _parse_obj_list_json(data):
        result = json.loads(data, object_pairs_hook=RgwConn._json_hook)
        if "Contents" not in result:
            result["Contents"] = []
        elif isinstance(result["Contents"][0], basestring):
            result["Contents"] = [result["Contents"]]
        return result

    @staticmethod
    def _json_hook(lst):
        dct = {}
        key_count = {}
        for key, val in lst:
            if key in key_count:
                key_count[key] += 1
            else:
                key_count[key] = 1
            if key in dct:
                if key_count[key] > 2:
                    dct[key].append(val)
                else:
                    dct[key] = [dct[key], val]
            else:
                dct[key] = val
        return dct

    def _get(self, path, query=None, expect_json=False, headers=None):
        # type: (str, dict, bool, dict) -> str
        if expect_json:
            if not query:
                query = {"format": "json"}
            else:
                query["format"] = "json"
        _, body = self._request("GET", path, query, headers)
        return body

    def _head(self, path):
        # type: (str) -> dict
        headers, _ = self._request("HEAD", path)
        return headers

    def _put(self, path, query=None, headers=None, data=""):
        # type: (str, dict, dict, str) -> bool
        self._request("PUT", path, query, headers, data)
        return True

    def _delete(self, path, query=None):
        # type: (str, dict) -> bool
        try:
            self._request("DELETE", path, query)
        except NotFound:
            return True
        return True

    @_translate_error
    def _request(self, method, path, query=None, headers=None, body=""):
        # type: (str, str, dict, dict, str) -> tuple
        if query is None:
            query = {}
        if headers is None:
            headers = {}
        if isinstance(path, unicode):
            path = path.encode("utf-8")
        path = urllib.quote(path)
        self._prepare_headers(method, path, query, headers, body)
        url = path
        if query:
            url = path + "?" + urllib.urlencode(query)
        return self._do_request(method, url, headers, body)

    def _prepare_headers(self, method, path, query, headers, body):
        # type: (str, str, dict, dict, str) -> object
        x_amz_headers = {}
        for header, val in headers.iteritems():
            if str.startswith(header, "x-amz-"):
                x_amz_headers[header] = val
        if "date" not in headers:
            now = int(time.time())
            if now - self._last_time > 2:
                self._last_strftime = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(now))
                self._last_time = now
            date = self._last_strftime
            headers["date"] = date
        else:
            date = headers["date"]
        headers["content-length"] = len(body)
        content_type = "application/octet-stream"
        headers["content-type"] = content_type
        headers["Authorization"] = self._sign(method, path, query, x_amz_headers, date, content_type)
        pass

    # TODO: need more
    _special_query = ["acl", "cors", "policy", "partNumber", "uploadId", "uploads", "start-date", "end-date"]
    _special_query_set = set(_special_query)

    def _sign(self, method, path, query, x_amz_headers, date, content_type):
        # type: (str, str, dict, dict, str, str) -> str
        lst = [method, "", content_type, date, path]
        if x_amz_headers:
            for idx, key in enumerate(sorted(x_amz_headers.keys())):
                val = x_amz_headers[key]
                lst.insert(-1, key + ":" + val)
        if query:
            first = True
            query_lst = [path]
            for s in sorted(query.keys()):
                if s not in self._special_query_set:
                    continue
                val = query[s]
                if first:
                    query_lst.append('?')
                    first = False
                else:
                    query_lst.append('&')
                query_lst.append(s)
                if val:
                    query_lst.append('=')
                    query_lst.append(val)
            lst[-1] = "".join(query_lst)
        auth = self._aws_auth + hmac.new(self.secret_key, "\n".join(lst), hashlib.sha1).digest().encode("base64")
        auth = auth.strip()
        return auth

    def _do_request(self, method, url, headers, body=""):
        full_url = "http://%s:%s%s" % (self.host, self.port, url)
        req = urllib2.Request(full_url, headers=headers)
        req.get_method = method.upper
        if body:
            req.add_data(body)
        try:
            response = urllib2.urlopen(req)
            headers = dict(response.info().items())
            result = response.read()
            return headers, result
        except urllib2.HTTPError as error:
            raise RgwError(url, error.getcode(), error.headers, error.reason, error.read())
        except urllib2.URLError as error:
            raise RGWURLError(error.errno, error.message)


class RgwAdminConn(RgwConn):
    def list_buckets_by_user(self, uid):
        return json.loads(self._get("/admin/bucket", query={"uid": uid}, expect_json=True))

    def list_all_users(self):
        return json.loads(self._get("/admin/metadata/user"))

    def get_user_info(self, uid):
        try:
            info = self._get("/admin/user", query={"uid": uid, "stats": "true"}, expect_json=True)
        except NotFound:
            info = self._get("/admin/user", query={"uid": uid}, expect_json=True)
        info = json.loads(info, object_pairs_hook=self._json_hook)
        if "stats" not in info:
            info["stats"] = {"num_kb_rounded": 0, "num_objects": 0, "num_kb": 0}
        return info

    def get_user_meta(self, uid):
        return json.loads(self._get("/admin/metadata/user", query={"key": uid}))

    def get_bucket_meta(self, bucket):
        return json.loads(self._get("/admin/metadata/bucket", query={"key": bucket}))

    def get_bucket_status(self, bucket):
        return json.loads(self._get("/admin/bucket", query={"bucket": bucket}))

    def create_user(self, uid, display_name="", access_key="", secret="", email="", max_buckets=1000, user_caps=""):
        if not display_name:
            display_name = uid
        query = {
            "uid": uid, "display-name": display_name
        }
        if access_key:
            query["access-key"] = access_key
        if secret:
            query["secret-key"] = secret
        if email:
            query["email"] = email
        if max_buckets:
            query["max-buckets"] = str(max_buckets)
        if user_caps:
            query["user-caps"] = user_caps
        return self._put("/admin/user", query=query)

    def delete_user(self, uid, purge_data=False):
        query = {
            "uid": uid,
        }
        if purge_data:
            query["purge-data"] = "true"
        try:
            return self._delete("/admin/user", query=query)
        except Conflict:
            return False
