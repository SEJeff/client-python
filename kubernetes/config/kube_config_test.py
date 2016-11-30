# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os
import tempfile
import unittest

from .incluster_config import ConfigException
from .kube_config import ConfigNode, FileOrData, KubeConfigLoader


def _base64(string):
    return base64.encodestring(string.encode()).decode()


TEST_FILE_KEY = "file"
TEST_DATA_KEY = "data"
TEST_FILENAME = "testfilename"

TEST_DATA = "testdata"
TEST_DATA_BASE64 = _base64(TEST_DATA)

TEST_ANOTHER_DATA = "anothertestdata"
TEST_ANOTHER_DATA_BASE64 = _base64(TEST_ANOTHER_DATA)

TEST_HOST = "testhost"
TEST_USERNAME = "me"
TEST_PASSWORD = "pass"
# token for me:pass
TEST_BASIC_TOKEN = "Basic bWU6cGFzcw=="

TEST_SSL_HOST = "https://testhost"
TEST_CERTIFICATE_AUTH = "certauth"
TEST_CERTIFICATE_AUTH_BASE64 = _base64(TEST_CERTIFICATE_AUTH)
TEST_CLIENT_KEY = "clientkey"
TEST_CLIENT_KEY_BASE64 = _base64(TEST_CLIENT_KEY)
TEST_CLIENT_CERT = "clientcert"
TEST_CLIENT_CERT_BASE64 = _base64(TEST_CLIENT_CERT)


class TestRoot(unittest.TestCase):

    def setUp(self):
        self._temp_files = []

    def tearDown(self):
        for f in self._temp_files:
            os.remove(f)

    def _create_temp_file(self, content=""):
        handler, name = tempfile.mkstemp()
        self._temp_files.append(name)
        os.write(handler, str.encode(content))
        os.close(handler)
        return name


class TestFileOrData(TestRoot):

    def get_file_content(self, file):
        with open(file) as f:
            return f.read()

    def test_file_given_file(self):
        obj = {TEST_FILE_KEY: TEST_FILENAME}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY)
        self.assertEqual(TEST_FILENAME, t.file)

    def test_file_fiven_data(self):
        obj = {TEST_DATA_KEY: TEST_DATA_BASE64}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY,
                       data_key_name=TEST_DATA_KEY)
        self.assertEqual(TEST_DATA, self.get_file_content(t.file))

    def test_data_given_data(self):
        obj = {TEST_DATA_KEY: TEST_DATA_BASE64}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY,
                       data_key_name=TEST_DATA_KEY)
        self.assertEqual(TEST_DATA_BASE64, t.data)

    def test_data_given_file(self):
        obj = {
            TEST_FILE_KEY: self._create_temp_file(content=TEST_DATA)}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY)
        self.assertEqual(TEST_DATA_BASE64, t.data)

    def test_data_given_file_and_data(self):
        obj = {
            TEST_DATA_KEY: TEST_DATA_BASE64,
            TEST_FILE_KEY: self._create_temp_file(
                content=TEST_ANOTHER_DATA)}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY,
                       data_key_name=TEST_DATA_KEY)
        self.assertEqual(TEST_DATA_BASE64, t.data)

    def test_file_given_file_and_data(self):
        obj = {
            TEST_DATA_KEY: TEST_DATA_BASE64,
            TEST_FILE_KEY: self._create_temp_file(
                content=TEST_ANOTHER_DATA)}
        t = FileOrData(obj=obj, file_key_name=TEST_FILE_KEY,
                       data_key_name=TEST_DATA_KEY)
        self.assertEqual(TEST_DATA, self.get_file_content(t.file))


class TestConfigNode(TestRoot):

    test_obj = {"key1": "test", "key2": ["a", "b", "c"],
                "key3": {"inner_key": "inner_value"},
                "with_names": [{"name": "test_name", "value": "test_value"},
                               {"name": "test_name2",
                                "value": {"key1", "test"}},
                               {"name": "test_name3", "value": [1, 2, 3]}]}

    def test_normal_map_array_operations(self):
        node = ConfigNode("test_obj", self.test_obj)
        self.assertEqual("test", node['key1'])
        self.assertEqual(4, len(node))

        self.assertEqual("test_obj/key2", node['key2'].name)
        self.assertEqual(["a", "b", "c"], node['key2'].value)
        self.assertEqual("b", node['key2'][1])
        self.assertEqual(3, len(node['key2']))

        self.assertEqual("test_obj/key3", node['key3'].name)
        self.assertEqual({"inner_key": "inner_value"}, node['key3'].value)
        self.assertEqual("inner_value", node['key3']["inner_key"])
        self.assertEqual(1, len(node['key3']))

    def test_get_with_name(self):
        node = ConfigNode("test_obj_with_names",
                          self.test_obj["with_names"])
        self.assertEqual(
            "test_value",
            node.get_with_name("test_name")["value"])
        self.assertTrue(
            isinstance(node.get_with_name("test_name2"), ConfigNode))
        self.assertTrue(
            isinstance(node.get_with_name("test_name3"), ConfigNode))
        self.assertEqual("test_obj_with_names[name=test_name2]",
                         node.get_with_name("test_name2").name)
        self.assertEqual("test_obj_with_names[name=test_name3]",
                         node.get_with_name("test_name3").name)

    def expect_exception(self, func, message_part):
        try:
            func()
            self.fail("Should fail.")
        except ConfigException as e:
            self.assertTrue(
                message_part in e.message, "'%s' should be in '%s'" %
                (message_part, e.message))

    def test_invalid_key(self):
        node = ConfigNode("test_obj", self.test_obj)
        self.expect_exception(lambda: node['non-existance-key'],
                              "Expect key non-existance-key in test_obj")
        self.expect_exception(lambda: node['key3']['non-existance-key'],
                              "Expect key non-existance-key in test_obj/key3")
        self.expect_exception(
            lambda: node['key2'].get_with_name('noname'),
            "Expect all values in test_obj/key2 list to have \'name\' key")
        self.expect_exception(
            lambda: node['key3'].get_with_name('noname'),
            "Expect test_obj/key3 to be a list")
        self.expect_exception(
            lambda: node['with_names'].get_with_name('noname'),
            "Expect object with name noname in test_obj/with_names list")


class FakeConfig:

    FILE_KEYS = ["ssl_ca_cert", "key_file", "cert_file"]

    def __init__(self, token=None, **kwargs):
        self.api_key = {}
        if token:
            self.api_key['authorization'] = token

        self.__dict__.update(kwargs)

    def __eq__(self, other):
        if len(self.__dict__) != len(other.__dict__):
            return
        for k, v in self.__dict__.items():
            if k not in other.__dict__:
                return
            if k in self.FILE_KEYS:
                try:
                    with open(v) as f1, open(other.__dict__[k]) as f2:
                        if f1.read() != f2.read():
                            return
                except IOError as e:
                    # fall back to only compare filenames in case we are testing
                    # passing filename to the config
                    if other.__dict__[k] != v:
                        return
            else:
                if other.__dict__[k] != v:
                    return
        return True

    def __repr__(self):
        rep = "\n"
        for k, v in self.__dict__.items():
            val = v
            if k in self.FILE_KEYS:
                try:
                    with open(v) as f:
                        val = "FILE: %s" % str.decode(f.read())
                except IOError as e:
                    val = "ERROR: %s" % str(e)
            rep += "\t%s: %s\n" % (k, val)
        return "Config(%s\n)" % rep


class TestKubeConfigLoader(TestRoot):
    TEST_KUBE_CONFIG = {
        "contexts": [
            {
                "name": "no_user",
                "context": {
                    "cluster": "default"
                }
            },
            {
                "name": "simple_token",
                "context": {
                    "cluster": "default",
                    "user": "simple_token"
                }
            },
            {
                "name": "gcp",
                "context": {
                    "cluster": "default",
                    "user": "gcp"
                }
            },
            {
                "name": "userpass",
                "context": {
                    "cluster": "default",
                    "user": "userpass"
                }
            },
            {
                "name": "ssl",
                "context": {
                    "cluster": "ssl",
                    "user": "ssl"
                }
            },
            {
                "name": "ssl-nofile",
                "context": {
                    "cluster": "ssl-nofile",
                    "user": "ssl-nofile"
                }
            },
        ],
        "clusters": [
            {
                "name": "default",
                "cluster": {
                    "server": TEST_HOST
                }
            },
            {
                "name": "ssl-nofile",
                "cluster": {
                    "server": TEST_SSL_HOST,
                    "certificate-authority": TEST_CERTIFICATE_AUTH,
                }
            },
            {
                "name": "ssl",
                "cluster": {
                    "server": TEST_SSL_HOST,
                    "certificate-authority-data": TEST_CERTIFICATE_AUTH_BASE64,
                }
            },
        ],
        "users": [
            {
                "name": "simple_token",
                "user": {
                    "token": TEST_DATA_BASE64,
                    "username": TEST_USERNAME,  # should be ignored
                    "password": TEST_PASSWORD,  # should be ignored
                }
            },
            {
                "name": "gcp",
                "user": {
                    "auth-provider": {
                        "name": "gcp",
                        "access_token": "not_used",
                    },
                    "token": TEST_DATA_BASE64,  # should be ignored
                    "username": TEST_USERNAME,  # should be ignored
                    "password": TEST_PASSWORD,  # should be ignored
                }
            },
            {
                "name": "userpass",
                "user": {
                    "username": TEST_USERNAME,  # should be ignored
                    "password": TEST_PASSWORD,  # should be ignored
                }
            },
            {
                "name": "ssl-nofile",
                "user": {
                    "token": TEST_DATA_BASE64,
                    "client-certificate": TEST_CLIENT_CERT,
                    "client-key": TEST_CLIENT_KEY,
                }
            },
            {
                "name": "ssl",
                "user": {
                    "token": TEST_DATA_BASE64,
                    "client-certificate-data": TEST_CLIENT_CERT_BASE64,
                    "client-key-data": TEST_CLIENT_KEY_BASE64,
                }
            },
        ]
    }

    def test_no_user_context(self):
        expected = FakeConfig(host=TEST_HOST)
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="no_user",
            client_configuration=actual).load_and_set()
        self.assertEqual(expected, actual)

    def test_simple_token(self):
        expected = FakeConfig(host=TEST_HOST, token=TEST_DATA_BASE64)
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="simple_token",
            client_configuration=actual).load_and_set()
        self.assertEqual(expected, actual)

    def test_gcp(self):
        expected = FakeConfig(host=TEST_HOST, token=TEST_ANOTHER_DATA_BASE64)
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="gcp",
            client_configuration=actual,
            get_google_credentials=lambda: TEST_ANOTHER_DATA_BASE64) \
            .load_and_set()
        self.assertEqual(expected, actual)

    def test_userpass(self):
        expected = FakeConfig(host=TEST_HOST, token=TEST_BASIC_TOKEN)
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="userpass",
            client_configuration=actual).load_and_set()
        self.assertEqual(expected, actual)

    def test_ssl_no_certfiles(self):
        expected = FakeConfig(
            host=TEST_SSL_HOST,
            token=TEST_DATA_BASE64,
            cert_file=TEST_CLIENT_CERT,
            key_file=TEST_CLIENT_KEY,
            ssl_ca_cert=TEST_CERTIFICATE_AUTH
        )
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="ssl-nofile",
            client_configuration=actual).load_and_set()
        self.assertEqual(expected, actual)

    def test_ssl(self):
        expected = FakeConfig(
            host=TEST_SSL_HOST,
            token=TEST_DATA_BASE64,
            cert_file=self._create_temp_file(TEST_CLIENT_CERT),
            key_file=self._create_temp_file(TEST_CLIENT_KEY),
            ssl_ca_cert=self._create_temp_file(TEST_CERTIFICATE_AUTH)
        )
        actual = FakeConfig()
        KubeConfigLoader(
            config_dict=self.TEST_KUBE_CONFIG,
            active_context="ssl",
            client_configuration=actual).load_and_set()
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
