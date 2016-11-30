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

import atexit
import base64
import os
import tempfile

import urllib3
import yaml
from kubernetes.client import configuration
from oauth2client.client import GoogleCredentials

from .incluster_config import ConfigException

_temp_files = {}


def _cleanup_temp_files():
    for k in _temp_files:
        os.remove(_temp_files[k])


def _create_temp_file_with_content(content):
    if len(_temp_files) == 0:
        atexit.register(_cleanup_temp_files)
    # Because we may change context several times, try to remember files we
    # created and reuse them at a small memory cost.
    content_key = content if isinstance(content, str) else str(content)
    if content_key in _temp_files:
        return _temp_files[content_key]
    _, name = tempfile.mkstemp()
    _temp_files[content_key] = name
    if isinstance(content, str):
        content = content.encode('utf8')
    with open(name, 'wb') as fd:
        fd.write(base64.decodestring(content))
    return name


class FileOrData(object):
    """Utility class to read content of obj[%data_key_name] or file's
     content of obj[%file_key_name] and represent it as file or data.
     Note that the data is preferred. The obj[%file_key_name] will be used iff
     obj['%data_key_name'] is not set or empty. Assumption is file content is
     raw data and data field is base64 string."""

    def __init__(self, obj, file_key_name, data_key_name=None):
        if not data_key_name:
            data_key_name = file_key_name + "-data"
        self._file = None
        self._data = None
        if data_key_name in obj:
            self._data = obj[data_key_name]
        elif file_key_name in obj:
            self._file = obj[file_key_name]

    @property
    def file(self):
        """If obj[%data_key_name] exists, return name of a file with base64
        decoded obj[%data_key_name] content otherwise obj[%file_key_name]."""
        use_data_if_no_file = not self._file and self._data
        if use_data_if_no_file:
            self._file = _create_temp_file_with_content(self._data)
        return self._file

    @property
    def data(self):
        """If obj[%data_key_name] exists, Return obj[%data_key_name] otherwise
        base64 encoded string of obj[%file_key_name] file content."""
        use_file_if_no_data = not self._data and self._file
        if use_file_if_no_data:
            with open(self._file) as f:
                self._data = bytes.decode(
                    base64.encodestring(str.encode(f.read())))
        return self._data


class KubeConfigLoader(object):

    def __init__(self, config_dict, active_context=None,
                 get_google_credentials=None, client_configuration=None):
        self._config = ConfigNode('kube-config', config_dict)
        self._current_context = None
        self._user = None
        self._cluster = None
        self.set_active_context(active_context)
        if get_google_credentials:
            self._get_google_credentials = get_google_credentials
        else:
            self._get_google_credentials = lambda: (
                GoogleCredentials.get_application_default()
                .get_access_token().access_token)
        if client_configuration:
            self._client_configuration = client_configuration
        else:
            self._client_configuration = configuration

    def set_active_context(self, context_name=None):
        if context_name is None:
            context_name = self._config['current-context']
        self._current_context = self._config['contexts'].get_with_name(
            context_name)
        if self._current_context['context'].safe_get('user'):
            self._user = self._config['users'].get_with_name(
                self._current_context['context']['user'])['user']
        else:
            self._user = None
        self._cluster = self._config['clusters'].get_with_name(
            self._current_context['context']['cluster'])['cluster']

    def _load_authentication(self):
        """Read authentication from kube-config user section if exists.

        This function goes through various authetication methods in user
        section of kubeconfig and stops if it founds a valid authentication
        method. The order of authentication methods is:

            1. GCP auth-provider
            2. token_data
            3. token field (point to a token file)
            4. username/password
        """
        if not self._user:
            return
        if self._load_gcp_token():
            return
        if self._load_user_token():
            return
        self._load_userpass_token()

    def _load_gcp_token(self):
        if 'auth-provider' not in self._user:
            return
        if 'name' not in self._user['auth-provider']:
            return
        if self._user['auth-provider']['name'] != 'gcp':
            return
        # Ignore configs in auth-provider and rely on GoogleCredentials
        # caching and refresh mechanism.
        # TODO: support gcp command based token ("cmd-path" config).
        self.token = self._get_google_credentials()
        return self.token

    def _load_user_token(self):
        token = FileOrData(self._user, 'tokenFile', 'token').data
        if token:
            self.token = token
            return True

    def _load_userpass_token(self):
        if 'username' in self._user and 'password' in self._user:
            self.token = urllib3.util.make_headers(
                basic_auth=(self._user['username'] + ':' +
                            self._user['password'])).get('authorization')
            return True

    def _load_cluster_info(self):
        if 'server' in self._cluster:
            self.host = self._cluster['server']
            if self.host.startswith("https"):
                self.ssl_ca_cert = FileOrData(
                    self._cluster, 'certificate-authority').file
                self.cert_file = FileOrData(
                    self._user, 'client-certificate').file
                self.key_file = FileOrData(self._user, 'client-key').file

    def _set_config(self):
        if hasattr(self, 'token'):
            self._client_configuration.api_key['authorization'] = self.token
        # copy these keys directly from self to configuration object
        keys = ['host', 'ssl_ca_cert', 'cert_file', 'key_file']
        for key in keys:
            if hasattr(self, key):
                setattr(self._client_configuration, key, getattr(self, key))

    def load_and_set(self):
        self._load_authentication()
        self._load_cluster_info()
        self._set_config()

    def list_context(self):
        contexts = []
        for c in self._config['contexts']:
            contexts.append(c.value)
        return contexts

    @property
    def current_context(self):
        return self._current_context.value


class ConfigNode:
    """Remembers each conifg key's path and construct a relevant exception
    message in case of missing keys. The assumption is all access keys are
    present in a well-formed kube-config."""

    def __init__(self, name, value):
        self._name = name
        self._value = value

    @property
    def value(self):
        return self._value

    @property
    def name(self):
        return self._name

    def __contains__(self, key):
        return key in self.value

    def __len__(self):
        return len(self.value)

    def safe_get(self, key):
        if (isinstance(self.value, list) and isinstance(key, int) or
                key in self.value):
            return self.value[key]

    def __getitem__(self, key):
        v = self.safe_get(key)
        if not v:
            raise ConfigException(
                'Invalid kube-config file. Expect key %s in %s'
                % (key, self._name))
        if isinstance(v, dict) or isinstance(v, list):
            return ConfigNode('%s/%s' % (self._name, key), v)
        else:
            return v

    def get_with_name(self, name):
        if not isinstance(self.value, list):
            raise ConfigException(
                'Invalid kube-config file. Expect %s to be a list'
                % self._name)
        for v in self.value:
            if 'name' not in v:
                raise ConfigException(
                    'Invalid kube-config file. '
                    'Expect all values in %s list to have \'name\' key'
                    % self._name)
            if v['name'] == name:
                return ConfigNode('%s[name=%s]' % (self._name, name), v)
        raise ConfigException(
            'Invalid kube-config file. '
            'Expect object with name %s in %s list' % (name, self._name))


def list_kube_config_context(config_file):
    with open(config_file) as f:
        loader = KubeConfigLoader(config_dict=yaml.load(f))
        return loader.list_context(), loader.current_context


def load_kube_config(config_file, context=None):
    """Loads authentication and cluster information from kube-config file
    and store them in kubernetes.client.configuration.

    :param config_file: Name of the kube-config file.
    :param context: set the active context. If is set to None, current_context
    from config file will be used.
    """

    with open(config_file) as f:
        KubeConfigLoader(
            config_dict=yaml.load(f), active_context=context).load_and_set()
