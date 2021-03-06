# coding: utf-8

"""
    Kubernetes

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

    OpenAPI spec version: v1.5.0-beta.1
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

from pprint import pformat
from six import iteritems
import re


class V1beta1DaemonSetStatus(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, current_number_scheduled=None, desired_number_scheduled=None, number_misscheduled=None, number_ready=None):
        """
        V1beta1DaemonSetStatus - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'current_number_scheduled': 'int',
            'desired_number_scheduled': 'int',
            'number_misscheduled': 'int',
            'number_ready': 'int'
        }

        self.attribute_map = {
            'current_number_scheduled': 'currentNumberScheduled',
            'desired_number_scheduled': 'desiredNumberScheduled',
            'number_misscheduled': 'numberMisscheduled',
            'number_ready': 'numberReady'
        }

        self._current_number_scheduled = current_number_scheduled
        self._desired_number_scheduled = desired_number_scheduled
        self._number_misscheduled = number_misscheduled
        self._number_ready = number_ready


    @property
    def current_number_scheduled(self):
        """
        Gets the current_number_scheduled of this V1beta1DaemonSetStatus.
        CurrentNumberScheduled is the number of nodes that are running at least 1 daemon pod and are supposed to run the daemon pod. More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :return: The current_number_scheduled of this V1beta1DaemonSetStatus.
        :rtype: int
        """
        return self._current_number_scheduled

    @current_number_scheduled.setter
    def current_number_scheduled(self, current_number_scheduled):
        """
        Sets the current_number_scheduled of this V1beta1DaemonSetStatus.
        CurrentNumberScheduled is the number of nodes that are running at least 1 daemon pod and are supposed to run the daemon pod. More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :param current_number_scheduled: The current_number_scheduled of this V1beta1DaemonSetStatus.
        :type: int
        """
        if current_number_scheduled is None:
            raise ValueError("Invalid value for `current_number_scheduled`, must not be `None`")

        self._current_number_scheduled = current_number_scheduled

    @property
    def desired_number_scheduled(self):
        """
        Gets the desired_number_scheduled of this V1beta1DaemonSetStatus.
        DesiredNumberScheduled is the total number of nodes that should be running the daemon pod (including nodes correctly running the daemon pod). More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :return: The desired_number_scheduled of this V1beta1DaemonSetStatus.
        :rtype: int
        """
        return self._desired_number_scheduled

    @desired_number_scheduled.setter
    def desired_number_scheduled(self, desired_number_scheduled):
        """
        Sets the desired_number_scheduled of this V1beta1DaemonSetStatus.
        DesiredNumberScheduled is the total number of nodes that should be running the daemon pod (including nodes correctly running the daemon pod). More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :param desired_number_scheduled: The desired_number_scheduled of this V1beta1DaemonSetStatus.
        :type: int
        """
        if desired_number_scheduled is None:
            raise ValueError("Invalid value for `desired_number_scheduled`, must not be `None`")

        self._desired_number_scheduled = desired_number_scheduled

    @property
    def number_misscheduled(self):
        """
        Gets the number_misscheduled of this V1beta1DaemonSetStatus.
        NumberMisscheduled is the number of nodes that are running the daemon pod, but are not supposed to run the daemon pod. More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :return: The number_misscheduled of this V1beta1DaemonSetStatus.
        :rtype: int
        """
        return self._number_misscheduled

    @number_misscheduled.setter
    def number_misscheduled(self, number_misscheduled):
        """
        Sets the number_misscheduled of this V1beta1DaemonSetStatus.
        NumberMisscheduled is the number of nodes that are running the daemon pod, but are not supposed to run the daemon pod. More info: http://releases.k8s.io/HEAD/docs/admin/daemons.md

        :param number_misscheduled: The number_misscheduled of this V1beta1DaemonSetStatus.
        :type: int
        """
        if number_misscheduled is None:
            raise ValueError("Invalid value for `number_misscheduled`, must not be `None`")

        self._number_misscheduled = number_misscheduled

    @property
    def number_ready(self):
        """
        Gets the number_ready of this V1beta1DaemonSetStatus.
        NumberReady is the number of nodes that should be running the daemon pod and have one or more of the daemon pod running and ready.

        :return: The number_ready of this V1beta1DaemonSetStatus.
        :rtype: int
        """
        return self._number_ready

    @number_ready.setter
    def number_ready(self, number_ready):
        """
        Sets the number_ready of this V1beta1DaemonSetStatus.
        NumberReady is the number of nodes that should be running the daemon pod and have one or more of the daemon pod running and ready.

        :param number_ready: The number_ready of this V1beta1DaemonSetStatus.
        :type: int
        """
        if number_ready is None:
            raise ValueError("Invalid value for `number_ready`, must not be `None`")

        self._number_ready = number_ready

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
