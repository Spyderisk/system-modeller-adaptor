# coding: utf-8

"""
    OpenAPI definition

    SPYDERISK System Modeller (SSM) REST API definitions for domain models, user system models and usage by other applications.  # noqa: E501

    The version of the OpenAPI document: v3.4.0
    Contact: info@spyderisk.com
    Generated by: https://openapi-generator.tech
"""


import pprint
import re  # noqa: F401

import six

from ssm_api_client.configuration import Configuration


class ControlSetDB(object):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    """
    Attributes:
      openapi_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    openapi_types = {
        'uri': 'str',
        'type': 'str',
        'id': 'str',
        'located_at': 'str',
        'control': 'str',
        'proposed': 'bool',
        'coverage_level': 'str',
        'min_of': 'str',
        'max_of': 'str',
        'has_min': 'str',
        'has_max': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'type': 'type',
        'id': 'id',
        'located_at': 'locatedAt',
        'control': 'control',
        'proposed': 'proposed',
        'coverage_level': 'coverageLevel',
        'min_of': 'minOf',
        'max_of': 'maxOf',
        'has_min': 'hasMin',
        'has_max': 'hasMax'
    }

    def __init__(self, uri=None, type=None, id=None, located_at=None, control=None, proposed=None, coverage_level=None, min_of=None, max_of=None, has_min=None, has_max=None, local_vars_configuration=None):  # noqa: E501
        """ControlSetDB - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._type = None
        self._id = None
        self._located_at = None
        self._control = None
        self._proposed = None
        self._coverage_level = None
        self._min_of = None
        self._max_of = None
        self._has_min = None
        self._has_max = None
        self.discriminator = None

        if uri is not None:
            self.uri = uri
        if type is not None:
            self.type = type
        if id is not None:
            self.id = id
        if located_at is not None:
            self.located_at = located_at
        if control is not None:
            self.control = control
        if proposed is not None:
            self.proposed = proposed
        if coverage_level is not None:
            self.coverage_level = coverage_level
        if min_of is not None:
            self.min_of = min_of
        if max_of is not None:
            self.max_of = max_of
        if has_min is not None:
            self.has_min = has_min
        if has_max is not None:
            self.has_max = has_max

    @property
    def uri(self):
        """Gets the uri of this ControlSetDB.  # noqa: E501


        :return: The uri of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this ControlSetDB.


        :param uri: The uri of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def type(self):
        """Gets the type of this ControlSetDB.  # noqa: E501


        :return: The type of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this ControlSetDB.


        :param type: The type of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def id(self):
        """Gets the id of this ControlSetDB.  # noqa: E501


        :return: The id of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ControlSetDB.


        :param id: The id of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def located_at(self):
        """Gets the located_at of this ControlSetDB.  # noqa: E501


        :return: The located_at of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._located_at

    @located_at.setter
    def located_at(self, located_at):
        """Sets the located_at of this ControlSetDB.


        :param located_at: The located_at of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._located_at = located_at

    @property
    def control(self):
        """Gets the control of this ControlSetDB.  # noqa: E501


        :return: The control of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._control

    @control.setter
    def control(self, control):
        """Sets the control of this ControlSetDB.


        :param control: The control of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._control = control

    @property
    def proposed(self):
        """Gets the proposed of this ControlSetDB.  # noqa: E501


        :return: The proposed of this ControlSetDB.  # noqa: E501
        :rtype: bool
        """
        return self._proposed

    @proposed.setter
    def proposed(self, proposed):
        """Sets the proposed of this ControlSetDB.


        :param proposed: The proposed of this ControlSetDB.  # noqa: E501
        :type: bool
        """

        self._proposed = proposed

    @property
    def coverage_level(self):
        """Gets the coverage_level of this ControlSetDB.  # noqa: E501


        :return: The coverage_level of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._coverage_level

    @coverage_level.setter
    def coverage_level(self, coverage_level):
        """Sets the coverage_level of this ControlSetDB.


        :param coverage_level: The coverage_level of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._coverage_level = coverage_level

    @property
    def min_of(self):
        """Gets the min_of of this ControlSetDB.  # noqa: E501


        :return: The min_of of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._min_of

    @min_of.setter
    def min_of(self, min_of):
        """Sets the min_of of this ControlSetDB.


        :param min_of: The min_of of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._min_of = min_of

    @property
    def max_of(self):
        """Gets the max_of of this ControlSetDB.  # noqa: E501


        :return: The max_of of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._max_of

    @max_of.setter
    def max_of(self, max_of):
        """Sets the max_of of this ControlSetDB.


        :param max_of: The max_of of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._max_of = max_of

    @property
    def has_min(self):
        """Gets the has_min of this ControlSetDB.  # noqa: E501


        :return: The has_min of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._has_min

    @has_min.setter
    def has_min(self, has_min):
        """Sets the has_min of this ControlSetDB.


        :param has_min: The has_min of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._has_min = has_min

    @property
    def has_max(self):
        """Gets the has_max of this ControlSetDB.  # noqa: E501


        :return: The has_max of this ControlSetDB.  # noqa: E501
        :rtype: str
        """
        return self._has_max

    @has_max.setter
    def has_max(self, has_max):
        """Sets the has_max of this ControlSetDB.


        :param has_max: The has_max of this ControlSetDB.  # noqa: E501
        :type: str
        """

        self._has_max = has_max

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.openapi_types):
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
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, ControlSetDB):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ControlSetDB):
            return True

        return self.to_dict() != other.to_dict()
