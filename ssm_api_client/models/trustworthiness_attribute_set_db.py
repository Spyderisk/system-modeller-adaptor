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


class TrustworthinessAttributeSetDB(object):
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
        'trustworthiness_attribute': 'str',
        'located_at': 'str',
        'asserted_level': 'str',
        'inferred_level': 'str',
        'external_cause': 'bool',
        'caused_threats': 'list[str]',
        'min_of': 'str',
        'max_of': 'str',
        'has_min': 'str',
        'has_max': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'type': 'type',
        'id': 'id',
        'trustworthiness_attribute': 'trustworthinessAttribute',
        'located_at': 'locatedAt',
        'asserted_level': 'assertedLevel',
        'inferred_level': 'inferredLevel',
        'external_cause': 'externalCause',
        'caused_threats': 'causedThreats',
        'min_of': 'minOf',
        'max_of': 'maxOf',
        'has_min': 'hasMin',
        'has_max': 'hasMax'
    }

    def __init__(self, uri=None, type=None, id=None, trustworthiness_attribute=None, located_at=None, asserted_level=None, inferred_level=None, external_cause=None, caused_threats=None, min_of=None, max_of=None, has_min=None, has_max=None, local_vars_configuration=None):  # noqa: E501
        """TrustworthinessAttributeSetDB - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._type = None
        self._id = None
        self._trustworthiness_attribute = None
        self._located_at = None
        self._asserted_level = None
        self._inferred_level = None
        self._external_cause = None
        self._caused_threats = None
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
        if trustworthiness_attribute is not None:
            self.trustworthiness_attribute = trustworthiness_attribute
        if located_at is not None:
            self.located_at = located_at
        if asserted_level is not None:
            self.asserted_level = asserted_level
        if inferred_level is not None:
            self.inferred_level = inferred_level
        if external_cause is not None:
            self.external_cause = external_cause
        if caused_threats is not None:
            self.caused_threats = caused_threats
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
        """Gets the uri of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The uri of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this TrustworthinessAttributeSetDB.


        :param uri: The uri of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def type(self):
        """Gets the type of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The type of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this TrustworthinessAttributeSetDB.


        :param type: The type of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def id(self):
        """Gets the id of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The id of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this TrustworthinessAttributeSetDB.


        :param id: The id of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def trustworthiness_attribute(self):
        """Gets the trustworthiness_attribute of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The trustworthiness_attribute of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._trustworthiness_attribute

    @trustworthiness_attribute.setter
    def trustworthiness_attribute(self, trustworthiness_attribute):
        """Sets the trustworthiness_attribute of this TrustworthinessAttributeSetDB.


        :param trustworthiness_attribute: The trustworthiness_attribute of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._trustworthiness_attribute = trustworthiness_attribute

    @property
    def located_at(self):
        """Gets the located_at of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The located_at of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._located_at

    @located_at.setter
    def located_at(self, located_at):
        """Sets the located_at of this TrustworthinessAttributeSetDB.


        :param located_at: The located_at of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._located_at = located_at

    @property
    def asserted_level(self):
        """Gets the asserted_level of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The asserted_level of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._asserted_level

    @asserted_level.setter
    def asserted_level(self, asserted_level):
        """Sets the asserted_level of this TrustworthinessAttributeSetDB.


        :param asserted_level: The asserted_level of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._asserted_level = asserted_level

    @property
    def inferred_level(self):
        """Gets the inferred_level of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The inferred_level of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._inferred_level

    @inferred_level.setter
    def inferred_level(self, inferred_level):
        """Sets the inferred_level of this TrustworthinessAttributeSetDB.


        :param inferred_level: The inferred_level of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._inferred_level = inferred_level

    @property
    def external_cause(self):
        """Gets the external_cause of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The external_cause of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: bool
        """
        return self._external_cause

    @external_cause.setter
    def external_cause(self, external_cause):
        """Sets the external_cause of this TrustworthinessAttributeSetDB.


        :param external_cause: The external_cause of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: bool
        """

        self._external_cause = external_cause

    @property
    def caused_threats(self):
        """Gets the caused_threats of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The caused_threats of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._caused_threats

    @caused_threats.setter
    def caused_threats(self, caused_threats):
        """Sets the caused_threats of this TrustworthinessAttributeSetDB.


        :param caused_threats: The caused_threats of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: list[str]
        """

        self._caused_threats = caused_threats

    @property
    def min_of(self):
        """Gets the min_of of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The min_of of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._min_of

    @min_of.setter
    def min_of(self, min_of):
        """Sets the min_of of this TrustworthinessAttributeSetDB.


        :param min_of: The min_of of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._min_of = min_of

    @property
    def max_of(self):
        """Gets the max_of of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The max_of of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._max_of

    @max_of.setter
    def max_of(self, max_of):
        """Sets the max_of of this TrustworthinessAttributeSetDB.


        :param max_of: The max_of of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._max_of = max_of

    @property
    def has_min(self):
        """Gets the has_min of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The has_min of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._has_min

    @has_min.setter
    def has_min(self, has_min):
        """Sets the has_min of this TrustworthinessAttributeSetDB.


        :param has_min: The has_min of this TrustworthinessAttributeSetDB.  # noqa: E501
        :type: str
        """

        self._has_min = has_min

    @property
    def has_max(self):
        """Gets the has_max of this TrustworthinessAttributeSetDB.  # noqa: E501


        :return: The has_max of this TrustworthinessAttributeSetDB.  # noqa: E501
        :rtype: str
        """
        return self._has_max

    @has_max.setter
    def has_max(self, has_max):
        """Sets the has_max of this TrustworthinessAttributeSetDB.


        :param has_max: The has_max of this TrustworthinessAttributeSetDB.  # noqa: E501
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
        if not isinstance(other, TrustworthinessAttributeSetDB):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TrustworthinessAttributeSetDB):
            return True

        return self.to_dict() != other.to_dict()
