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


class MetadataPair(object):
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
        'label': 'str',
        'description': 'str',
        'parents': 'list[str]',
        'key': 'str',
        'value': 'str',
        'id': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'label': 'label',
        'description': 'description',
        'parents': 'parents',
        'key': 'key',
        'value': 'value',
        'id': 'id'
    }

    def __init__(self, uri=None, label=None, description=None, parents=None, key=None, value=None, id=None, local_vars_configuration=None):  # noqa: E501
        """MetadataPair - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._label = None
        self._description = None
        self._parents = None
        self._key = None
        self._value = None
        self._id = None
        self.discriminator = None

        if uri is not None:
            self.uri = uri
        if label is not None:
            self.label = label
        if description is not None:
            self.description = description
        if parents is not None:
            self.parents = parents
        if key is not None:
            self.key = key
        if value is not None:
            self.value = value
        if id is not None:
            self.id = id

    @property
    def uri(self):
        """Gets the uri of this MetadataPair.  # noqa: E501


        :return: The uri of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this MetadataPair.


        :param uri: The uri of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def label(self):
        """Gets the label of this MetadataPair.  # noqa: E501


        :return: The label of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this MetadataPair.


        :param label: The label of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this MetadataPair.  # noqa: E501


        :return: The description of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this MetadataPair.


        :param description: The description of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def parents(self):
        """Gets the parents of this MetadataPair.  # noqa: E501


        :return: The parents of this MetadataPair.  # noqa: E501
        :rtype: list[str]
        """
        return self._parents

    @parents.setter
    def parents(self, parents):
        """Sets the parents of this MetadataPair.


        :param parents: The parents of this MetadataPair.  # noqa: E501
        :type: list[str]
        """

        self._parents = parents

    @property
    def key(self):
        """Gets the key of this MetadataPair.  # noqa: E501


        :return: The key of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """Sets the key of this MetadataPair.


        :param key: The key of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._key = key

    @property
    def value(self):
        """Gets the value of this MetadataPair.  # noqa: E501


        :return: The value of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """Sets the value of this MetadataPair.


        :param value: The value of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._value = value

    @property
    def id(self):
        """Gets the id of this MetadataPair.  # noqa: E501


        :return: The id of this MetadataPair.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this MetadataPair.


        :param id: The id of this MetadataPair.  # noqa: E501
        :type: str
        """

        self._id = id

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
        if not isinstance(other, MetadataPair):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, MetadataPair):
            return True

        return self.to_dict() != other.to_dict()
