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


class AssetDB(object):
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
        'label': 'str',
        'description': 'str',
        'min_cardinality': 'int',
        'max_cardinality': 'int',
        'population': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'type': 'type',
        'id': 'id',
        'label': 'label',
        'description': 'description',
        'min_cardinality': 'minCardinality',
        'max_cardinality': 'maxCardinality',
        'population': 'population'
    }

    def __init__(self, uri=None, type=None, id=None, label=None, description=None, min_cardinality=None, max_cardinality=None, population=None, local_vars_configuration=None):  # noqa: E501
        """AssetDB - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._type = None
        self._id = None
        self._label = None
        self._description = None
        self._min_cardinality = None
        self._max_cardinality = None
        self._population = None
        self.discriminator = None

        if uri is not None:
            self.uri = uri
        if type is not None:
            self.type = type
        if id is not None:
            self.id = id
        if label is not None:
            self.label = label
        if description is not None:
            self.description = description
        if min_cardinality is not None:
            self.min_cardinality = min_cardinality
        if max_cardinality is not None:
            self.max_cardinality = max_cardinality
        if population is not None:
            self.population = population

    @property
    def uri(self):
        """Gets the uri of this AssetDB.  # noqa: E501


        :return: The uri of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this AssetDB.


        :param uri: The uri of this AssetDB.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def type(self):
        """Gets the type of this AssetDB.  # noqa: E501


        :return: The type of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this AssetDB.


        :param type: The type of this AssetDB.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def id(self):
        """Gets the id of this AssetDB.  # noqa: E501


        :return: The id of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this AssetDB.


        :param id: The id of this AssetDB.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def label(self):
        """Gets the label of this AssetDB.  # noqa: E501


        :return: The label of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this AssetDB.


        :param label: The label of this AssetDB.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this AssetDB.  # noqa: E501


        :return: The description of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this AssetDB.


        :param description: The description of this AssetDB.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def min_cardinality(self):
        """Gets the min_cardinality of this AssetDB.  # noqa: E501


        :return: The min_cardinality of this AssetDB.  # noqa: E501
        :rtype: int
        """
        return self._min_cardinality

    @min_cardinality.setter
    def min_cardinality(self, min_cardinality):
        """Sets the min_cardinality of this AssetDB.


        :param min_cardinality: The min_cardinality of this AssetDB.  # noqa: E501
        :type: int
        """

        self._min_cardinality = min_cardinality

    @property
    def max_cardinality(self):
        """Gets the max_cardinality of this AssetDB.  # noqa: E501


        :return: The max_cardinality of this AssetDB.  # noqa: E501
        :rtype: int
        """
        return self._max_cardinality

    @max_cardinality.setter
    def max_cardinality(self, max_cardinality):
        """Sets the max_cardinality of this AssetDB.


        :param max_cardinality: The max_cardinality of this AssetDB.  # noqa: E501
        :type: int
        """

        self._max_cardinality = max_cardinality

    @property
    def population(self):
        """Gets the population of this AssetDB.  # noqa: E501


        :return: The population of this AssetDB.  # noqa: E501
        :rtype: str
        """
        return self._population

    @population.setter
    def population(self, population):
        """Sets the population of this AssetDB.


        :param population: The population of this AssetDB.  # noqa: E501
        :type: str
        """

        self._population = population

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
        if not isinstance(other, AssetDB):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AssetDB):
            return True

        return self.to_dict() != other.to_dict()
