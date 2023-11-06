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


class Graph(object):
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
        'threats': 'dict(str, int)',
        'misbehaviours': 'dict(str, int)',
        'twas': 'dict(str, int)',
        'links': 'list[list[str]]'
    }

    attribute_map = {
        'threats': 'threats',
        'misbehaviours': 'misbehaviours',
        'twas': 'twas',
        'links': 'links'
    }

    def __init__(self, threats=None, misbehaviours=None, twas=None, links=None, local_vars_configuration=None):  # noqa: E501
        """Graph - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._threats = None
        self._misbehaviours = None
        self._twas = None
        self._links = None
        self.discriminator = None

        if threats is not None:
            self.threats = threats
        if misbehaviours is not None:
            self.misbehaviours = misbehaviours
        if twas is not None:
            self.twas = twas
        if links is not None:
            self.links = links

    @property
    def threats(self):
        """Gets the threats of this Graph.  # noqa: E501


        :return: The threats of this Graph.  # noqa: E501
        :rtype: dict(str, int)
        """
        return self._threats

    @threats.setter
    def threats(self, threats):
        """Sets the threats of this Graph.


        :param threats: The threats of this Graph.  # noqa: E501
        :type: dict(str, int)
        """

        self._threats = threats

    @property
    def misbehaviours(self):
        """Gets the misbehaviours of this Graph.  # noqa: E501


        :return: The misbehaviours of this Graph.  # noqa: E501
        :rtype: dict(str, int)
        """
        return self._misbehaviours

    @misbehaviours.setter
    def misbehaviours(self, misbehaviours):
        """Sets the misbehaviours of this Graph.


        :param misbehaviours: The misbehaviours of this Graph.  # noqa: E501
        :type: dict(str, int)
        """

        self._misbehaviours = misbehaviours

    @property
    def twas(self):
        """Gets the twas of this Graph.  # noqa: E501


        :return: The twas of this Graph.  # noqa: E501
        :rtype: dict(str, int)
        """
        return self._twas

    @twas.setter
    def twas(self, twas):
        """Sets the twas of this Graph.


        :param twas: The twas of this Graph.  # noqa: E501
        :type: dict(str, int)
        """

        self._twas = twas

    @property
    def links(self):
        """Gets the links of this Graph.  # noqa: E501


        :return: The links of this Graph.  # noqa: E501
        :rtype: list[list[str]]
        """
        return self._links

    @links.setter
    def links(self, links):
        """Sets the links of this Graph.


        :param links: The links of this Graph.  # noqa: E501
        :type: list[list[str]]
        """

        self._links = links

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
        if not isinstance(other, Graph):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, Graph):
            return True

        return self.to_dict() != other.to_dict()
