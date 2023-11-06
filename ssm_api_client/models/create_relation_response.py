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


class CreateRelationResponse(object):
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
        'relation': 'Relation',
        'model': 'ModelDTO'
    }

    attribute_map = {
        'relation': 'relation',
        'model': 'model'
    }

    def __init__(self, relation=None, model=None, local_vars_configuration=None):  # noqa: E501
        """CreateRelationResponse - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._relation = None
        self._model = None
        self.discriminator = None

        if relation is not None:
            self.relation = relation
        if model is not None:
            self.model = model

    @property
    def relation(self):
        """Gets the relation of this CreateRelationResponse.  # noqa: E501


        :return: The relation of this CreateRelationResponse.  # noqa: E501
        :rtype: Relation
        """
        return self._relation

    @relation.setter
    def relation(self, relation):
        """Sets the relation of this CreateRelationResponse.


        :param relation: The relation of this CreateRelationResponse.  # noqa: E501
        :type: Relation
        """

        self._relation = relation

    @property
    def model(self):
        """Gets the model of this CreateRelationResponse.  # noqa: E501


        :return: The model of this CreateRelationResponse.  # noqa: E501
        :rtype: ModelDTO
        """
        return self._model

    @model.setter
    def model(self, model):
        """Sets the model of this CreateRelationResponse.


        :param model: The model of this CreateRelationResponse.  # noqa: E501
        :type: ModelDTO
        """

        self._model = model

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
        if not isinstance(other, CreateRelationResponse):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, CreateRelationResponse):
            return True

        return self.to_dict() != other.to_dict()