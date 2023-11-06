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


class DeleteGroupResponse(object):
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
        'assets': 'list[str]',
        'relations': 'list[str]',
        'valid': 'bool',
        'asset_group': 'str',
        'empty': 'bool'
    }

    attribute_map = {
        'assets': 'assets',
        'relations': 'relations',
        'valid': 'valid',
        'asset_group': 'assetGroup',
        'empty': 'empty'
    }

    def __init__(self, assets=None, relations=None, valid=None, asset_group=None, empty=None, local_vars_configuration=None):  # noqa: E501
        """DeleteGroupResponse - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._assets = None
        self._relations = None
        self._valid = None
        self._asset_group = None
        self._empty = None
        self.discriminator = None

        if assets is not None:
            self.assets = assets
        if relations is not None:
            self.relations = relations
        if valid is not None:
            self.valid = valid
        if asset_group is not None:
            self.asset_group = asset_group
        if empty is not None:
            self.empty = empty

    @property
    def assets(self):
        """Gets the assets of this DeleteGroupResponse.  # noqa: E501


        :return: The assets of this DeleteGroupResponse.  # noqa: E501
        :rtype: list[str]
        """
        return self._assets

    @assets.setter
    def assets(self, assets):
        """Sets the assets of this DeleteGroupResponse.


        :param assets: The assets of this DeleteGroupResponse.  # noqa: E501
        :type: list[str]
        """

        self._assets = assets

    @property
    def relations(self):
        """Gets the relations of this DeleteGroupResponse.  # noqa: E501


        :return: The relations of this DeleteGroupResponse.  # noqa: E501
        :rtype: list[str]
        """
        return self._relations

    @relations.setter
    def relations(self, relations):
        """Sets the relations of this DeleteGroupResponse.


        :param relations: The relations of this DeleteGroupResponse.  # noqa: E501
        :type: list[str]
        """

        self._relations = relations

    @property
    def valid(self):
        """Gets the valid of this DeleteGroupResponse.  # noqa: E501


        :return: The valid of this DeleteGroupResponse.  # noqa: E501
        :rtype: bool
        """
        return self._valid

    @valid.setter
    def valid(self, valid):
        """Sets the valid of this DeleteGroupResponse.


        :param valid: The valid of this DeleteGroupResponse.  # noqa: E501
        :type: bool
        """

        self._valid = valid

    @property
    def asset_group(self):
        """Gets the asset_group of this DeleteGroupResponse.  # noqa: E501


        :return: The asset_group of this DeleteGroupResponse.  # noqa: E501
        :rtype: str
        """
        return self._asset_group

    @asset_group.setter
    def asset_group(self, asset_group):
        """Sets the asset_group of this DeleteGroupResponse.


        :param asset_group: The asset_group of this DeleteGroupResponse.  # noqa: E501
        :type: str
        """

        self._asset_group = asset_group

    @property
    def empty(self):
        """Gets the empty of this DeleteGroupResponse.  # noqa: E501


        :return: The empty of this DeleteGroupResponse.  # noqa: E501
        :rtype: bool
        """
        return self._empty

    @empty.setter
    def empty(self, empty):
        """Sets the empty of this DeleteGroupResponse.


        :param empty: The empty of this DeleteGroupResponse.  # noqa: E501
        :type: bool
        """

        self._empty = empty

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
        if not isinstance(other, DeleteGroupResponse):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DeleteGroupResponse):
            return True

        return self.to_dict() != other.to_dict()
