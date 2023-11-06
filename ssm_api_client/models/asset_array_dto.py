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


class AssetArrayDTO(object):
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
        'assets': 'list[Asset]'
    }

    attribute_map = {
        'assets': 'assets'
    }

    def __init__(self, assets=None, local_vars_configuration=None):  # noqa: E501
        """AssetArrayDTO - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._assets = None
        self.discriminator = None

        if assets is not None:
            self.assets = assets

    @property
    def assets(self):
        """Gets the assets of this AssetArrayDTO.  # noqa: E501


        :return: The assets of this AssetArrayDTO.  # noqa: E501
        :rtype: list[Asset]
        """
        return self._assets

    @assets.setter
    def assets(self, assets):
        """Sets the assets of this AssetArrayDTO.


        :param assets: The assets of this AssetArrayDTO.  # noqa: E501
        :type: list[Asset]
        """

        self._assets = assets

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
        if not isinstance(other, AssetArrayDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AssetArrayDTO):
            return True

        return self.to_dict() != other.to_dict()