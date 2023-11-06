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


class AssetGroupDTO(object):
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
        'left': 'str',
        'top': 'str',
        'width': 'int',
        'height': 'int',
        'expanded': 'bool',
        'asset_ids': 'list[object]',
        'name': 'str',
        'id': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'label': 'label',
        'description': 'description',
        'left': 'left',
        'top': 'top',
        'width': 'width',
        'height': 'height',
        'expanded': 'expanded',
        'asset_ids': 'assetIds',
        'name': 'name',
        'id': 'id'
    }

    def __init__(self, uri=None, label=None, description=None, left=None, top=None, width=None, height=None, expanded=None, asset_ids=None, name=None, id=None, local_vars_configuration=None):  # noqa: E501
        """AssetGroupDTO - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._label = None
        self._description = None
        self._left = None
        self._top = None
        self._width = None
        self._height = None
        self._expanded = None
        self._asset_ids = None
        self._name = None
        self._id = None
        self.discriminator = None

        if uri is not None:
            self.uri = uri
        if label is not None:
            self.label = label
        if description is not None:
            self.description = description
        if left is not None:
            self.left = left
        if top is not None:
            self.top = top
        if width is not None:
            self.width = width
        if height is not None:
            self.height = height
        if expanded is not None:
            self.expanded = expanded
        if asset_ids is not None:
            self.asset_ids = asset_ids
        if name is not None:
            self.name = name
        if id is not None:
            self.id = id

    @property
    def uri(self):
        """Gets the uri of this AssetGroupDTO.  # noqa: E501


        :return: The uri of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this AssetGroupDTO.


        :param uri: The uri of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def label(self):
        """Gets the label of this AssetGroupDTO.  # noqa: E501


        :return: The label of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this AssetGroupDTO.


        :param label: The label of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this AssetGroupDTO.  # noqa: E501


        :return: The description of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this AssetGroupDTO.


        :param description: The description of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def left(self):
        """Gets the left of this AssetGroupDTO.  # noqa: E501


        :return: The left of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._left

    @left.setter
    def left(self, left):
        """Sets the left of this AssetGroupDTO.


        :param left: The left of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._left = left

    @property
    def top(self):
        """Gets the top of this AssetGroupDTO.  # noqa: E501


        :return: The top of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._top

    @top.setter
    def top(self, top):
        """Sets the top of this AssetGroupDTO.


        :param top: The top of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._top = top

    @property
    def width(self):
        """Gets the width of this AssetGroupDTO.  # noqa: E501


        :return: The width of this AssetGroupDTO.  # noqa: E501
        :rtype: int
        """
        return self._width

    @width.setter
    def width(self, width):
        """Sets the width of this AssetGroupDTO.


        :param width: The width of this AssetGroupDTO.  # noqa: E501
        :type: int
        """

        self._width = width

    @property
    def height(self):
        """Gets the height of this AssetGroupDTO.  # noqa: E501


        :return: The height of this AssetGroupDTO.  # noqa: E501
        :rtype: int
        """
        return self._height

    @height.setter
    def height(self, height):
        """Sets the height of this AssetGroupDTO.


        :param height: The height of this AssetGroupDTO.  # noqa: E501
        :type: int
        """

        self._height = height

    @property
    def expanded(self):
        """Gets the expanded of this AssetGroupDTO.  # noqa: E501


        :return: The expanded of this AssetGroupDTO.  # noqa: E501
        :rtype: bool
        """
        return self._expanded

    @expanded.setter
    def expanded(self, expanded):
        """Sets the expanded of this AssetGroupDTO.


        :param expanded: The expanded of this AssetGroupDTO.  # noqa: E501
        :type: bool
        """

        self._expanded = expanded

    @property
    def asset_ids(self):
        """Gets the asset_ids of this AssetGroupDTO.  # noqa: E501


        :return: The asset_ids of this AssetGroupDTO.  # noqa: E501
        :rtype: list[object]
        """
        return self._asset_ids

    @asset_ids.setter
    def asset_ids(self, asset_ids):
        """Sets the asset_ids of this AssetGroupDTO.


        :param asset_ids: The asset_ids of this AssetGroupDTO.  # noqa: E501
        :type: list[object]
        """

        self._asset_ids = asset_ids

    @property
    def name(self):
        """Gets the name of this AssetGroupDTO.  # noqa: E501


        :return: The name of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this AssetGroupDTO.


        :param name: The name of this AssetGroupDTO.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def id(self):
        """Gets the id of this AssetGroupDTO.  # noqa: E501


        :return: The id of this AssetGroupDTO.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this AssetGroupDTO.


        :param id: The id of this AssetGroupDTO.  # noqa: E501
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
        if not isinstance(other, AssetGroupDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AssetGroupDTO):
            return True

        return self.to_dict() != other.to_dict()
