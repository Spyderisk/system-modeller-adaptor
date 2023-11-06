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


class AuthzDTO(object):
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
        'read_usernames': 'list[str]',
        'write_usernames': 'list[str]',
        'owner_usernames': 'list[str]',
        'no_role_url': 'str',
        'read_url': 'str',
        'write_url': 'str',
        'owner_url': 'str'
    }

    attribute_map = {
        'read_usernames': 'readUsernames',
        'write_usernames': 'writeUsernames',
        'owner_usernames': 'ownerUsernames',
        'no_role_url': 'noRoleUrl',
        'read_url': 'readUrl',
        'write_url': 'writeUrl',
        'owner_url': 'ownerUrl'
    }

    def __init__(self, read_usernames=None, write_usernames=None, owner_usernames=None, no_role_url=None, read_url=None, write_url=None, owner_url=None, local_vars_configuration=None):  # noqa: E501
        """AuthzDTO - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._read_usernames = None
        self._write_usernames = None
        self._owner_usernames = None
        self._no_role_url = None
        self._read_url = None
        self._write_url = None
        self._owner_url = None
        self.discriminator = None

        if read_usernames is not None:
            self.read_usernames = read_usernames
        if write_usernames is not None:
            self.write_usernames = write_usernames
        if owner_usernames is not None:
            self.owner_usernames = owner_usernames
        if no_role_url is not None:
            self.no_role_url = no_role_url
        if read_url is not None:
            self.read_url = read_url
        if write_url is not None:
            self.write_url = write_url
        if owner_url is not None:
            self.owner_url = owner_url

    @property
    def read_usernames(self):
        """Gets the read_usernames of this AuthzDTO.  # noqa: E501


        :return: The read_usernames of this AuthzDTO.  # noqa: E501
        :rtype: list[str]
        """
        return self._read_usernames

    @read_usernames.setter
    def read_usernames(self, read_usernames):
        """Sets the read_usernames of this AuthzDTO.


        :param read_usernames: The read_usernames of this AuthzDTO.  # noqa: E501
        :type: list[str]
        """

        self._read_usernames = read_usernames

    @property
    def write_usernames(self):
        """Gets the write_usernames of this AuthzDTO.  # noqa: E501


        :return: The write_usernames of this AuthzDTO.  # noqa: E501
        :rtype: list[str]
        """
        return self._write_usernames

    @write_usernames.setter
    def write_usernames(self, write_usernames):
        """Sets the write_usernames of this AuthzDTO.


        :param write_usernames: The write_usernames of this AuthzDTO.  # noqa: E501
        :type: list[str]
        """

        self._write_usernames = write_usernames

    @property
    def owner_usernames(self):
        """Gets the owner_usernames of this AuthzDTO.  # noqa: E501


        :return: The owner_usernames of this AuthzDTO.  # noqa: E501
        :rtype: list[str]
        """
        return self._owner_usernames

    @owner_usernames.setter
    def owner_usernames(self, owner_usernames):
        """Sets the owner_usernames of this AuthzDTO.


        :param owner_usernames: The owner_usernames of this AuthzDTO.  # noqa: E501
        :type: list[str]
        """

        self._owner_usernames = owner_usernames

    @property
    def no_role_url(self):
        """Gets the no_role_url of this AuthzDTO.  # noqa: E501


        :return: The no_role_url of this AuthzDTO.  # noqa: E501
        :rtype: str
        """
        return self._no_role_url

    @no_role_url.setter
    def no_role_url(self, no_role_url):
        """Sets the no_role_url of this AuthzDTO.


        :param no_role_url: The no_role_url of this AuthzDTO.  # noqa: E501
        :type: str
        """

        self._no_role_url = no_role_url

    @property
    def read_url(self):
        """Gets the read_url of this AuthzDTO.  # noqa: E501


        :return: The read_url of this AuthzDTO.  # noqa: E501
        :rtype: str
        """
        return self._read_url

    @read_url.setter
    def read_url(self, read_url):
        """Sets the read_url of this AuthzDTO.


        :param read_url: The read_url of this AuthzDTO.  # noqa: E501
        :type: str
        """

        self._read_url = read_url

    @property
    def write_url(self):
        """Gets the write_url of this AuthzDTO.  # noqa: E501


        :return: The write_url of this AuthzDTO.  # noqa: E501
        :rtype: str
        """
        return self._write_url

    @write_url.setter
    def write_url(self, write_url):
        """Sets the write_url of this AuthzDTO.


        :param write_url: The write_url of this AuthzDTO.  # noqa: E501
        :type: str
        """

        self._write_url = write_url

    @property
    def owner_url(self):
        """Gets the owner_url of this AuthzDTO.  # noqa: E501


        :return: The owner_url of this AuthzDTO.  # noqa: E501
        :rtype: str
        """
        return self._owner_url

    @owner_url.setter
    def owner_url(self, owner_url):
        """Sets the owner_url of this AuthzDTO.


        :param owner_url: The owner_url of this AuthzDTO.  # noqa: E501
        :type: str
        """

        self._owner_url = owner_url

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
        if not isinstance(other, AuthzDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AuthzDTO):
            return True

        return self.to_dict() != other.to_dict()