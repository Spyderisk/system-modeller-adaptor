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


class ControlStrategyDTO(object):
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
        'blocking_effect': 'Level',
        'enabled': 'bool',
        'mandatory_control_sets': 'list[str]',
        'optional_control_sets': 'list[str]',
        'threat_csg_types': 'dict(str, str)',
        'id': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'label': 'label',
        'description': 'description',
        'blocking_effect': 'blockingEffect',
        'enabled': 'enabled',
        'mandatory_control_sets': 'mandatoryControlSets',
        'optional_control_sets': 'optionalControlSets',
        'threat_csg_types': 'threatCsgTypes',
        'id': 'id'
    }

    def __init__(self, uri=None, label=None, description=None, blocking_effect=None, enabled=None, mandatory_control_sets=None, optional_control_sets=None, threat_csg_types=None, id=None, local_vars_configuration=None):  # noqa: E501
        """ControlStrategyDTO - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._label = None
        self._description = None
        self._blocking_effect = None
        self._enabled = None
        self._mandatory_control_sets = None
        self._optional_control_sets = None
        self._threat_csg_types = None
        self._id = None
        self.discriminator = None

        if uri is not None:
            self.uri = uri
        if label is not None:
            self.label = label
        if description is not None:
            self.description = description
        if blocking_effect is not None:
            self.blocking_effect = blocking_effect
        if enabled is not None:
            self.enabled = enabled
        if mandatory_control_sets is not None:
            self.mandatory_control_sets = mandatory_control_sets
        if optional_control_sets is not None:
            self.optional_control_sets = optional_control_sets
        if threat_csg_types is not None:
            self.threat_csg_types = threat_csg_types
        if id is not None:
            self.id = id

    @property
    def uri(self):
        """Gets the uri of this ControlStrategyDTO.  # noqa: E501


        :return: The uri of this ControlStrategyDTO.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this ControlStrategyDTO.


        :param uri: The uri of this ControlStrategyDTO.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def label(self):
        """Gets the label of this ControlStrategyDTO.  # noqa: E501


        :return: The label of this ControlStrategyDTO.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this ControlStrategyDTO.


        :param label: The label of this ControlStrategyDTO.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this ControlStrategyDTO.  # noqa: E501


        :return: The description of this ControlStrategyDTO.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this ControlStrategyDTO.


        :param description: The description of this ControlStrategyDTO.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def blocking_effect(self):
        """Gets the blocking_effect of this ControlStrategyDTO.  # noqa: E501


        :return: The blocking_effect of this ControlStrategyDTO.  # noqa: E501
        :rtype: Level
        """
        return self._blocking_effect

    @blocking_effect.setter
    def blocking_effect(self, blocking_effect):
        """Sets the blocking_effect of this ControlStrategyDTO.


        :param blocking_effect: The blocking_effect of this ControlStrategyDTO.  # noqa: E501
        :type: Level
        """

        self._blocking_effect = blocking_effect

    @property
    def enabled(self):
        """Gets the enabled of this ControlStrategyDTO.  # noqa: E501


        :return: The enabled of this ControlStrategyDTO.  # noqa: E501
        :rtype: bool
        """
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Sets the enabled of this ControlStrategyDTO.


        :param enabled: The enabled of this ControlStrategyDTO.  # noqa: E501
        :type: bool
        """

        self._enabled = enabled

    @property
    def mandatory_control_sets(self):
        """Gets the mandatory_control_sets of this ControlStrategyDTO.  # noqa: E501


        :return: The mandatory_control_sets of this ControlStrategyDTO.  # noqa: E501
        :rtype: list[str]
        """
        return self._mandatory_control_sets

    @mandatory_control_sets.setter
    def mandatory_control_sets(self, mandatory_control_sets):
        """Sets the mandatory_control_sets of this ControlStrategyDTO.


        :param mandatory_control_sets: The mandatory_control_sets of this ControlStrategyDTO.  # noqa: E501
        :type: list[str]
        """

        self._mandatory_control_sets = mandatory_control_sets

    @property
    def optional_control_sets(self):
        """Gets the optional_control_sets of this ControlStrategyDTO.  # noqa: E501


        :return: The optional_control_sets of this ControlStrategyDTO.  # noqa: E501
        :rtype: list[str]
        """
        return self._optional_control_sets

    @optional_control_sets.setter
    def optional_control_sets(self, optional_control_sets):
        """Sets the optional_control_sets of this ControlStrategyDTO.


        :param optional_control_sets: The optional_control_sets of this ControlStrategyDTO.  # noqa: E501
        :type: list[str]
        """

        self._optional_control_sets = optional_control_sets

    @property
    def threat_csg_types(self):
        """Gets the threat_csg_types of this ControlStrategyDTO.  # noqa: E501


        :return: The threat_csg_types of this ControlStrategyDTO.  # noqa: E501
        :rtype: dict(str, str)
        """
        return self._threat_csg_types

    @threat_csg_types.setter
    def threat_csg_types(self, threat_csg_types):
        """Sets the threat_csg_types of this ControlStrategyDTO.


        :param threat_csg_types: The threat_csg_types of this ControlStrategyDTO.  # noqa: E501
        :type: dict(str, str)
        """
        allowed_values = ["BLOCK", "MITIGATE", "TRIGGER"]  # noqa: E501
        if (self.local_vars_configuration.client_side_validation and
                not set(threat_csg_types.values()).issubset(set(allowed_values))):  # noqa: E501
            raise ValueError(
                "Invalid values in `threat_csg_types` [{0}], must be a subset of [{1}]"  # noqa: E501
                .format(", ".join(map(str, set(threat_csg_types.values()) - set(allowed_values))),  # noqa: E501
                        ", ".join(map(str, allowed_values)))
            )

        self._threat_csg_types = threat_csg_types

    @property
    def id(self):
        """Gets the id of this ControlStrategyDTO.  # noqa: E501


        :return: The id of this ControlStrategyDTO.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ControlStrategyDTO.


        :param id: The id of this ControlStrategyDTO.  # noqa: E501
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
        if not isinstance(other, ControlStrategyDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ControlStrategyDTO):
            return True

        return self.to_dict() != other.to_dict()
