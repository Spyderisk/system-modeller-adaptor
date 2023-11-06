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


class ControlStrategyDB(object):
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
        'parent': 'str',
        'blocking_effect': 'str',
        'coverage_level': 'str',
        'control_sets': 'list[str]',
        'mandatory_cs': 'list[str]',
        'optional_cs': 'list[str]',
        'blocks': 'list[str]',
        'mitigates': 'list[str]',
        'triggers': 'list[str]',
        'current_risk': 'bool',
        'future_risk': 'bool',
        'enabled': 'bool',
        'min_of': 'str',
        'max_of': 'str',
        'has_min': 'str',
        'has_max': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'type': 'type',
        'id': 'id',
        'label': 'label',
        'description': 'description',
        'parent': 'parent',
        'blocking_effect': 'blockingEffect',
        'coverage_level': 'coverageLevel',
        'control_sets': 'controlSets',
        'mandatory_cs': 'mandatoryCS',
        'optional_cs': 'optionalCS',
        'blocks': 'blocks',
        'mitigates': 'mitigates',
        'triggers': 'triggers',
        'current_risk': 'currentRisk',
        'future_risk': 'futureRisk',
        'enabled': 'enabled',
        'min_of': 'minOf',
        'max_of': 'maxOf',
        'has_min': 'hasMin',
        'has_max': 'hasMax'
    }

    def __init__(self, uri=None, type=None, id=None, label=None, description=None, parent=None, blocking_effect=None, coverage_level=None, control_sets=None, mandatory_cs=None, optional_cs=None, blocks=None, mitigates=None, triggers=None, current_risk=None, future_risk=None, enabled=None, min_of=None, max_of=None, has_min=None, has_max=None, local_vars_configuration=None):  # noqa: E501
        """ControlStrategyDB - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._type = None
        self._id = None
        self._label = None
        self._description = None
        self._parent = None
        self._blocking_effect = None
        self._coverage_level = None
        self._control_sets = None
        self._mandatory_cs = None
        self._optional_cs = None
        self._blocks = None
        self._mitigates = None
        self._triggers = None
        self._current_risk = None
        self._future_risk = None
        self._enabled = None
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
        if label is not None:
            self.label = label
        if description is not None:
            self.description = description
        if parent is not None:
            self.parent = parent
        if blocking_effect is not None:
            self.blocking_effect = blocking_effect
        if coverage_level is not None:
            self.coverage_level = coverage_level
        if control_sets is not None:
            self.control_sets = control_sets
        if mandatory_cs is not None:
            self.mandatory_cs = mandatory_cs
        if optional_cs is not None:
            self.optional_cs = optional_cs
        if blocks is not None:
            self.blocks = blocks
        if mitigates is not None:
            self.mitigates = mitigates
        if triggers is not None:
            self.triggers = triggers
        if current_risk is not None:
            self.current_risk = current_risk
        if future_risk is not None:
            self.future_risk = future_risk
        if enabled is not None:
            self.enabled = enabled
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
        """Gets the uri of this ControlStrategyDB.  # noqa: E501


        :return: The uri of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this ControlStrategyDB.


        :param uri: The uri of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def type(self):
        """Gets the type of this ControlStrategyDB.  # noqa: E501


        :return: The type of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this ControlStrategyDB.


        :param type: The type of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def id(self):
        """Gets the id of this ControlStrategyDB.  # noqa: E501


        :return: The id of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ControlStrategyDB.


        :param id: The id of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def label(self):
        """Gets the label of this ControlStrategyDB.  # noqa: E501


        :return: The label of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this ControlStrategyDB.


        :param label: The label of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this ControlStrategyDB.  # noqa: E501


        :return: The description of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this ControlStrategyDB.


        :param description: The description of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def parent(self):
        """Gets the parent of this ControlStrategyDB.  # noqa: E501


        :return: The parent of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._parent

    @parent.setter
    def parent(self, parent):
        """Sets the parent of this ControlStrategyDB.


        :param parent: The parent of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._parent = parent

    @property
    def blocking_effect(self):
        """Gets the blocking_effect of this ControlStrategyDB.  # noqa: E501


        :return: The blocking_effect of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._blocking_effect

    @blocking_effect.setter
    def blocking_effect(self, blocking_effect):
        """Sets the blocking_effect of this ControlStrategyDB.


        :param blocking_effect: The blocking_effect of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._blocking_effect = blocking_effect

    @property
    def coverage_level(self):
        """Gets the coverage_level of this ControlStrategyDB.  # noqa: E501


        :return: The coverage_level of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._coverage_level

    @coverage_level.setter
    def coverage_level(self, coverage_level):
        """Sets the coverage_level of this ControlStrategyDB.


        :param coverage_level: The coverage_level of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._coverage_level = coverage_level

    @property
    def control_sets(self):
        """Gets the control_sets of this ControlStrategyDB.  # noqa: E501


        :return: The control_sets of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._control_sets

    @control_sets.setter
    def control_sets(self, control_sets):
        """Sets the control_sets of this ControlStrategyDB.


        :param control_sets: The control_sets of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._control_sets = control_sets

    @property
    def mandatory_cs(self):
        """Gets the mandatory_cs of this ControlStrategyDB.  # noqa: E501


        :return: The mandatory_cs of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._mandatory_cs

    @mandatory_cs.setter
    def mandatory_cs(self, mandatory_cs):
        """Sets the mandatory_cs of this ControlStrategyDB.


        :param mandatory_cs: The mandatory_cs of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._mandatory_cs = mandatory_cs

    @property
    def optional_cs(self):
        """Gets the optional_cs of this ControlStrategyDB.  # noqa: E501


        :return: The optional_cs of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._optional_cs

    @optional_cs.setter
    def optional_cs(self, optional_cs):
        """Sets the optional_cs of this ControlStrategyDB.


        :param optional_cs: The optional_cs of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._optional_cs = optional_cs

    @property
    def blocks(self):
        """Gets the blocks of this ControlStrategyDB.  # noqa: E501


        :return: The blocks of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._blocks

    @blocks.setter
    def blocks(self, blocks):
        """Sets the blocks of this ControlStrategyDB.


        :param blocks: The blocks of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._blocks = blocks

    @property
    def mitigates(self):
        """Gets the mitigates of this ControlStrategyDB.  # noqa: E501


        :return: The mitigates of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._mitigates

    @mitigates.setter
    def mitigates(self, mitigates):
        """Sets the mitigates of this ControlStrategyDB.


        :param mitigates: The mitigates of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._mitigates = mitigates

    @property
    def triggers(self):
        """Gets the triggers of this ControlStrategyDB.  # noqa: E501


        :return: The triggers of this ControlStrategyDB.  # noqa: E501
        :rtype: list[str]
        """
        return self._triggers

    @triggers.setter
    def triggers(self, triggers):
        """Sets the triggers of this ControlStrategyDB.


        :param triggers: The triggers of this ControlStrategyDB.  # noqa: E501
        :type: list[str]
        """

        self._triggers = triggers

    @property
    def current_risk(self):
        """Gets the current_risk of this ControlStrategyDB.  # noqa: E501


        :return: The current_risk of this ControlStrategyDB.  # noqa: E501
        :rtype: bool
        """
        return self._current_risk

    @current_risk.setter
    def current_risk(self, current_risk):
        """Sets the current_risk of this ControlStrategyDB.


        :param current_risk: The current_risk of this ControlStrategyDB.  # noqa: E501
        :type: bool
        """

        self._current_risk = current_risk

    @property
    def future_risk(self):
        """Gets the future_risk of this ControlStrategyDB.  # noqa: E501


        :return: The future_risk of this ControlStrategyDB.  # noqa: E501
        :rtype: bool
        """
        return self._future_risk

    @future_risk.setter
    def future_risk(self, future_risk):
        """Sets the future_risk of this ControlStrategyDB.


        :param future_risk: The future_risk of this ControlStrategyDB.  # noqa: E501
        :type: bool
        """

        self._future_risk = future_risk

    @property
    def enabled(self):
        """Gets the enabled of this ControlStrategyDB.  # noqa: E501


        :return: The enabled of this ControlStrategyDB.  # noqa: E501
        :rtype: bool
        """
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Sets the enabled of this ControlStrategyDB.


        :param enabled: The enabled of this ControlStrategyDB.  # noqa: E501
        :type: bool
        """

        self._enabled = enabled

    @property
    def min_of(self):
        """Gets the min_of of this ControlStrategyDB.  # noqa: E501


        :return: The min_of of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._min_of

    @min_of.setter
    def min_of(self, min_of):
        """Sets the min_of of this ControlStrategyDB.


        :param min_of: The min_of of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._min_of = min_of

    @property
    def max_of(self):
        """Gets the max_of of this ControlStrategyDB.  # noqa: E501


        :return: The max_of of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._max_of

    @max_of.setter
    def max_of(self, max_of):
        """Sets the max_of of this ControlStrategyDB.


        :param max_of: The max_of of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._max_of = max_of

    @property
    def has_min(self):
        """Gets the has_min of this ControlStrategyDB.  # noqa: E501


        :return: The has_min of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._has_min

    @has_min.setter
    def has_min(self, has_min):
        """Sets the has_min of this ControlStrategyDB.


        :param has_min: The has_min of this ControlStrategyDB.  # noqa: E501
        :type: str
        """

        self._has_min = has_min

    @property
    def has_max(self):
        """Gets the has_max of this ControlStrategyDB.  # noqa: E501


        :return: The has_max of this ControlStrategyDB.  # noqa: E501
        :rtype: str
        """
        return self._has_max

    @has_max.setter
    def has_max(self, has_max):
        """Sets the has_max of this ControlStrategyDB.


        :param has_max: The has_max of this ControlStrategyDB.  # noqa: E501
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
        if not isinstance(other, ControlStrategyDB):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ControlStrategyDB):
            return True

        return self.to_dict() != other.to_dict()
