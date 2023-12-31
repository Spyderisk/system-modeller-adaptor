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


class MisbehaviourSet(object):
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
        'misbehaviour': 'str',
        'misbehaviour_label': 'str',
        'asset': 'str',
        'asset_label': 'str',
        'visible': 'bool',
        'impact_level': 'Level',
        'likelihood': 'Level',
        'risk_level': 'Level',
        'impact_level_asserted': 'bool',
        'direct_causes': 'list[str]',
        'indirect_causes': 'list[str]',
        'root_causes': 'list[str]',
        'direct_effects': 'list[str]',
        'id': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'label': 'label',
        'description': 'description',
        'parents': 'parents',
        'misbehaviour': 'misbehaviour',
        'misbehaviour_label': 'misbehaviourLabel',
        'asset': 'asset',
        'asset_label': 'assetLabel',
        'visible': 'visible',
        'impact_level': 'impactLevel',
        'likelihood': 'likelihood',
        'risk_level': 'riskLevel',
        'impact_level_asserted': 'impactLevelAsserted',
        'direct_causes': 'directCauses',
        'indirect_causes': 'indirectCauses',
        'root_causes': 'rootCauses',
        'direct_effects': 'directEffects',
        'id': 'id'
    }

    def __init__(self, uri=None, label=None, description=None, parents=None, misbehaviour=None, misbehaviour_label=None, asset=None, asset_label=None, visible=None, impact_level=None, likelihood=None, risk_level=None, impact_level_asserted=None, direct_causes=None, indirect_causes=None, root_causes=None, direct_effects=None, id=None, local_vars_configuration=None):  # noqa: E501
        """MisbehaviourSet - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._uri = None
        self._label = None
        self._description = None
        self._parents = None
        self._misbehaviour = None
        self._misbehaviour_label = None
        self._asset = None
        self._asset_label = None
        self._visible = None
        self._impact_level = None
        self._likelihood = None
        self._risk_level = None
        self._impact_level_asserted = None
        self._direct_causes = None
        self._indirect_causes = None
        self._root_causes = None
        self._direct_effects = None
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
        if misbehaviour is not None:
            self.misbehaviour = misbehaviour
        if misbehaviour_label is not None:
            self.misbehaviour_label = misbehaviour_label
        if asset is not None:
            self.asset = asset
        if asset_label is not None:
            self.asset_label = asset_label
        if visible is not None:
            self.visible = visible
        if impact_level is not None:
            self.impact_level = impact_level
        if likelihood is not None:
            self.likelihood = likelihood
        if risk_level is not None:
            self.risk_level = risk_level
        if impact_level_asserted is not None:
            self.impact_level_asserted = impact_level_asserted
        if direct_causes is not None:
            self.direct_causes = direct_causes
        if indirect_causes is not None:
            self.indirect_causes = indirect_causes
        if root_causes is not None:
            self.root_causes = root_causes
        if direct_effects is not None:
            self.direct_effects = direct_effects
        if id is not None:
            self.id = id

    @property
    def uri(self):
        """Gets the uri of this MisbehaviourSet.  # noqa: E501


        :return: The uri of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this MisbehaviourSet.


        :param uri: The uri of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._uri = uri

    @property
    def label(self):
        """Gets the label of this MisbehaviourSet.  # noqa: E501


        :return: The label of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this MisbehaviourSet.


        :param label: The label of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._label = label

    @property
    def description(self):
        """Gets the description of this MisbehaviourSet.  # noqa: E501


        :return: The description of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this MisbehaviourSet.


        :param description: The description of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def parents(self):
        """Gets the parents of this MisbehaviourSet.  # noqa: E501


        :return: The parents of this MisbehaviourSet.  # noqa: E501
        :rtype: list[str]
        """
        return self._parents

    @parents.setter
    def parents(self, parents):
        """Sets the parents of this MisbehaviourSet.


        :param parents: The parents of this MisbehaviourSet.  # noqa: E501
        :type: list[str]
        """

        self._parents = parents

    @property
    def misbehaviour(self):
        """Gets the misbehaviour of this MisbehaviourSet.  # noqa: E501


        :return: The misbehaviour of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._misbehaviour

    @misbehaviour.setter
    def misbehaviour(self, misbehaviour):
        """Sets the misbehaviour of this MisbehaviourSet.


        :param misbehaviour: The misbehaviour of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._misbehaviour = misbehaviour

    @property
    def misbehaviour_label(self):
        """Gets the misbehaviour_label of this MisbehaviourSet.  # noqa: E501


        :return: The misbehaviour_label of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._misbehaviour_label

    @misbehaviour_label.setter
    def misbehaviour_label(self, misbehaviour_label):
        """Sets the misbehaviour_label of this MisbehaviourSet.


        :param misbehaviour_label: The misbehaviour_label of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._misbehaviour_label = misbehaviour_label

    @property
    def asset(self):
        """Gets the asset of this MisbehaviourSet.  # noqa: E501


        :return: The asset of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._asset

    @asset.setter
    def asset(self, asset):
        """Sets the asset of this MisbehaviourSet.


        :param asset: The asset of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._asset = asset

    @property
    def asset_label(self):
        """Gets the asset_label of this MisbehaviourSet.  # noqa: E501


        :return: The asset_label of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._asset_label

    @asset_label.setter
    def asset_label(self, asset_label):
        """Sets the asset_label of this MisbehaviourSet.


        :param asset_label: The asset_label of this MisbehaviourSet.  # noqa: E501
        :type: str
        """

        self._asset_label = asset_label

    @property
    def visible(self):
        """Gets the visible of this MisbehaviourSet.  # noqa: E501


        :return: The visible of this MisbehaviourSet.  # noqa: E501
        :rtype: bool
        """
        return self._visible

    @visible.setter
    def visible(self, visible):
        """Sets the visible of this MisbehaviourSet.


        :param visible: The visible of this MisbehaviourSet.  # noqa: E501
        :type: bool
        """

        self._visible = visible

    @property
    def impact_level(self):
        """Gets the impact_level of this MisbehaviourSet.  # noqa: E501


        :return: The impact_level of this MisbehaviourSet.  # noqa: E501
        :rtype: Level
        """
        return self._impact_level

    @impact_level.setter
    def impact_level(self, impact_level):
        """Sets the impact_level of this MisbehaviourSet.


        :param impact_level: The impact_level of this MisbehaviourSet.  # noqa: E501
        :type: Level
        """

        self._impact_level = impact_level

    @property
    def likelihood(self):
        """Gets the likelihood of this MisbehaviourSet.  # noqa: E501


        :return: The likelihood of this MisbehaviourSet.  # noqa: E501
        :rtype: Level
        """
        return self._likelihood

    @likelihood.setter
    def likelihood(self, likelihood):
        """Sets the likelihood of this MisbehaviourSet.


        :param likelihood: The likelihood of this MisbehaviourSet.  # noqa: E501
        :type: Level
        """

        self._likelihood = likelihood

    @property
    def risk_level(self):
        """Gets the risk_level of this MisbehaviourSet.  # noqa: E501


        :return: The risk_level of this MisbehaviourSet.  # noqa: E501
        :rtype: Level
        """
        return self._risk_level

    @risk_level.setter
    def risk_level(self, risk_level):
        """Sets the risk_level of this MisbehaviourSet.


        :param risk_level: The risk_level of this MisbehaviourSet.  # noqa: E501
        :type: Level
        """

        self._risk_level = risk_level

    @property
    def impact_level_asserted(self):
        """Gets the impact_level_asserted of this MisbehaviourSet.  # noqa: E501


        :return: The impact_level_asserted of this MisbehaviourSet.  # noqa: E501
        :rtype: bool
        """
        return self._impact_level_asserted

    @impact_level_asserted.setter
    def impact_level_asserted(self, impact_level_asserted):
        """Sets the impact_level_asserted of this MisbehaviourSet.


        :param impact_level_asserted: The impact_level_asserted of this MisbehaviourSet.  # noqa: E501
        :type: bool
        """

        self._impact_level_asserted = impact_level_asserted

    @property
    def direct_causes(self):
        """Gets the direct_causes of this MisbehaviourSet.  # noqa: E501


        :return: The direct_causes of this MisbehaviourSet.  # noqa: E501
        :rtype: list[str]
        """
        return self._direct_causes

    @direct_causes.setter
    def direct_causes(self, direct_causes):
        """Sets the direct_causes of this MisbehaviourSet.


        :param direct_causes: The direct_causes of this MisbehaviourSet.  # noqa: E501
        :type: list[str]
        """

        self._direct_causes = direct_causes

    @property
    def indirect_causes(self):
        """Gets the indirect_causes of this MisbehaviourSet.  # noqa: E501


        :return: The indirect_causes of this MisbehaviourSet.  # noqa: E501
        :rtype: list[str]
        """
        return self._indirect_causes

    @indirect_causes.setter
    def indirect_causes(self, indirect_causes):
        """Sets the indirect_causes of this MisbehaviourSet.


        :param indirect_causes: The indirect_causes of this MisbehaviourSet.  # noqa: E501
        :type: list[str]
        """

        self._indirect_causes = indirect_causes

    @property
    def root_causes(self):
        """Gets the root_causes of this MisbehaviourSet.  # noqa: E501


        :return: The root_causes of this MisbehaviourSet.  # noqa: E501
        :rtype: list[str]
        """
        return self._root_causes

    @root_causes.setter
    def root_causes(self, root_causes):
        """Sets the root_causes of this MisbehaviourSet.


        :param root_causes: The root_causes of this MisbehaviourSet.  # noqa: E501
        :type: list[str]
        """

        self._root_causes = root_causes

    @property
    def direct_effects(self):
        """Gets the direct_effects of this MisbehaviourSet.  # noqa: E501


        :return: The direct_effects of this MisbehaviourSet.  # noqa: E501
        :rtype: list[str]
        """
        return self._direct_effects

    @direct_effects.setter
    def direct_effects(self, direct_effects):
        """Sets the direct_effects of this MisbehaviourSet.


        :param direct_effects: The direct_effects of this MisbehaviourSet.  # noqa: E501
        :type: list[str]
        """

        self._direct_effects = direct_effects

    @property
    def id(self):
        """Gets the id of this MisbehaviourSet.  # noqa: E501


        :return: The id of this MisbehaviourSet.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this MisbehaviourSet.


        :param id: The id of this MisbehaviourSet.  # noqa: E501
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
        if not isinstance(other, MisbehaviourSet):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, MisbehaviourSet):
            return True

        return self.to_dict() != other.to_dict()
