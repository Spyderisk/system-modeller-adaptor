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


class Progress(object):
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
        'model_id': 'str',
        'progress': 'float',
        'message': 'str',
        'status': 'str',
        'error': 'str'
    }

    attribute_map = {
        'model_id': 'modelId',
        'progress': 'progress',
        'message': 'message',
        'status': 'status',
        'error': 'error'
    }

    def __init__(self, model_id=None, progress=None, message=None, status=None, error=None, local_vars_configuration=None):  # noqa: E501
        """Progress - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._model_id = None
        self._progress = None
        self._message = None
        self._status = None
        self._error = None
        self.discriminator = None

        if model_id is not None:
            self.model_id = model_id
        if progress is not None:
            self.progress = progress
        if message is not None:
            self.message = message
        if status is not None:
            self.status = status
        if error is not None:
            self.error = error

    @property
    def model_id(self):
        """Gets the model_id of this Progress.  # noqa: E501


        :return: The model_id of this Progress.  # noqa: E501
        :rtype: str
        """
        return self._model_id

    @model_id.setter
    def model_id(self, model_id):
        """Sets the model_id of this Progress.


        :param model_id: The model_id of this Progress.  # noqa: E501
        :type: str
        """

        self._model_id = model_id

    @property
    def progress(self):
        """Gets the progress of this Progress.  # noqa: E501


        :return: The progress of this Progress.  # noqa: E501
        :rtype: float
        """
        return self._progress

    @progress.setter
    def progress(self, progress):
        """Sets the progress of this Progress.


        :param progress: The progress of this Progress.  # noqa: E501
        :type: float
        """

        self._progress = progress

    @property
    def message(self):
        """Gets the message of this Progress.  # noqa: E501


        :return: The message of this Progress.  # noqa: E501
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """Sets the message of this Progress.


        :param message: The message of this Progress.  # noqa: E501
        :type: str
        """

        self._message = message

    @property
    def status(self):
        """Gets the status of this Progress.  # noqa: E501


        :return: The status of this Progress.  # noqa: E501
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this Progress.


        :param status: The status of this Progress.  # noqa: E501
        :type: str
        """

        self._status = status

    @property
    def error(self):
        """Gets the error of this Progress.  # noqa: E501


        :return: The error of this Progress.  # noqa: E501
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error):
        """Sets the error of this Progress.


        :param error: The error of this Progress.  # noqa: E501
        :type: str
        """

        self._error = error

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
        if not isinstance(other, Progress):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, Progress):
            return True

        return self.to_dict() != other.to_dict()
