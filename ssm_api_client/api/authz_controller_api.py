# coding: utf-8

"""
    OpenAPI definition

    SPYDERISK System Modeller (SSM) REST API definitions for domain models, user system models and usage by other applications.  # noqa: E501

    The version of the OpenAPI document: v3.4.0
    Contact: info@spyderisk.com
    Generated by: https://openapi-generator.tech
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from ssm_api_client.api_client import ApiClient
from ssm_api_client.exceptions import (  # noqa: F401
    ApiTypeError,
    ApiValueError
)


class AuthzControllerApi(object):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def get_authz(self, model_id, **kwargs):  # noqa: E501
        """get_authz  # noqa: E501

        REST method to GET the authzDTO for a model if user has owner permissions or is using an   owner web key  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_authz(model_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool: execute request asynchronously
        :param str model_id: (required)
        :param _preload_content: if False, the urllib3.HTTPResponse object will
                                 be returned without reading/decoding response
                                 data. Default is True.
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: AuthzDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        return self.get_authz_with_http_info(model_id, **kwargs)  # noqa: E501

    def get_authz_with_http_info(self, model_id, **kwargs):  # noqa: E501
        """get_authz  # noqa: E501

        REST method to GET the authzDTO for a model if user has owner permissions or is using an   owner web key  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_authz_with_http_info(model_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool: execute request asynchronously
        :param str model_id: (required)
        :param _return_http_data_only: response data without head status code
                                       and headers
        :param _preload_content: if False, the urllib3.HTTPResponse object will
                                 be returned without reading/decoding response
                                 data. Default is True.
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: tuple(AuthzDTO, status_code(int), headers(HTTPHeaderDict))
                 If the method is called asynchronously,
                 returns the request thread.
        """

        local_var_params = locals()

        all_params = [
            'model_id'
        ]
        all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout'
            ]
        )

        for key, val in six.iteritems(local_var_params['kwargs']):
            if key not in all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method get_authz" % key
                )
            local_var_params[key] = val
        del local_var_params['kwargs']
        # verify the required parameter 'model_id' is set
        if self.api_client.client_side_validation and ('model_id' not in local_var_params or  # noqa: E501
                                                        local_var_params['model_id'] is None):  # noqa: E501
            raise ApiValueError("Missing the required parameter `model_id` when calling `get_authz`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'model_id' in local_var_params:
            path_params['modelId'] = local_var_params['model_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['*/*'])  # noqa: E501

        # Authentication setting
        auth_settings = []  # noqa: E501

        return self.api_client.call_api(
            '/models/{modelId}/authz', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='AuthzDTO',  # noqa: E501
            auth_settings=auth_settings,
            async_req=local_var_params.get('async_req'),
            _return_http_data_only=local_var_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=local_var_params.get('_preload_content', True),
            _request_timeout=local_var_params.get('_request_timeout'),
            collection_formats=collection_formats)

    def update_authz(self, model_id, authz_dto, **kwargs):  # noqa: E501
        """update_authz  # noqa: E501

        REST method to PUT authzDTO object, saving it in MongoDB for a model   if user has owner permissions or is using an owner web key  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_authz(model_id, authz_dto, async_req=True)
        >>> result = thread.get()

        :param async_req bool: execute request asynchronously
        :param str model_id: (required)
        :param AuthzDTO authz_dto: (required)
        :param _preload_content: if False, the urllib3.HTTPResponse object will
                                 be returned without reading/decoding response
                                 data. Default is True.
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: str
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        return self.update_authz_with_http_info(model_id, authz_dto, **kwargs)  # noqa: E501

    def update_authz_with_http_info(self, model_id, authz_dto, **kwargs):  # noqa: E501
        """update_authz  # noqa: E501

        REST method to PUT authzDTO object, saving it in MongoDB for a model   if user has owner permissions or is using an owner web key  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_authz_with_http_info(model_id, authz_dto, async_req=True)
        >>> result = thread.get()

        :param async_req bool: execute request asynchronously
        :param str model_id: (required)
        :param AuthzDTO authz_dto: (required)
        :param _return_http_data_only: response data without head status code
                                       and headers
        :param _preload_content: if False, the urllib3.HTTPResponse object will
                                 be returned without reading/decoding response
                                 data. Default is True.
        :param _request_timeout: timeout setting for this request. If one
                                 number provided, it will be total request
                                 timeout. It can also be a pair (tuple) of
                                 (connection, read) timeouts.
        :return: tuple(str, status_code(int), headers(HTTPHeaderDict))
                 If the method is called asynchronously,
                 returns the request thread.
        """

        local_var_params = locals()

        all_params = [
            'model_id',
            'authz_dto'
        ]
        all_params.extend(
            [
                'async_req',
                '_return_http_data_only',
                '_preload_content',
                '_request_timeout'
            ]
        )

        for key, val in six.iteritems(local_var_params['kwargs']):
            if key not in all_params:
                raise ApiTypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method update_authz" % key
                )
            local_var_params[key] = val
        del local_var_params['kwargs']
        # verify the required parameter 'model_id' is set
        if self.api_client.client_side_validation and ('model_id' not in local_var_params or  # noqa: E501
                                                        local_var_params['model_id'] is None):  # noqa: E501
            raise ApiValueError("Missing the required parameter `model_id` when calling `update_authz`")  # noqa: E501
        # verify the required parameter 'authz_dto' is set
        if self.api_client.client_side_validation and ('authz_dto' not in local_var_params or  # noqa: E501
                                                        local_var_params['authz_dto'] is None):  # noqa: E501
            raise ApiValueError("Missing the required parameter `authz_dto` when calling `update_authz`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'model_id' in local_var_params:
            path_params['modelId'] = local_var_params['model_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        if 'authz_dto' in local_var_params:
            body_params = local_var_params['authz_dto']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['*/*'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = []  # noqa: E501

        return self.api_client.call_api(
            '/models/{modelId}/authz', 'PUT',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='str',  # noqa: E501
            auth_settings=auth_settings,
            async_req=local_var_params.get('async_req'),
            _return_http_data_only=local_var_params.get('_return_http_data_only'),  # noqa: E501
            _preload_content=local_var_params.get('_preload_content', True),
            _request_timeout=local_var_params.get('_request_timeout'),
            collection_formats=collection_formats)