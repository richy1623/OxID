# \UserApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**user_create**](UserApi.md#user_create) | **POST** /user | Create a new user
[**user_fetch**](UserApi.md#user_fetch) | **GET** /user/{userId} | Fetch user details
[**user_login**](UserApi.md#user_login) | **POST** /auth/login | User login
[**user_refresh_login**](UserApi.md#user_refresh_login) | **POST** /auth/login/refresh | Refresh login tokens



## user_create

> models::User user_create(create_user_request)
Create a new user

Registers a new user account with the system. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**create_user_request** | [**CreateUserRequest**](CreateUserRequest.md) | User registration payload | [required] |

### Return type

[**models::User**](User.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## user_fetch

> models::User user_fetch(user_id)
Fetch user details

Retrieves user profile information for the specified user ID. Requires a valid JWT access token. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **uuid::Uuid** | Unique identifier of the user | [required] |

### Return type

[**models::User**](User.md)

### Authorization

[JwtAuth](../README.md#JwtAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## user_login

> models::LoginToken user_login(user_login_request)
User login

Authenticates a user using email and password. Returns a short-lived access token and a long-lived refresh token. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_login_request** | [**UserLoginRequest**](UserLoginRequest.md) | Login credentials | [required] |

### Return type

[**models::LoginToken**](LoginToken.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## user_refresh_login

> models::LoginToken user_refresh_login(user_refresh_login_request)
Refresh login tokens

Issues a new access token and refresh token using a valid refresh token. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_refresh_login_request** | [**UserRefreshLoginRequest**](UserRefreshLoginRequest.md) | Refresh token payload | [required] |

### Return type

[**models::LoginToken**](LoginToken.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

