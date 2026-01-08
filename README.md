# PHP-KEYCLOAK-CLIENT

A PHP library that can be used to secure web applications with Keycloak. It is typically used in conjunction with RESTful web service APIs.

See also:

 -  [YII2-JWT-AUTH](https://github.com/klsoft-web/yii2-jwt-auth) - The package provides a Yii 2 authentication method based on a JWT token
 -  [YII2-KEYCLOAK-AUTHZ](https://github.com/klsoft-web/yii2-keycloak-authz) - The package provides Keycloak authorization for the web service APIs of Yii 2
 -  [YII3-JWT-AUTH](https://github.com/klsoft-web/yii3-jwt-auth) - The package provides a Yii 3 authentication method based on a JWT token
 -  [YII3-KEYCLOAK-AUTHZ](https://github.com/klsoft-web/yii3-keycloak-authz) - The package provides Keycloak authorization for the web service APIs of Yii 3

## Requirement 

 - PHP 8.1 or higher.

## Installation

```bash
composer require klsoft/php-keycloak-client
```

## Example of initializing a KeycloakClient

```php
use Klsoft\KeycloakClient\KeycloakClient;

$keycloakClient = new KeycloakClient(
    "http://localhost:8080/realms/myrealm", //Keycloak realm URL
    "Keycloak client ID",
    "http://localhost/login", //Keycloak client redirect URI
    "Keycloak client secret"); //This is optional, but it is required when Keycloak 'Client authentication' is ON
```

## Example of creating an Authorization Code flow URL

```php
<a  href="<?=  $keycloakClient->createAuthorizationCodeLoginUrl()  ?>">Login</a>
```

## Example of creating an Implicit flow URL

```php
<a  href="<?=  $keycloakClient->createImplicitLoginUrl()  ?>">Login</a>
```

## Example of obtaining a token using an Authorization Code

```php
$queryParams = $request->getQueryParams();
if (isset($queryParams['code'])) {
    $responseResult = $keycloakClient->getTokenByAuthorizationCode($queryParams['code"']);
    if ($responseResult->responseStatusCode == 200) {
        $data = $responseResult->data;
        $identityData = $this->extractIndentityData($data->id_token);
        $identityRepository->save(new User(
            $identityData->sub, 
            $identityData->preferred_username, 
            $identityData->email, 
            $data->access_token, 
            $data->refresh_token));
        $identity = $identityRepository->findIdentity($identityData->sub)    
        $authManager->login($identity);
    } 
    elseif ($responseResult->responseStatusCode == 401) {
        //Unauthorized
    }
    else {
        //Something got wrong
    }
}
```

## Example of obtaining a token using client credentials

This method can only be used by confidential clients. Make sure that both the **Client authentication** and **Service accounts roles** options are ON in Keycloak

```php
$responseResult = $keycloakClient->getTokenByClientCredentials();
if ($responseResult->responseStatusCode == 200) {
    $data = $responseResult->data;
} 
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```

## Example of refreshing a token

```php
$responseResult = $keycloakClient->refreshToken($authManager->identity->refresh_token);
if ($responseResult->responseStatusCode == 200) {
    $data = $responseResult->data;
    $identityRepository->findIdentity($identityData->sub);
    $identityData = $this->extractIndentityData($data->id_token);
    {
        $data = $responseResult->data;
        $identityData = $this->extractIndentityData(data->id_token);
        $user = $identityRepository->findIdentity($identityData->sub);
        $user->access_token = $data->access_token;
        $user->refresh_token = $data->refresh_token;
        $identityRepository->save($user);
    }
} 
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```

## Example of obtaining a Requesting Party Token using a permission ticket

```php
$responseResult = $keycloakClient->getRequestingPartyTokenByPermissionTicket(
    $authManager->identity->access_token,
    "permission ticket");
if ($responseResult->responseStatusCode == 200) {
    $rpt = $responseResult->data->access_token;
} 
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```

## Example of obtaining a Requesting Party Token by the client ID

```php
$responseResult = $keycloakClient->getRequestingPartyTokenByClientId($authManager->identity->access_token);
if ($responseResult->responseStatusCode == 200) {
    $rpt = $responseResult->data->access_token;
} 
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```

## Example of a logout

```php
$responseResult = $keycloakClient->logout($authManager->identity->refresh_token);
if ($responseResult->responseStatusCode == 204) {
    $authManager->logout();
} 
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```

## Example of obtaining a user information

```php
$responseResult = $keycloakClient->getUserInfo($authManager->identity->access_token);
if ($responseResult->responseStatusCode == 200) {
    $data = $responseResult->data;
}
elseif ($responseResult->responseStatusCode == 401) {
    //Unauthorized
}
else {
    //Something got wrong
}
```
