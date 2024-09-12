# Virgil Core SDK PHP

[![Build Status](https://github.com/VirgilSecurity/virgil-sdk-php/actions/workflows/build.yml/badge.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-sdk-php)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/virgil/sdk.svg?style=flat-square)](https://packagist.org/packages/virgil/sdk)
[![Total Downloads](https://img.shields.io/packagist/dt/virgil/sdk.svg?style=flat-square)](https://packagist.org/packages/virgil/sdk.svg)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Configure SDK](#configure-sdk) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communications, securely store data, and ensure data integrity. Virgil Security products are available for desktop, embedded (IoT), mobile, cloud, and web applications in a variety of modern programming languages.

The Virgil Core SDK is a low-level library that allows developers to get up and running with [Virgil Cards Service API](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/) quickly and add end-to-end security to their new or existing digital solutions.

In case you need additional security functionality for multi-device support, group chats and more, try our high-level [Virgil E3Kit framework](https://github.com/VirgilSecurity/awesome-virgil#E3Kit).

## SDK Features

- Communicate with [Virgil Cards Service](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/)
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use [Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto-php)

## Installation

The Virgil Core SDK is provided as a package named [_virgil/sdk_](https://packagist.org/packages/virgil/sdk). The package is distributed via [Composer package](https://getcomposer.org/doc/) management system.

The package is available for PHP version 8.2 and newer.

Installing the package using Package Manager Console:

```bash
composer require virgil/sdk
```

### Crypto Extensions notice

In order to support crypto operations, you'll also need to install a Virgil crypto extensions. We supply Virgil Core SDK with our own extensions that can be easily used by everyone. To install automatically extensions in your current system just run this command:

```bash
./vendor/virgil/crypto-wrapper/_extensions/setup.sh -all -vendor
```

Be aware that crypto-wrapper package appears in your vendors after virgil/sdk have been installed by composer.
To check Virgil crypto extensions is proper installed run:

```bash
php -m
```

There are should be available following extensions: `vsce_phe_php`, `vscf_foundation_php`, `vscp_pythia_php`

NOTE: If following warning is occurred export environment variable `LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/php7/modules` (/usr/lib/php7/modules - your php extensions path can be other):

```
PHP Warning:  PHP Startup: Unable to load dynamic library 'vsce_phe_php' (tried: /usr/lib/php7/modules/vsce_phe_php (Error loading shared library /usr/lib/php7/modules/vsce_phe_php: No such file or directory), /usr/lib/php7/modules/vsce_phe_php.so (Error loading shared library vscf_foundation_php.so: No such file or directory (needed by /usr/lib/php7/modules/vsce_phe_php.so))) in Unknown on line 0
```

`LD_LIBRARY_PATH` is environment variable which keeps all path that contains users dynamic shared libraries.

Now Virgil Core SDK is ready to be used, lets configure it and run some samples.

## Configure SDK

This section contains guides on how to set up Virgil Core SDK modules for authenticating users, managing Virgil Cards and storing private keys.

### Set up authentication

Set up user authentication with tokens that are based on the [JSON Web Token standard](https://jwt.io/) with some Virgil modifications.

In order to make calls to Virgil Services (for example, to publish user's Card on Virgil Cards Service), you need to have a JSON Web Token ("JWT") that contains the user's `identity`, which is a string that uniquely identifies each user in your application.

Credentials that you'll need:

| Parameter  | Description                                                                                                                                                                                               |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| App ID     | ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)                                                                                                                        |
| App Key ID | A unique string value that identifies your account at the Virgil developer portal                                                                                                                         |
| App Key    | A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the App Key when the key is created. Don't forget to save it in a secure location for the next step |

#### Set up JWT provider on Client side

Use these lines of code to specify which JWT generation source you prefer to use in your project:

```php
use Virgil\Sdk\Web\Authorization\CallbackJwtProvider;
use Virgil\Sdk\Web\Authorization\TokenContext;

$authenticatedQueryToServerSide = function (TokenContext $context){
    // Get generated token from server-side
    return "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak";
};

// Setup AccessTokenProvider
$accessTokenProvider = new CallbackJwtProvider($authenticatedQueryToServerSide);
```

#### Generate JWT on Server side

Next, you'll need to set up the `JwtGenerator` and generate a JWT using the Virgil SDK.

Here is an example of how to generate a JWT:

```php
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Web\Authorization\JwtGenerator;

// App Key (you got this Key at Virgil Dashboard)
$privateKeyStr = "MC4CAQAwBQYDK2VwBCIEIH2RKUdXkK/3tfVWO2AJahOhCYG2hCEHg4mPJEAuvmj7";
$appKeyData = base64_decode($privateKeyStr);

// VirgilCrypto imports a private key into a necessary format
$crypto = new VirgilCrypto();
$privateKey = $crypto->importPrivateKey($appKeyData);

// use your App Credentials you got at Virgil Dashboard:
$appId = "be00e10e4e1f4bf58f9b4dc85d79c77a"; // App ID
$appKeyId = "70b447e321f3a0fd";              // App Key ID
$ttl = 3600; // 1 hour (JWT's lifetime)

// setup JWT generator with necessary parameters:
$jwtGenerator = new JwtGenerator($privateKey->getPrivateKey(), $appKeyId, $crypto, $appId, $ttl);

// generate JWT for a user
// remember that you must provide each user with his unique JWT
// each JWT contains unique user's identity (in this case - Alice)
// identity can be any value: name, email, some id etc.
$identity = "Alice";
$token = $jwtGenerator->generateToken($identity);

// as result you get users JWT, it looks like this: "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak"
// you can provide users with JWT at registration or authorization steps
// Send a JWT to client-side
$token->__toString();
```

For this subsection we've created a sample backend that demonstrates how you can set up your backend to generate the JWTs. To set up and run the sample backend locally, head over to your GitHub repo of choice:

[Node.js](https://github.com/VirgilSecurity/sample-backend-nodejs) | [Golang](https://github.com/VirgilSecurity/sample-backend-go) | [PHP](https://github.com/VirgilSecurity/sample-backend-php) | [Java](https://github.com/VirgilSecurity/sample-backend-java) | [Python](https://github.com/VirgilSecurity/virgil-sdk-python/tree/master#sample-backend-for-jwt-generation)
and follow the instructions in README.

### Set up Card Verifier

Virgil Card Verifier helps you automatically verify signatures of a user's Card, for example when you get a Card from Virgil Cards Service.

By default, `VirgilCardVerifier` verifies only two signatures - those of a Card owner and Virgil Cards Service.

Set up `VirgilCardVerifier` with the following lines of code:

```php
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Verification\VerifierCredentials;
use Virgil\Sdk\Verification\VirgilCardVerifier;
use Virgil\Sdk\Verification\Whitelist;

// initialize Crypto library
$crypto = new VirgilCrypto();

$publicKey = $crypto->importPublicKey("EXPORTED_PUBLIC_KEY");

$yourBackendVerifierCredentials = new VerifierCredentials("YOUR_BACKEND", $publicKey);

$yourBackendWhitelist = new Whitelist([$yourBackendVerifierCredentials]);

$cardVerifier = new VirgilCardVerifier($crypto, true, true, [$yourBackendWhitelist]);
```

### Set up Card Manager

This subsection shows how to set up a Card Manager module to help you manage users' public keys.

With Card Manager you can:

- specify an access Token (JWT) Provider.
- specify a Card Verifier used to verify signatures of your users, your App Server, Virgil Services (optional).

Use the following lines of code to set up the Card Manager:

```php
use Virgil\Sdk\CardManager;
use Virgil\Sdk\Verification\VirgilCardVerifier;

$cardVerifier = new VirgilCardVerifier($virgilCrypto, true, true);

// initialize cardManager and specify accessTokenProvider, cardVerifier
$cardManager = new CardManager($virgilCrypto, $accessTokenProvider, $cardVerifier);
```

## Usage Examples

Before you start practicing with the usage examples, make sure that the SDK is configured. See the [Configure SDK](#configure-sdk) section for more information.

### Generate and publish Virgil Cards at Cards Service

Use the following lines of code to create a user's Card with a public key inside and publish it at Virgil Cards Service:

```php
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\CardParams;

$crypto = new VirgilCrypto();

// generate a key pair
$keyPair = $crypto->generateKeyPair();

// save Alice private key into key storage
$privateKeyStorage->store($keyPair->getPrivateKey(), "Alice");

// create and publish user's card with identity Alice on the Cards Service
$card = $cardManager->publishCard(
    CardParams::create(
        [
            CardParams::PUBLIC_KEY  => $keyPair->getPublicKey(),
            CardParams::PRIVATE_KEY => $keyPair->getPrivateKey(),
        ]
    )
);
```

### Sign then encrypt data

Virgil Core SDK allows you to use a user's private key and their Virgil Cards to sign and encrypt any kind of data.

In the following example, we load a private key from a customized key storage and get recipient's Card from the Virgil Cards Service. Recipient's Card contains a public key which we will use to encrypt the data and verify a signature.

```php
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;

// prepare a message
$dataToEncrypt = 'Hello, Bob!';

// load a private key from a device storage
$alicePrivateKeyEntry = $privateKeyStorage->load('Alice');

// using cardManager search for Bob's cards on Cards Service
$cards = $cardManager->searchCards('Bob');

$bobRelevantCardsPublicKeys = array_map(
    function (Virgil\Sdk\Card $cards) {
        return $cards->getPublicKey();
    },
    $cards
);

$bobRelevantCardsPublicKeysCollection = new VirgilPublicKeyCollection($bobRelevantCardsPublicKeys);

// sign a message with a private key then encrypt using Bob's public keys
$encryptedData = $crypto->signAndEncrypt(
    $dataToEncrypt,
    $alicePrivateKeyEntry->getPrivateKey(),
    $bobRelevantCardsPublicKeysCollection
);
```

### Decrypt data and verify signature

Once the user receives the signed and encrypted message, they can decrypt it with their own private key and verify the signature with the sender's Card:

```php
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;

// load a private key from a device storage
$bobPrivateKeyEntry = $privateKeyStorage->load('Bob');

// using cardManager search for Alice's cards on Cards Service
$cards = $cardManager->searchCards('Alice');

$aliceRelevantCardsPublicKeys = array_map(
    function (Virgil\Sdk\Card $cards) {
        return $cards->getPublicKey();
    },
    $cards
);

$aliceRelevantCardsPublicKeysCollection = new VirgilPublicKeyCollection($aliceRelevantCardsPublicKeys);

// decrypt with a private key and verify using one of Alice's public keys
$decryptedData = $crypto->decryptAndVerify(
    $encryptedData,
    $bobPrivateKeyEntry->getPrivateKey(),
    $aliceRelevantCardsPublicKeysCollection
);
```

### Get Card by its ID

Use the following lines of code to get a user's card from Virgil Cloud by its ID:

```php
// using cardManager get a user's card from the Cards Service
$card = $cardManager->getCard("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8");
```

### Get Card by user's identity

For a single user, use the following lines of code to get a user's Card by a user's `identity`:

```php
// using cardManager search for user's cards on Cards Service
$cards = $cardManager->searchCards("Bob");
```

### Revoke Card

You can revoke user's Card in case they don't need it anymore. Revoked Card can still be obtained using its identifier, but this card won't appear during search query.

```php
// using cardManager revoke user's card on Cards Service by card id
$cardManager->revokeCard("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8");
```

### Generate key pair using VirgilCrypto

You can generate a key pair and save it in a secure key storage with the following code:

```php
use \Virgil\Crypto\VirgilCrypto;

$crypto = new VirgilCrypto();

$keyPair = $crypto->generateKeyPair();
```

### Save and retrieve key from filesystem key storage

```php
use Virgil\Sdk\Storage\PrivateKeyStorage;
use Virgil\Crypto\VirgilCrypto;

$crypto = new VirgilCrypto();

$keyPair = $crypto->generateKeyPair();
$storage = new PrivateKeyStorage($crypto, '/var/www/storage');

$storage->store($keyPair->getPrivateKey(), 'alicePk');

$alicePk = $storage->load('alicePk');
```

## Docs

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
