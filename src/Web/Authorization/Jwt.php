<?php
/**
 * Copyright (c) 2015-2024 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

declare(strict_types=1);

namespace Virgil\Sdk\Web\Authorization;

use InvalidArgumentException;

/**
 * Class Jwt
 */
class Jwt implements AccessToken
{
    public const string VIRGIL_JWT_TYPE = 'JWT';
    public const string VIRGIL_JWT_CONTENT_TYPE = 'virgil-jwt;v=1';
    public const string VIRGIL_JWT_ALGORITHM = 'VEDS512';

    /**
     * @var JwtParser
     */
    protected JwtParser $jwtParser;

    public function __construct(
        private readonly JwtHeaderContent $headerContent,
        private readonly JwtBodyContent $bodyContent,
        private readonly string $signatureContent
    ) {
        $this->jwtParser = new JwtParser();
    }

    public static function fromString(string $token): Jwt
    {
        $jwtParser = new JwtParser();
        $tokenParts = explode('.', $token);
        if (count($tokenParts) !== 3) {
            throw new InvalidArgumentException("JWT parse failed: " . $token);
        }
        $tokenBase64Header = $tokenParts[0];
        $tokenBase64Body = $tokenParts[1];
        $tokenBase64Signature = $tokenParts[2];

        $urlSafeBase64Decode = function ($data) {
            return base64_decode(strtr($data, '-_', '+/'));
        };

        $tokenJsonHeader = $urlSafeBase64Decode($tokenBase64Header);
        $tokenJsonBody = $urlSafeBase64Decode($tokenBase64Body);
        $signature = $urlSafeBase64Decode($tokenBase64Signature);

        return new Jwt(
            $jwtParser->parseJwtHeaderContent($tokenJsonHeader),
            $jwtParser->parseJwtBodyContent($tokenJsonBody),
            $signature
        );
    }


    public function isExpired(): bool
    {
        return $this->bodyContent->getExpiresAt() < time();
    }


    public function identity(): string
    {
        return $this->bodyContent->getIdentity();
    }


    public function __toString(): string
    {
        if ($this->signatureContent !== '') {
            $jwtBase64Signature = $this->urlSafeBase64Encode($this->signatureContent);

            return $this->getUnsigned() . "." . $jwtBase64Signature;
        }

        return $this->getUnsigned();
    }


    public function getSignatureContent(): string
    {
        return $this->signatureContent;
    }


    public function getUnsigned(): string
    {
        $jwtBase64Body = $this->urlSafeBase64Encode($this->jwtParser->buildJwtBody($this->bodyContent));
        $jwtBase64Header = $this->urlSafeBase64Encode($this->jwtParser->buildJwtHeader($this->headerContent));

        return $jwtBase64Header . "." . $jwtBase64Body;
    }


    public function getBodyContent(): JwtBodyContent
    {
        return $this->bodyContent;
    }


    public function getHeaderContent(): JwtHeaderContent
    {
        return $this->headerContent;
    }


    private function urlSafeBase64Encode($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
