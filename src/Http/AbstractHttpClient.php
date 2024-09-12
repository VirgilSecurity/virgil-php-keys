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

namespace Virgil\Sdk\Http;

use RuntimeException;
use Virgil\Sdk\Http\Constants\RequestMethods;
use Virgil\Sdk\Http\Requests\HttpRequestInterface;
use Virgil\Sdk\Http\Responses\HttpResponseInterface;

/**
 * An abstract HTTP client class responsible for defining send request strategy logic.
 */
abstract class AbstractHttpClient implements HttpClientInterface
{
    /**
     * Sends HTTP request.
     *
     * @param HttpRequestInterface $httpRequest The HTTP request to send.
     * @return HttpResponseInterface The response from the HTTP request.
     * @throws RuntimeException If the request method is not supported.
     */
    public function send(HttpRequestInterface $httpRequest): HttpResponseInterface
    {
        $url = $httpRequest->getUrl();
        $headers = $httpRequest->getHeaders();
        return match ($httpRequest->getMethod()) {
            RequestMethods::HTTP_GET => $this->get($url, [], $headers),
            RequestMethods::HTTP_POST => $this->post($url, (string) $httpRequest->getBody(), $headers),
            RequestMethods::HTTP_DELETE => $this->delete(
                $url,
                (string) $httpRequest->getBody(),
                $headers
            ),
            default => throw new RuntimeException('No such method for handling this kind of request'),
        };
    }

    // Abstract methods for GET, POST, DELETE to be implemented in child classes
    abstract protected function get(string $url, array $queryParams, array $headers): HttpResponseInterface;

    abstract protected function post(string $url, string $body, array $headers): HttpResponseInterface;

    abstract protected function delete(string $url, string $body, array $headers): HttpResponseInterface;
}
