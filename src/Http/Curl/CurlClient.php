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

namespace Virgil\Sdk\Http\Curl;

use Virgil\Sdk\Http\AbstractHttpClient;
use Virgil\Sdk\Http\Constants\RequestMethods;
use Virgil\Sdk\Http\HttpClientInterface;
use Virgil\Sdk\Http\Responses\HttpResponse;
use Virgil\Sdk\Http\Responses\HttpResponseInterface;
use Virgil\Sdk\Http\Responses\HttpStatusCode;

/**
 * Class CurlClient
 */
class CurlClient extends AbstractHttpClient implements HttpClientInterface
{
    public function __construct(
        private readonly RequestFactoryInterface $curlRequestFactory,
        private array $requestHeaders = []
    ) {
    }

    /**
     * Make and execute an HTTP POST request.
     */
    public function post(string $url, string $body, array $headers = []): HttpResponseInterface
    {
        $curlOptions = [
            CURLOPT_URL => $this->buildUrl($url),
            CURLOPT_HTTPHEADER => $this->buildHeaders($headers),
            CURLOPT_CUSTOMREQUEST => RequestMethods::HTTP_POST,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_POST => true,
        ];

        $curlRequest = $this->curlRequestFactory->create($curlOptions);

        return $this->doRequest($curlRequest);
    }

    /**
     * Make and execute a HTTP DELETE request.
     */
    public function delete(string $url, string $body, array $headers = []): HttpResponseInterface
    {
        $curlRequest = $this->curlRequestFactory->create(
            [
                CURLOPT_URL => $this->buildUrl($url),
                CURLOPT_HTTPHEADER => $this->buildHeaders($headers),
                CURLOPT_CUSTOMREQUEST => RequestMethods::HTTP_DELETE,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_POST => true,
            ]
        );

        return $this->doRequest($curlRequest);
    }

    /**
     * Make and execute a HTTP GET request.
     */
    public function get(
        string $url,
        array $queryParams = [],
        array $headers = []
    ): HttpResponseInterface {
        $curlRequest = $this->curlRequestFactory->create(
            [
                CURLOPT_URL => $this->buildUrl($url, $queryParams),
                CURLOPT_HTTPHEADER => $this->buildHeaders($headers),
                CURLOPT_CUSTOMREQUEST => RequestMethods::HTTP_GET,
                CURLOPT_HTTPGET => true,
            ]
        );

        return $this->doRequest($curlRequest);
    }

    /**
     * Get default headers for all requests.
     */
    public function getRequestHeaders(): array
    {
        return $this->requestHeaders;
    }

    /**
     * Set default headers for all requests.
     */
    public function setRequestHeaders(array $requestHeaders): void
    {
        $this->requestHeaders = $requestHeaders;
    }

    /**
     * Do a http request
     */
    protected function doRequest(RequestInterface $httpRequest): HttpResponse
    {
        $httpRawResponse = $httpRequest->execute();
        $httpStatusCode = $httpRequest->getInfo(CURLINFO_HTTP_CODE);
        $httpRequest->close();

        return $this->buildResponse((string) $httpStatusCode, (string) $httpRawResponse);
    }

    /**
     * Builds response from raw HTTP response body and HTTP status code.
     */
    protected function buildResponse(string $httpStatusCode, string $httpResponse): HttpResponse
    {
        return new HttpResponse(
            new HttpStatusCode($httpStatusCode),
            ...explode("\r\n\r\n", $httpResponse, 2)
        );
    }

    /**
     * Returns HTTP compatible request headers.
     */
    protected function buildHeaders(array $requestHeaders): array
    {
        $requestHeaders = $requestHeaders + $this->requestHeaders;
        $resultHeaders = [];

        foreach ($requestHeaders as $headerName => $headerValue) {
            if (is_array($headerValue)) {
                $headerValue = implode(',', $headerValue);
            }

            $resultHeaders[] = ucfirst($headerName) . ': ' . $headerValue;
        }

        return $resultHeaders;
    }

    /**
     * Returns HTTP compatible request URL with params if specified.
     */
    protected function buildUrl(string $requestUrl, array $requestParams = []): string
    {
        if (!empty($requestParams)) {
            $requestUrl = $requestUrl . '?' . http_build_query($requestParams);
        }

        return $requestUrl;
    }
}
