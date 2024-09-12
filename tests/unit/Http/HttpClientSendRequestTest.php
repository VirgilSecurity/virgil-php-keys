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

namespace Tests\Unit\Http;

use Virgil\Sdk\Http\Curl\CurlClient;
use Virgil\Sdk\Http\Requests\DeleteHttpRequest;
use Virgil\Sdk\Http\Requests\GetHttpRequest;
use Virgil\Sdk\Http\Requests\PostHttpRequest;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class HttpClientSendRequestTest extends TestCase
{
    #[Test]
    #[DataProvider("getHttpRequestArguments")]
    public function send__httpGetRequest__callsGetHandler($requestUrl, $requestBody, $requestHeaders)
    {
        $httpClientMock = $this->getHttpClient();
        $getHttpRequest = $this->createGetHttpRequest($requestUrl, $requestHeaders);


        $httpClientMock->expects($this->once())
            ->method('get')
            ->with($requestUrl, [], $requestHeaders);


        $httpClientMock->send($getHttpRequest);
    }


    #[Test]
    #[DataProvider("getHttpRequestArguments")]
    public function send__httpPostRequest__callsPostHandler($requestUrl, $requestBody, $requestHeaders)
    {
        $httpClientMock = $this->getHttpClient();
        $postHttpRequest = $this->createPostHttpRequest($requestUrl, $requestBody, $requestHeaders);


        $httpClientMock->expects($this->once())
            ->method('post')
            ->with($requestUrl, $requestBody, $requestHeaders);


        $httpClientMock->send($postHttpRequest);
    }

    #[Test]
    #[DataProvider("getHttpRequestArguments")]
    public function send__httpDeleteRequest__callsDeleteHandler($requestUrl, $requestBody, $requestHeaders)
    {
        $httpClientMock = $this->getHttpClient();
        $deleteHttpRequest = $this->createDeleteHttpRequest($requestUrl, $requestBody, $requestHeaders);


        $httpClientMock->expects($this->once())
            ->method('delete')
            ->with($requestUrl, $requestBody, $requestHeaders);


        $httpClientMock->send($deleteHttpRequest);
    }


    public static function getHttpRequestArguments()
    {
        return [
            [
                'http://immutable.host/card/id/1',
                'Hello Card 1',
                ['UserName' => 'Alice', 'UserRole' => 'receiver'],
            ],
        ];
    }


    /**
     * @return \PHPUnit\Framework\MockObject\MockObject|CurlClient
     */
    protected function getHttpClient()
    {
        return $this->createPartialMock(CurlClient::class, ['get', 'post', 'delete']);
    }


    protected function createGetHttpRequest($requestUrl, $requestHeaders)
    {
        return new GetHttpRequest($requestUrl, null, $requestHeaders);
    }


    private function createDeleteHttpRequest($requestUrl, $requestBody, $requestHeaders)
    {
        return new DeleteHttpRequest($requestUrl, $requestBody, $requestHeaders);
    }


    private function createPostHttpRequest($requestUrl, $requestBody, $requestHeaders)
    {
        return new PostHttpRequest($requestUrl, $requestBody, $requestHeaders);
    }
}
