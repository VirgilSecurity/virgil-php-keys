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

/**
 * Class aims initialize cURL session and provides necessary methods to perform configuration, execution and closing
 * the session.
 */
class CurlRequest implements RequestInterface
{
    /** @var resource $handle */
    private $handle;

    /** @var array $options */
    private array $options;

    public function __construct(?string $url = null)
    {
        $this->handle = $url !== null ? curl_init($url) : curl_init();
    }


    /**
     * @inheritdoc
     */
    public function execute(): mixed
    {
        curl_setopt_array($this->handle, $this->options);

        return curl_exec($this->handle);
    }


    /**
     * @inheritdoc
     */
    public function getInfo(?int $option = null): mixed
    {
        return $option !== null ? curl_getinfo($this->handle, $option) : curl_getinfo($this->handle);
    }


    /**
     * @inheritdoc
     */
    public function setOption(string $name, $option): RequestInterface
    {
        $this->options[$name] = $option;

        return $this;
    }


    /**
     * @inheritdoc
     */
    public function setOptions(array $options): RequestInterface
    {
        $this->options = $options;

        return $this;
    }


    /**
     * @inheritdoc
     */
    public function getOptions(): array
    {
        return $this->options;
    }


    /**
     * @inheritdoc
     */
    public function close(): RequestInterface
    {
        curl_close($this->handle);

        return $this;
    }
}
