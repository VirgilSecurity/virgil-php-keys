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

namespace Virgil\Sdk\Http\VirgilAgent;

/**
 * Class HttpVirgilAgent
 */
class HttpVirgilAgent
{
    /**
     * @var string
     */
    private string $name = 'Virgil-agent';
    /**
     * @var string
     */
    private string $product = 'sdk';
    /**
     * @var string
     */
    private string $family = 'php';


    public function getName(): string
    {
        return $this->name;
    }


    public function getFormatString(): string
    {
        $os = strtolower(php_uname('s'));
        return $this->product . ";" . $this->family . ";" . $os . ";" . $this->getVersion();
    }


    private function getVersion(): string
    {
        $composerLock = 'composer.lock';
        $packageName = 'virgil/crypto';
        $version = 'unknown';

        $path = __DIR__ . DIRECTORY_SEPARATOR . DIRECTORY_SEPARATOR;

        if (!is_dir($path) || !in_array($composerLock, scandir($path))) {
            return $version;
        }

        $composerLockFile = file_get_contents($path . $composerLock);
        $composerLockFileToArray = json_decode($composerLockFile);

        $packages = $composerLockFileToArray->packages;

        foreach ($packages as $package) {
            if ($packageName === $package->name) {
                $version = $package->version;
                if ('v' === $version[0]) {
                    $version = ltrim($version, 'v');
                }
                break;
            }
        }

        return $version;
    }
}
