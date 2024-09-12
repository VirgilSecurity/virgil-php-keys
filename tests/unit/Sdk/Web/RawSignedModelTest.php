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

namespace Tests\Unit\Sdk\Web;

use Virgil\Sdk\Web\RawSignature;
use Virgil\Sdk\Web\RawSignedModel;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

class RawSignedModelTest extends TestCase
{

    public static function dataProvider()
    {

        return [
            [
                '{"content_snapshot":"eyJpZGVudGl0eSI6IkFsaWNlLTZjYWRhYTY4ZjA5MWQzZDM2MjZhIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==","signatures":[{"signer":"self","signature":"MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="},{"signer":"virgil","signature":"MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="}]}',
                [RawSignedModel::class, 'rawSignedModelFromJson'],
            ],
            [
                'eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNklrRnNhV05sTFRaallXUmhZVFk0WmpBNU1XUXpaRE0yTWpaaElpd2ljSFZpYkdsalgydGxlU0k2SWsxRGIzZENVVmxFU3pKV2QwRjVSVUZFTjBKT1pWWkVZblZhT1VaUVQwcDFRMloyVVVKV1pXeHlZV3B6Y0daVWIyMTJVbkJPTVVSWlZtNHdQU0lzSW5abGNuTnBiMjRpT2lJMUxqQWlMQ0pqY21WaGRHVmtYMkYwSWpveE5USXpPREkzT0RnNGZRPT0iLCJzaWduYXR1cmVzIjpbeyJzaWduZXIiOiJzZWxmIiwic2lnbmF0dXJlIjoiTUZFd0RRWUpZSVpJQVdVREJBSURCUUFFUURCYllaa1R1N3Z0NUFLVGNDUEo2ODVuTXVRQ2l2UVplTVIrNmptbUpZMjEvazVCNHhFczVBN0hGMjkzZmJZVi82WmxxZFRBc1BqalF1TVhQTlU2cHdBPSJ9LHsic2lnbmVyIjoidmlyZ2lsIiwic2lnbmF0dXJlIjoiTUZFd0RRWUpZSVpJQVdVREJBSURCUUFFUUFPaUUwWTI5cy9yUEF0eGpWMEhac0dmM0VUUW5qQ0ZTbmR2YWMyS1BOUDRyWFVPSjJOT2o3VmdSQWtjM2l6S1FwRHMrQmQxWU55MGhaZWgzNkdjSlFjPSJ9XX0=',
                [RawSignedModel::class, 'rawSignedModelFromBase64String'],
            ],
        ];
    }


    #[Test]
    #[DataProvider("dataProvider")]
    public function RawSignedModel_FromString_returnsValidModel($json, $fromFunc)
    {
        $model = call_user_func($fromFunc, $json);

        $this->assertEquals(
            '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}',
            $model->getContentSnapshot()
        );
        $this->assertEquals(
            [
                new RawSignature(
                    "self",
                    base64_decode(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                    )
                ),
                new RawSignature(
                    "virgil",
                    base64_decode(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="
                    )
                ),
            ],
            $model->getSignatures()
        );
    }
}
