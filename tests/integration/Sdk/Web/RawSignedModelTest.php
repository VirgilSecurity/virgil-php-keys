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

namespace Tests\Integration\Sdk\Web;

use Virgil\Sdk\Web\RawSignature;
use Virgil\Sdk\Web\RawSignedModel;
use Tests\Integration\IntegrationBaseTestCase;

use PHPUnit\Framework\Attributes\Test;

class RawSignedModelTest extends IntegrationBaseTestCase
{

    #[Test]
    public function testSTC1()
    {
        $stc1AsString = $this->fixtures->STC1__As_String();
        $rawSignedModelFromString = RawSignedModel::rawSignedModelFromBase64String($stc1AsString);

        $stc1AsJson = $this->fixtures->STC1__As_Json();
        $rawSignedModelFromJson = RawSignedModel::rawSignedModelFromJson($stc1AsJson);

        /** @var RawSignedModel $rawSignedModel */
        foreach ([$rawSignedModelFromString, $rawSignedModelFromJson] as $rawSignedModel) {
            $content = json_decode($rawSignedModel->getContentSnapshot(), true);

            $exportedString = $rawSignedModel->exportAsBase64String();
            $exportedJson = $rawSignedModel->exportAsJson();

            $this->assertEquals($stc1AsString, $exportedString);
            $this->assertEquals($stc1AsJson, $exportedJson);

            $this->assertEquals('test', $content['identity']);
            $this->assertEquals('MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=', $content['public_key']);
            $this->assertEquals('5.0', $content['version']);
            $this->assertEquals('1515686245', $content['created_at']);
            $this->assertNotContains('previous_card_id', $content);
        }
    }

    #[Test]
    public function testSTC2()
    {
        $stc2AsString = $this->fixtures->STC2__As_String();
        $rawSignedModelFromString = RawSignedModel::rawSignedModelFromBase64String($stc2AsString);

        $stc2AsJson = $this->fixtures->STC2__As_Json();
        $rawSignedModelFromJson = RawSignedModel::rawSignedModelFromJson($stc2AsJson);

        /** @var RawSignedModel $rawSignedModel */
        foreach ([$rawSignedModelFromString, $rawSignedModelFromJson] as $rawSignedModel) {
            $signatures = $rawSignedModelFromJson->getSignatures();
            $content = json_decode($rawSignedModel->getContentSnapshot(), true);

            $exportedString = $rawSignedModel->exportAsBase64String();
            $exportedJson = $rawSignedModel->exportAsJson();

            $this->assertEquals($stc2AsString, $exportedString);
            $this->assertEquals($stc2AsJson, $exportedJson);

            $this->assertEquals($stc2AsString, $exportedString);
            $this->assertEquals('test', $content['identity']);
            $this->assertEquals('MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=', $content['public_key']);
            $this->assertEquals('5.0', $content['version']);
            $this->assertEquals('1515686245', $content['created_at']);
            $this->assertEquals(
                'a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9',
                $content['previous_card_id']
            );
            $this->assertCount(3, $signatures);

            $this->assertEquals(
                new RawSignature(
                    'self',
                    base64_decode(
                        'MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8='
                    )
                ),
                $signatures[0]
            );

            $this->assertEquals(
                new RawSignature(
                    'virgil',
                    base64_decode(
                        'MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8='
                    )
                ),
                $signatures[1]
            );

            $this->assertEquals(
                new RawSignature(
                    'extra',
                    base64_decode(
                        'MFEwDQYJYIZIAWUDBAIDBQAEQCA3O35Rk+doRPHkHhJJKJyFxz2APDZOSBZi6QhmI7BP3yTb65gRYwu0HtNNYdMRsEqVj9IEKhtDelf4SKpbJwo='
                    )
                ),
                $signatures[2]
            );

        }
    }
}
