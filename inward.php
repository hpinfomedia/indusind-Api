<?php 
        require_once 'vendor/autoload.php';
        use Jose\Component\Core\AlgorithmManager;
        use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
        use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
        use Jose\Component\Signature\Algorithm\RS256;
        use Jose\Component\Encryption\Compression\CompressionMethodManager;
        use Jose\Component\Encryption\Compression\Deflate;
        use Jose\Component\Encryption\JWEBuilder ;
        use Jose\Component\KeyManagement\JWKFactory;
        use Jose\Component\Encryption\Serializer\CompactSerializer;
        use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
        use Jose\Component\Encryption\Serializer\JWESerializerManager;
        use Jose\Component\Encryption\JWEDecrypter;
        use Jose\Component\Encryption\JWELoader;
        use Jose\Component\Encryption\JWEDecrypterFactory;
       // use Jose\Component\Checker\HeaderCheckerManager;
        //use Jose\Component\Checker\AlgorithmChecker;
        //use Jose\Component\Signature\JWSTokenSupport;
        //use Jose\Component\Encryption\JWELoaderFactory;
        //use Jose\Component\Core\JWK;
        //use Jose\Component\Signature\Algorithm\PS256;
        //use Jose\Component\Signature\Algorithm\ES512;
        
        ini_set('display_errors', 1);
        ini_set('display_startup_errors', 1);
        error_reporting(E_ALL);
        
        /*  
            Production Credentials
            $client_id      = "053e548914570c1785dda7a778ea1e4a";
            $client_secret  = "bc5cfc52cb655ddab2607e1357ab65fc";
        */

        /*  UAT Credentials  */

            $client_id      = "854401182fb7a10ea313c12221136f0e";
            $client_secret  = "b79e5e6adfe3157ec216fa0f0f16c08c";
            $apiUrl="https://indusapiuat.indusind.com/indusapi-np/uat/iec/etender/updateTenderId/v1";
        // arr consists of sample payload
        
        $arr = [
            'request' => [
                'header' => [
                    'requestUUID' => time(),
                    'channelId' => "NETWARE",
                ],
                'body' => [


                    'fetchIECDataReq' => [
                        'customerTenderId' => "SKUSB"
                    ]
                ]
            ]
        ];

        $data = json_encode($arr);

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new A256KW(),
        ]);

        // The content encryption algorithm manager with the A256CBC-HS256 algorithm.
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256GCM(),
        ]);

        // The signatrue encryption algorithm manager with the RS256 algorithm.
        $signatureEncryptionAlgorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

        // // The compression method manager with the DEF (Deflate) method.
        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        // We instantiate our JWE Builder.
        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
        $rndEncryptionKey = openssl_random_pseudo_bytes(32);
        $GenaratedKey = JWKFactory::createFromSecret(
            $rndEncryptionKey     // The shared secret
        );

    
      // $array = (array) $GenaratedKey;
     //  print_r($GenaratedKey);
        $jwe = $jweBuilder
            ->create()              // We want to create a new JWE
            ->withPayload($data) // We set the payload
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',        // Key Encryption Algorithm
                'enc' => 'A256GCM', // Content Encryption Algorithm
                'zip' => 'DEF'            // We enable the compression (irrelevant as the payload is small, just for the example).
            ])
            ->addRecipient($GenaratedKey)    // We add a recipient (a shared key or public key).
            ->build();              // We build it
        $serializer = new CompactSerializer(); // The serializer
        $encData = $serializer->serialize($jwe, 0); // We serialize the recipient at index 0 (we only have one recipient).

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256(),
        ]);

        // // We instantiate our JWE Builder.
        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
        // 4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(
        $key = JWKFactory::createFromKeyFile(
            'indusCertificate.txt', // The filename
            '',                   // Secret if the key is encrypted, otherwise null
            [
                'use' => 'enc',         // Additional parameters
            ]
        );

        $rndEncryptionKeyHexCode =  bin2hex($rndEncryptionKey);

        $jwe = $jweBuilder
            ->create()              // We want to create a new JWE
            ->withPayload($rndEncryptionKeyHexCode) // We set the payload
           // ->withPayload($data) // We set the payload
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',        // Key Encryption Algorithm
                'enc' => 'A256GCM', // Content Encryption Algorithm
                'zip' => 'DEF'            // We enable the compression (irrelevant as the payload is small, just for the example).
            ])
            ->addRecipient($key)    // We add a recipient (a shared key or public key).
            ->build();              // We build it

        $serializer = new CompactSerializer(); // The serializer
        $encKey = $serializer->serialize($jwe, 0); // We serialize the recipient at index 0 (we only have one recipient).

        $request = json_encode([
            'data' => $encData,
            'key' => $encKey,
            'bit' => 0
        ]);
        // print_r($request);
        $httpUrl = $apiUrl;

        $headers = array(
            'IBL-Client-Id: '.$client_id,
            'IBL-Client-Secret: '.$client_secret,
            'Content-Type: application/json',
        );

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $httpUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 1,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $request,
            CURLOPT_HTTPHEADER => $headers,
        ));
        
        $response = curl_exec($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        //$httpcode = 200;
        //$response = 'eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.Y_QfrwhoLIItqfnY98cBCPoVVfvp2kdBuVzkTa5fdY-hI7C9AFgzJw.zS9oj-2HpsxJyGbq.GDfoIXoBv4QyetjO-9wbm_axZfsRnVrjC2fYINj1-pv2BkT43iYWc9DhWF-zHiPqf9JCtbqFgrgfJGRBUlDyKl1AGent6i7Z6dR8y_icH70DYH1vGz5pqJyYWDmMUFK_By6-_KSVG52_5eH2Pf7bmHW-gq-i64XPVNL1bs1xLUUrt7cFrF6X7BZp7tG8f17eq-QaKteDO4RtRlQ5uKV14-1jqKFWTRzfsGUHF8-KKmnSATA8Yz1ljoj3Utw137hjMxr8xmbT15lWamU-VJEROsX8RkO9Aoc2KtnJ32ISiwzu45aen0rWFKuKzebfmzsSsI3U1b7_vcuxE3Rp1LH0DUJBjrZ9x10Yy9Z9GZpvI9_ZcOWNl1ngKjoxxqfAv5f313zoYsTV2NJagIOCWmaFkXUVyox7cnJsjAl4KpTUuradPOtlMcNwMypzpbMU5_zqrIkG_YBhehK-x-sGm_pIVa_-uChnPARIuJ-7NHoj7p64_w33hDs6gXX9STj-W0sMlbTXJIhv4PFZ1m7_GKjFhxqrZ3eaOeKxOnNIKcql8b00n9qVIK0ngJb9XmfD-Jy-fL45S_esNQ_5OWEK7bBV5lBh9zT_zbGdtahxNXZAB5PclQX7IlJNZy15lwUQtIw1bjflNd1GIgZklhuWSJ3QruZQLnDaeqb5xocMJoOFjuP5O703BrU.nU84mG-kev9oPrUo229vwg';
        $response   = json_decode($response)->data;
       
        // print_r( $response);
        //  die();
      
        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new A256KW(),
        ]);

        // The content encryption algorithm manager with the A256CBC-HS256 algorithm.
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256GCM(),
        ]);

        // // The compression method manager with the DEF (Deflate) method.
        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        // $encToken = base64_decode(explode('.', $raw_response)[1]);

        // The serializer manager. We only use the JWE Compact Serialization Mode.
        $serializerManager = new JWESerializerManager([
            new CompactSerializer(),
        ]);

        // We try to load the token.
        $jwe = $serializerManager->unserialize($response);

        $jwkAlgkey = JWKFactory::createFromSecret(
            $rndEncryptionKey // '4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(',       // The shared secret
        );

 
        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
////////////////////////////////deserialize and decrypt the input we receive/////////////////////////////

          $decryptionSuccess = $jweDecrypter->decryptUsingKey($jwe, $jwkAlgkey,0);

          if (!$decryptionSuccess) {
            exit('Unable to decrypt the token');
        }
        // print_r('The token has been decrypted');
        print_r($jwe->getPayload());
            
?>


