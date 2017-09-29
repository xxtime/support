<?php

/**
 * 生成密钥对
 * openssl genrsa 2048 > private_key.pem
 * openssl rsa -in private_key.pem -pubout > public_key.pem
 */
namespace Xxtime\Support;


class Rsa
{

    private $_publicKey;


    private $_privateKey;


    private $_blockLength;


    private $_maxLength;


    private function setLength($bit = 1024)
    {
        $this->_blockLength = $bit / 8;
        $this->_maxLength = $this->_blockLength - 11;
    }


    public function setPublicKey($keyString = '', $bit = 1024)
    {
        $this->_publicKey = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split($keyString, 64, "\n") .
            '-----END PUBLIC KEY-----';
        $this->setLength($bit);
    }


    public function setPrivateKey($keyString = '', $bit = 1024)
    {
        $this->_privateKey = "-----BEGIN PRIVATE KEY-----\n" .
            chunk_split($keyString, 64, "\n") .
            '-----END PRIVATE KEY-----';
        $this->setLength($bit);
    }


    public function setPublicKeyPath($path = '', $bit = 1024)
    {
        $this->_publicKey = file_get_contents($path);
        $this->setLength($bit);
    }


    public function setPrivateKeyPath($path = '', $bit = 1024)
    {
        $this->_privateKey = file_get_contents($path);
        $this->setLength($bit);
    }


    /**
     * 加密
     * bin2hex 转16进制
     * base64_encode
     * @param string $plaintext
     * @return bool|string
     */
    public function encrypt($plaintext = '')
    {
        if (!$this->_publicKey) {
            return false;
        }
        $keyResource = openssl_get_publickey($this->_publicKey);
        $plaintext = str_split($plaintext, $this->_maxLength);
        $result = '';
        foreach ($plaintext as $block) {
            openssl_public_encrypt($block, $encrypted, $keyResource);
            $result .= $encrypted;
        }
        return $result;
    }


    /**
     * 解密
     * @param string $data
     * @return bool|string
     */
    public function decrypt($data = '')
    {
        if (!$this->_privateKey) {
            return false;
        }
        $keyResource = openssl_get_privatekey($this->_privateKey);
        $data = str_split($data, $this->_blockLength);
        $result = '';
        foreach ($data as $block) {
            openssl_private_decrypt($block, $decrypted, $keyResource);
            $result .= $decrypted;
        }
        return $result;
    }


    /**
     * 生成签名
     * @param string $data
     * @param int $alg http://php.net/manual/en/openssl.signature-algos.php
     * @return mixed
     */
    public function signature($data = '', $alg = OPENSSL_ALGO_SHA1)
    {
        $keyResource = openssl_get_privatekey($this->_privateKey);
        openssl_sign($data, $signature, $keyResource, $alg);
        return $signature;
    }


    /**
     * 验证签名
     * @param string $data
     * @param string $signature
     * @param int $alg http://php.net/manual/en/openssl.signature-algos.php
     * @return bool
     */
    public function verifySign($data = '', $signature = '', $alg = OPENSSL_ALGO_SHA1)
    {
        $keyResource = openssl_get_publickey($this->_publicKey);
        $verified = openssl_verify($data, $signature, $keyResource, $alg);
        if ($verified != 1) {
            return false;
        }
        return true;
    }

}