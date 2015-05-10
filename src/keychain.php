<?php namespace recca0120\ios;

use phpseclib\Crypt\RSA;
use phpseclib\File\X509;

class KeyChain
{
    public $DNProp = [
        'emailAddress' => 'recca0120@gmail.com',
    ];

    public $privateKey = null;
    public $publicKey = null;
    public $p12 = null;
    public $p12data = null;
    public function __construct($options = [])
    {
        $key = (empty($options['key']) === false) ? $options['key'] : [];
        $jsonFile = (empty($options['json']) === false) ? $options['json'] : 'key.json';
        if (empty($key['privatekey']) === true or empty($key['publickey']) === true) {
            if (file_exists($jsonFile) === true) {
                $key = json_decode(file_get_contents($jsonFile), true);
            } else {
                $rsa = new RSA();
                $key = $rsa->createKey(2048);
                file_put_contents($jsonFile, json_encode($key));
            }
        }
        $this->privateKey = $key['privatekey'];
        $this->publicKey = $key['publickey'];
    }

    public function certSigningRequest()
    {
        $privkey = new RSA();
        $privkey->loadKey($this->privateKey);
        $pubkey = new RSA();
        $pubkey->loadKey($this->publicKey);
        $pubkey->setPublicKey();
        // Create certificate request.
        $csr = new X509();
        $csr->setPrivateKey($privkey);
        $csr->setPublicKey($pubkey);
        foreach ($this->DNProp as $key => $value) {
            $csr->setDNProp($key, $value);
        }
        // Set CSR attribute.
        // $csr->setAttribute('pkcs-9-at-unstructuredName', array('directoryString' => array('utf8String' => 'myCSR')), FILE_X509_ATTR_REPLACE);

        // Set extension request.
        // $csr->setExtension('id-ce-keyUsage', array('encipherOnly'));

        // Generate CSR.
        $signCSR = $csr->saveCSR($csr->signCSR());

        return $signCSR;
    }

    public function createCertSigningRequest($path = '')
    {
        file_put_contents($path.'/CertificateSigningRequest.certSigningRequest', $this->certSigningRequest());
    }

    public function loadCer($cer, $password = null)
    {
        $pem = '-----BEGIN CERTIFICATE-----'."\n"
            .chunk_split(base64_encode($cer), 64, "\n")
            .'-----END CERTIFICATE-----'."\n";

        if (openssl_pkcs12_export($pem, $out, $this->privateKey, $password)) {
            $this->loadP12($out, $password);

            return $out;
        } else {
            throw new \Exception(openssl_error_string());
        }
    }

    public function loadP12($p12, $password = null)
    {
        if (openssl_pkcs12_read($p12, $out, $password)) {
            $this->p12 = $out;
            $this->p12data = openssl_x509_parse($out['cert']);
        } else {
            throw new \Exception(openssl_error_string());
        }
    }

    public function generate()
    {
        $result = 'Bag Attributes'."\n";
        $result .= '    friendlyName: '.$this->p12data['subject']['CN']."\n";
        $result .= '    localKeyID: '.$this->p12data['extensions']['subjectKeyIdentifier']."\n";
        $result .= 'subject=';
        foreach ($this->p12data['subject'] as $key => $value) {
            $result .= '/'.$key.'='.$value;
        }
        $result .= "\n";
        $result .= 'issuer=';
        foreach ($this->p12data['issuer'] as $key => $value) {
            $result .= '/'.$key.'='.$value;
        }
        $result .= "\n";
        $result .= $this->p12['cert'].$this->p12['pkey'];

        return $result;
    }

    public function save($result, $path = '', $encode = null)
    {
        $filename = $path.'/'.$this->p12data['subject']['UID'].(strpos($this->p12data['subject']['CN'], 'Production') > -1 ? '.prod' : '.dev').'.pem';
        file_put_contents($filename, $result);
        echo sprintf(
            'Generate <b>%s</b> is valid until %s.<hr>',
            $filename,
            date('d/m/Y', $this->p12data['validTo_time_t'])
        );
        return $filename;
    }
}
