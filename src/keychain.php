<?php namespace recca0120\ios;

use phpseclib\Crypt\RSA;
use phpseclib\File\X509;

class KeyChain
{
    public $rsa = [
        'privatekey' => '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAohFPmQfdSgnquBr39uktUlCBQ9/AUUhLWWCJjAj71NFJO+B/
Wgq5BeeczSTS3P0raUZpcKFptoPfkkUzmyArMl6RfjcYB+RgBvzPRkBli+YvLqNW
V0fOfBzAYULDeQ4JrRNJG/aHaoQbPa4XieU/RVtCLeCdtB6Wq0XilBBKY4A5OCb5
UglPtfaX3TvhehfWLLMEBGVqFZhq2Ftmj4KTAGP1v14xN84oZXmAU4RYrkoQI3Q2
KSnBDi69owhGtKPJcMKHBIMMPDPATS0ZbeiJ0k4xW3JfudGp6rWufrCy5diaaBmK
07Kt2TRTfvhj7P4gu91IKmwnseaOSpkwLphqawIDAQABAoIBAFmFqGtGrdTc/3us
4fXQvckvUQgWC5yai4yWR8RDnh/jb0mU66PoMmXxl2q2AYgyjI09aLbfYo5/77pT
YXs53MKY/FM0yaBqZSTW9wO+RJlvj/Z6IRJbRtLF6vqOr30p5Oxmr8azef+7c3Sx
uqzgJgAAteCzp0k8cEuxccQJ751f8GPLUWYcLnWEBmx50SgbCwEFL4eyfJQmOtJt
g6z78BaGOMYFYN9VoFgpJn8MsMfeCsM6g/VTPUhj9syDnkkUTFD62k6vm6xyzFvs
eUJHgRtMQLMuMdXEdx08RVXeJSLcaSndEEhdCZMLIO5O8CTxv/ETLwjgCN21LdFs
PdVWnCkCgYEA1rmcc3mZlATzJWDA0qwRbgcCVMOODRFqvQ1sMN+9DOkWOtkzGits
1SlE0MfZjvHvOEvEbcRkEaINx+cqSkL4jEU69jpHtnf8PoR7lPOMhTZ7bzLHhSPJ
nEN5JD8JwDESeDe0Mtz3W3ZgvGzYK1xU1he9Txb6kOF62IH8sl5xT/0CgYEAwTh8
C7yTxCMaiyfWs5+u6KcDx4YhAyyCYD9m2MaqSIsbPl2y789XZ+oEDnsTZlquywUO
Zlxc1kT6fSjCmy7YT4pH9hnzaf2tcu2t4aJfVPU6MfVOkanoXb+m74qqIVm+fSux
Dvl5Jy2Fzzk3/+h00FarIK8Ifg7l9B9zUZGi7IcCgYEAtSbegOVj1ebfIvefdZzJ
D6RGKTDaFNhOzrQWRJ1dpxi2MmuvmzJrnOI2NlWEi/48LahuTZTUP7QSIEY7/W7G
tcBqX/UHLz/GxQ+MGzvlnzU5qbSTcxWgL38VIqk0FrrPtDB6jDazUKxsLEs/jEVX
JU/d3G2scrJnq2TuxaS7wBkCgYEAk/Atecb+1FOURStRheIjR1po2GFn8Ugo4oxo
sF0bj8OCLnQLRvVXlOZmCLhPGDUiU6shZVoecqgJqb6Fkc+CKxRTGKix6FskbDRy
x6lMmH3R+uI5L+oJUY4lwI5IyJQv9yJ2xGJaUpbWNt02dSeEGOfiynl5ZRr/EbTq
1G9PcQ0CgYBtMaGqUGbGJZk7/Whw6HropSSuyvHIQ4sAHX7XjRazFsdd6/UzDCXR
VcZ98cJGXqIvNpqGKtYM7a+rNEMtP8vvndIHO49X3Cdxk4tCD6UdwDAXrT+Fs+I+
oYx7IkXRcHoU/FSQp7PM/Q0nQfjfJLNsk3LQ2kPNaJvRvwxz/zBD6w==
-----END RSA PRIVATE KEY-----',
        'publickey' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAohFPmQfdSgnquBr39ukt
UlCBQ9/AUUhLWWCJjAj71NFJO+B/Wgq5BeeczSTS3P0raUZpcKFptoPfkkUzmyAr
Ml6RfjcYB+RgBvzPRkBli+YvLqNWV0fOfBzAYULDeQ4JrRNJG/aHaoQbPa4XieU/
RVtCLeCdtB6Wq0XilBBKY4A5OCb5UglPtfaX3TvhehfWLLMEBGVqFZhq2Ftmj4KT
AGP1v14xN84oZXmAU4RYrkoQI3Q2KSnBDi69owhGtKPJcMKHBIMMPDPATS0ZbeiJ
0k4xW3JfudGp6rWufrCy5diaaBmK07Kt2TRTfvhj7P4gu91IKmwnseaOSpkwLphq
awIDAQAB
-----END PUBLIC KEY-----',
        'partialkey' => false,
    ];
    public $DNProp = [
        'emailAddress' => 'recca0120@gmail.com',
    ];

    protected $privateKey = null;
    protected $publicKey = null;
    protected $p12 = null;
    protected $p12data = null;
    public function __construct()
    {
        $key = $this->generateRSA();
        $this->privateKey = $key['privatekey'];
        $this->publicKey = $key['publickey'];
    }

    private function generateRSA()
    {
        $rsaJSON = 'rsa.json';
        if (empty($this->rsa) === false) {
            $key = $this->rsa;
        } elseif (file_exists($rsaJSON) === true) {
            $key = json_decode($rsaJSON, true);
        } else {
            $rsa = new RSA();
            $key = $rsa->createKey(2048);
            file_put_contents($rsaJSON, json_encode($key));
        }

        return $key;
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

    public function save($result, $path = '')
    {
        $filename = $path.'/'.$this->p12data['subject']['UID'].(strpos($this->p12data['subject']['CN'], 'Production') > -1 ? '.prod' : '.dev').'.pem';
        file_put_contents($filename, $result);
        echo sprintf(
            'Generate <b>%s</b> is valid until %s.<hr>',
            $filename,
            date('d/m/Y', $this->p12data['validTo_time_t'])
        );
    }
}
