# Minisign (PHP)

[![Support on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.herokuapp.com%2Fsoatok&style=flat)](https://patreon.com/soatok)
[![Linux Build Status](https://travis-ci.org/soatok/minisign-php.svg?branch=master)](https://travis-ci.org/soatok/minisign-php)
[![Latest Stable Version](https://poser.pugx.org/soatok/minisign/v/stable)](https://packagist.org/packages/soatok/minisign-php)
[![Latest Unstable Version](https://poser.pugx.org/soatok/minisign/v/unstable)](https://packagist.org/packages/soatok/minisign-php)
[![License](https://poser.pugx.org/soatok/minisign/license)](https://packagist.org/packages/soatok/minisign-php)
[![Downloads](https://img.shields.io/packagist/dt/soatok/minisign.svg)](https://packagist.org/packages/soatok/minisign-php)

PHP implementation of [Minisign](https://jedisct1.github.io/minisign/).
Powered by Libsodium.

## Installing

```terminal
composer require soatok/minisign
```

## Usage (Command Line)

### Creating a key pair

```terminal
vendor/bin/minisign -G
```

### Signing a file

```terminal
vendor/bin/minisign -Sm myfile.txt
```

Or to include a comment in the signature, that will be verified and displayed when verifying the file:

```terminal
vendor/bin/minisign -Sm myfile.txt -t 'This comment will be signed as well'
```

The signature is put into myfile.txt.minisig.

Multiple files can also be signed at once:

```terminal
vendor/bin/minisign -Sm file1.txt file2.txt *.jpg
```

### Verifying a file

```terminal
vendor/bin/minisign -Vm myfile.txt -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

or

```terminal
vendor/bin/minisign -Vm myfile.txt -p signature.pub
```

This requires the signature `myfile.txt.minisig` to be present in the same directory.

The public key can either reside in a file (`./minisign.pub` by default) or be directly specified on the command line.

## Usage (PHP Code)

### Creating a key pair

```php
<?php
use Soatok\Minisign\Core\SecretKey;

$secretKey = SecretKey::generate();
$password = 'correct horse battery staple';
$saveToFile = $secretKey->serialize($password);
\file_put_contents('/path/to/secret.key', $saveToFile);
```

### Signing a file

```php
<?php
use Soatok\Minisign\Core\SecretKey;
use Soatok\Minisign\Core\File\MessageFile;

$trustedComment = 'Trusted comment goes here';
$untrustedComment = 'Untrusted comment; can be changed';
$password = 'correct horse battery staple';
$preHash = false; // Set to TRUE to prehash the file

$secretKey = SecretKey::fromFile('/path/to/secret.key', $password);
$fileToSign = MessageFile::fromFile('/path/to/file');
$signature = $fileToSign->sign(
    $secretKey,
    $preHash,
    $trustedComment,
    $untrustedComment
);

\file_put_contents(
    '/path/to/file.minisig',
    $signature->toSigFile()->getContents()
);
```

### Verifying a file

```php
<?php
use Soatok\Minisign\Core\PublicKey;
use Soatok\Minisign\Core\File\{
    MessageFile,
    SigFile
};

$pk = PublicKey::fromFile('/path/to/minisign.pub');
$fileToCheck = MessageFile::fromFile('/path/to/file');
$signature = SigFile::fromFile('/path/to/file.minisig')->deserialize();
if (!$fileToCheck->verify($pk, $signature)) {
    echo 'Invalid signature!', PHP_EOL;
    exit(1);
}
$trusted = $signature->getTrustedComment();
```
