<?php
namespace ClientWhois;

use ClientWhois\WhoisServers;

class WhoisClient
{
    protected int $timeout;
    protected int $maxBytes;
    protected int $cacheTtl;
    protected string $cacheDir;

    public function __construct(array $opts = [])
    {
        $this->timeout  = (int)($opts['timeout'] ?? 8);
        $this->maxBytes = (int)($opts['maxBytes'] ?? 200000);

        $this->cacheTtl = (int)($opts['cacheTtl'] ?? 3600); // 1 hour default
        $this->cacheDir = $opts['cacheDir']
            ?? __DIR__ . '/../cache';

        if ($this->timeout < 2 || $this->timeout > 30) {
            $this->timeout = 8;
        }

        if ($this->maxBytes < 5000 || $this->maxBytes > 2000000) {
            $this->maxBytes = 200000;
        }

        if ($this->cacheTtl < 60) {
            $this->cacheTtl = 60;
        }
    }

    /**
     * Main WHOIS lookup with cache
     */
    public function lookup(string $domain): string
    {
        $domain = strtolower(trim($domain));
        if ($domain === '') {
            throw new \RuntimeException("Empty domain.");
        }

        // 1️⃣ Cache hit?
        $cached = $this->getCache($domain);
        if ($cached !== null) {
            return $cached;
        }

        // 2️⃣ Perform live lookup
        $labels = explode('.', $domain);
        $tld    = end($labels);

        // Custom WHOIS server override
        $customServer = WhoisServers::forTld($tld);
        if ($customServer) {
            $result = $this->queryServer($customServer, $domain);
            $this->setCache($domain, $result);
            return $result;
        }

        // Default: IANA → referral
        $ianaOutput = $this->queryServer('whois.iana.org', $domain);
        $referral   = $this->parseReferralServer($ianaOutput);

        if ($referral !== '') {
            $out = $this->queryServer($referral, $domain);
            $final = $out !== '' ? $out : $ianaOutput;
        } else {
            $final = $ianaOutput;
        }

        $this->setCache($domain, $final);
        return $final;
    }

    /* ---------------------------------------------------------
     * Cache helpers
     * --------------------------------------------------------- */

    protected function getCache(string $domain): ?string
    {
        $file = $this->cacheFile($domain);

        if (!is_file($file)) {
            return null;
        }

        if (filemtime($file) + $this->cacheTtl < time()) {
            @unlink($file);
            return null;
        }

        $data = file_get_contents($file);
        return $data !== false ? $data : null;
    }

    protected function setCache(string $domain, string $data): void
    {
        if (!is_dir($this->cacheDir)) {
            return;
        }

        $file = $this->cacheFile($domain);
        @file_put_contents($file, $data, LOCK_EX);
    }

    protected function cacheFile(string $domain): string
    {
        return rtrim($this->cacheDir, '/')
            . '/whois_' . sha1($domain) . '.txt';
    }

    /* ---------------------------------------------------------
     * WHOIS internals
     * --------------------------------------------------------- */

    protected function parseReferralServer(string $ianaOutput): string
    {
        $patterns = [
            '/^\s*refer:\s*(\S+)\s*$/mi',
            '/^\s*whois:\s*(\S+)\s*$/mi',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $ianaOutput, $m)) {
                return strtolower(trim($m[1]));
            }
        }

        return '';
    }

    protected function queryServer(string $server, string $query): string
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, $this->timeout);
        if (!$fp) {
            throw new \RuntimeException(
                "Unable to connect to WHOIS server {$server} ({$errno}: {$errstr})"
            );
        }

        stream_set_timeout($fp, $this->timeout);
        fwrite($fp, $query . "\r\n");

        $data = '';
        while (!feof($fp)) {
            $chunk = fread($fp, 2048);
            if ($chunk === false) {
                break;
            }

            $data .= $chunk;

            if (strlen($data) >= $this->maxBytes) {
                $data = substr($data, 0, $this->maxBytes)
                      . "\n\n[WHOIS output truncated]\n";
                break;
            }
        }

        fclose($fp);
        return $data;
    }
}