<?php
namespace ClientWhois;

use WHMCS\Database\Capsule;

class WhoisServers
{
    public static function forTld(string $tld): ?string
    {
        $tld = strtolower(ltrim($tld, '.'));

        // 1) DB override
        $row = Capsule::table('mod_client_whois_servers')
            ->where('tld', $tld)
            ->where('active', 1)
            ->first();

        if ($row) {
            return $row->server;
        }

        // 2) Static fallback
        $static = self::staticMap();
        return $static[$tld] ?? null;
    }

    protected static function staticMap(): array
    {
        return [
            'com' => 'whois.verisign-grs.com',
            'net' => 'whois.verisign-grs.com',
            'org' => 'whois.pir.org',
        ];
    }
}
