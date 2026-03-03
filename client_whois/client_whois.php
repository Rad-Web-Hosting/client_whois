<?php
/**
 * WHMCS Addon: Client WHOIS Lookup
 * File: /modules/addons/client_whois/client_whois.php
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

require_once __DIR__ . '/lib/WhoisClient.php';
require_once __DIR__ . '/lib/WhoisServers.php';

use WHMCS\Database\Capsule;
use ClientWhois\WhoisClient;

/* --------------------------------------------------------------------
 * Module Configuration
 * -------------------------------------------------------------------- */
function client_whois_config()
{
    return [
        "name"        => "Client WHOIS Lookup",
        "description" => "Client-facing WHOIS lookup with strict SLD.TLD validation and optional WHOIS server overrides.",
        "version"     => "1.1.0",
        "author"      => '<a href="https://radwebhosting.com" target="_blank">Rad Web Hosting</a>',
        "fields"      => [
            "pageTitle" => [
                "FriendlyName" => "Client WHOIS",
                "Type"         => "text",
                "Size"         => "40",
                "Default"      => "WHOIS Lookup",
            ],
            "timeout" => [
                "FriendlyName" => "WHOIS Timeout (seconds)",
                "Type"         => "text",
                "Size"         => "5",
                "Default"      => "8",
            ],
            "maxBytes" => [
                "FriendlyName" => "Max Bytes to Read",
                "Type"         => "text",
                "Size"         => "8",
                "Default"      => "200000",
            ],
            "allowPrivateTlds" => [
                "FriendlyName" => "Allow Non-Listed TLDs",
                "Type"         => "yesno",
                "Default"      => "",
                "Description"  => "If unchecked, TLD must exist in config/tlds.php",
            ],
        ],
    ];
}

function client_whois_activate()
{
    try {
        Capsule::schema()->create('mod_client_whois_servers', function ($table) {
            $table->increments('id');
            $table->string('tld', 255)->unique();
            $table->string('server', 255);
            $table->integer('port')->default(43);
            $table->boolean('active')->default(true);
            $table->timestamps();
        });
    } catch (\Exception $e) {
        // table may already exist
    }

    return [
        'status' => 'success',
        'description' => 'Client WHOIS Lookup activated with WHOIS server management'
    ];
}

function client_whois_deactivate()
{
    return ["status" => "success", "description" => "Client WHOIS Lookup deactivated"];
}

/* --------------------------------------------------------------------
 * Client Area Controller
 * -------------------------------------------------------------------- */
function client_whois_clientarea($vars)
{
    $modulelink = $vars['modulelink'];
    $pageTitle  = trim($vars['pageTitle'] ?? 'WHOIS Lookup');
    $timeout    = (int)($vars['timeout'] ?? 8);
    $maxBytes   = (int)($vars['maxBytes'] ?? 200000);
    $allowAny   = !empty($vars['allowPrivateTlds']);

    $timeout  = ($timeout >= 2 && $timeout <= 30) ? $timeout : 8;
    $maxBytes = ($maxBytes >= 5000 && $maxBytes <= 2000000) ? $maxBytes : 200000;

    $domainInput = '';
    $whoisText   = '';
    $error       = '';
    $didLookup   = false;

    // Load allowed TLDs
    $allowedTlds = client_whois_allowed_tlds();
    $allowedSet  = client_whois_build_allowed_set($allowedTlds);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $didLookup   = true;
        $domainInput = trim($_POST['domain'] ?? '');

        $normalized = client_whois_normalize_domain($domainInput);
        if ($normalized === '') {
            $error = "Please enter a domain in the format example.tld";
        } else {
            $parts = client_whois_split_sld_tld($normalized);
            if ($parts === null) {
                $error = "Invalid domain format. Only <second-level>.<tld> is allowed.";
            } else {
                [$sld, $tld] = $parts;

                if (!client_whois_valid_sld($sld)) {
                    $error = "Invalid second-level domain (SLD).";
                } else {
                    $tldKey = client_whois_mb_lower($tld);

                    if (!$allowAny && !isset($allowedSet[$tldKey])) {
                        $error = "That TLD is not allowed.";
                    } else {
                        $lookupDomain = client_whois_to_ascii_domain($sld . '.' . $tld);

                        try {
                            $client = new WhoisClient([
                                'timeout'  => $timeout,
                                'maxBytes' => $maxBytes,
                                'cacheTtl' => 3600, // seconds (1 hour)
                                'cacheDir' => __DIR__ . '/cache',
                            ]);

                            $whoisText = $client->lookup($lookupDomain);
                            if ($whoisText === '') {
                                $error = "WHOIS lookup returned no data.";
                            }
                        } catch (\Throwable $e) {
                            $error = "WHOIS lookup failed: " . $e->getMessage();
                        }
                    }
                }
            }
        }
    }

    return [
        'pagetitle'    => $pageTitle,
        'breadcrumb'   => [
            'index.php?m=client_whois' => $pageTitle,
        ],
        'templatefile' => 'clientarea',
        'requirelogin' => false,
        'vars'         => [
            'modulelink'  => $modulelink,
            'pageTitle'   => $pageTitle,
            'domainInput' => $domainInput,
            'didLookup'   => $didLookup,
            'whoisText'   => $whoisText,
            'error'       => $error,
        ],
    ];
}

/* --------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------- */
function client_whois_allowed_tlds(): array
{
    $file = __DIR__ . '/config/tlds.php';
    if (!file_exists($file)) {
        return [];
    }

    $tlds = require $file;
    return is_array($tlds) ? $tlds : [];
}

function client_whois_build_allowed_set(array $tlds): array
{
    $set = [];
    foreach ($tlds as $tld) {
        $tld = ltrim(client_whois_mb_lower(trim($tld)), '.');
        if ($tld === '') {
            continue;
        }

        $set[$tld] = true;

        if (function_exists('idn_to_ascii')) {
            $ascii = @idn_to_ascii($tld, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii) {
                $set[strtolower($ascii)] = true;
            }
        }
    }
    return $set;
}

function client_whois_normalize_domain(string $input): string
{
    $input = trim($input);
    if ($input === '') {
        return '';
    }

    $input = preg_replace('~^[a-z]+://~i', '', $input);
    $input = preg_replace('~[/\?#].*$~', '', $input);
    $input = trim($input, " \t\n\r\0\x0B.");
    $input = preg_replace('~\.+~', '.', $input);

    return client_whois_mb_lower($input);
}

function client_whois_split_sld_tld(string $domain): ?array
{
    if (substr_count($domain, '.') !== 1) {
        return null;
    }

    [$sld, $tld] = explode('.', $domain, 2);
    return ($sld !== '' && $tld !== '') ? [$sld, $tld] : null;
}

function client_whois_valid_sld(string $sld): bool
{
    if (strlen($sld) < 1 || strlen($sld) > 63) {
        return false;
    }
    if ($sld[0] === '-' || substr($sld, -1) === '-') {
        return false;
    }
    return (bool)preg_match('/^[a-z0-9-]+$/', $sld);
}

function client_whois_mb_lower(string $str): string
{
    return function_exists('mb_strtolower')
        ? mb_strtolower($str, 'UTF-8')
        : strtolower($str);
}

function client_whois_to_ascii_domain(string $domain): string
{
    if (!function_exists('idn_to_ascii')) {
        return $domain;
    }

    $ascii = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    return $ascii ? strtolower($ascii) : $domain;
}

function client_whois_output($vars)
{
    $action = $_REQUEST['action'] ?? 'list';

    echo '<h2>Client WHOIS – WHOIS Server Overrides</h2>';

    switch ($action) {
        case 'add':
            client_whois_admin_add();
            break;

        case 'edit':
            client_whois_admin_edit((int)($_REQUEST['id'] ?? 0));
            break;

        case 'delete':
            client_whois_admin_delete((int)($_REQUEST['id'] ?? 0));
            break;

        default:
            client_whois_admin_list();
    }
}

function client_whois_admin_list()
{
    $rows = Capsule::table('mod_client_whois_servers')
        ->orderBy('tld')
        ->get();

    echo '<p><a href="?module=client_whois&action=add" class="btn btn-primary">Add WHOIS Server</a></p>';

    echo '<table class="table table-striped">';
    echo '<tr>
            <th>TLD</th>
            <th>WHOIS Server</th>
            <th>Port</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>';

    foreach ($rows as $row) {
        echo '<tr>
                <td>.' . htmlspecialchars($row->tld) . '</td>
                <td>' . htmlspecialchars($row->server) . '</td>
                <td>' . (int)$row->port . '</td>
                <td>' . ($row->active ? 'Active' : 'Disabled') . '</td>
                <td>
                    <a href="?module=client_whois&action=edit&id=' . $row->id . '">Edit</a> |
                    <a href="?module=client_whois&action=delete&id=' . $row->id . '" onclick="return confirm(\'Delete this entry?\')">Delete</a>
                </td>
              </tr>';
    }

    echo '</table>';
}

function client_whois_admin_add()
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Capsule::table('mod_client_whois_servers')->insert([
            'tld'        => strtolower(trim(ltrim($_POST['tld'], '.'))),
            'server'     => trim($_POST['server']),
            'port'       => (int)($_POST['port'] ?? 43),
            'active'     => isset($_POST['active']) ? 1 : 0,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

        header('Location: ?module=client_whois');
        exit;
    }

    echo client_whois_admin_form();
}

function client_whois_admin_edit(int $id)
{
    $row = Capsule::table('mod_client_whois_servers')->where('id', $id)->first();
    if (!$row) {
        echo '<div class="alert alert-danger">Entry not found</div>';
        return;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Capsule::table('mod_client_whois_servers')
            ->where('id', $id)
            ->update([
                'tld'        => strtolower(trim(ltrim($_POST['tld'], '.'))),
                'server'     => trim($_POST['server']),
                'port'       => (int)($_POST['port'] ?? 43),
                'active'     => isset($_POST['active']) ? 1 : 0,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);

        header('Location: ?module=client_whois');
        exit;
    }

    echo client_whois_admin_form($row);
}

function client_whois_admin_delete(int $id)
{
    Capsule::table('mod_client_whois_servers')->where('id', $id)->delete();
    header('Location: ?module=client_whois');
    exit;
}

function client_whois_admin_form($row = null)
{
    $tld    = $row->tld ?? '';
    $server = $row->server ?? '';
    $port   = $row->port ?? 43;
    $active = isset($row->active) ? (bool)$row->active : true;

    return '
    <form method="post">
        <div class="form-group">
            <label>TLD (without dot)</label>
            <input type="text" name="tld" class="form-control" value="' . htmlspecialchars($tld) . '" required>
        </div>

        <div class="form-group">
            <label>WHOIS Server</label>
            <input type="text" name="server" class="form-control" value="' . htmlspecialchars($server) . '" required>
        </div>

        <div class="form-group">
            <label>Port</label>
            <input type="number" name="port" class="form-control" value="' . (int)$port . '">
        </div>

        <div class="checkbox">
            <label>
                <input type="checkbox" name="active" ' . ($active ? 'checked' : '') . '> Active
            </label>
        </div>

        <button type="submit" class="btn btn-success">Save</button>
        <a href="?module=client_whois" class="btn btn-default">Cancel</a>
    </form>';
}