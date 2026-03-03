{* /modules/addons/client_whois/templates/clientarea.tpl *}

<link rel="stylesheet" href="{$modulelink}/templates/style.css" />

<div class="client-whois-wrap">
  <h1 class="client-whois-title">{$pageTitle|escape}</h1>

  <form method="post" action="{$modulelink}" class="client-whois-form" autocomplete="off">
    <label for="whoisDomain" class="client-whois-label">Domain</label>
    <div class="client-whois-row">
      <input
        type="text"
        id="whoisDomain"
        name="domain"
        class="client-whois-input"
        value="{$domainInput|escape}"
        placeholder="example.com"
        inputmode="url"
        autocapitalize="none"
        spellcheck="false"
        maxlength="253"
        aria-label="Domain name for WHOIS lookup"
        required
      />
      <button type="submit" class="client-whois-btn">Lookup</button>
    </div>
    <div class="client-whois-hint">Format: <code>example.tld</code> (exactly one dot).</div>
  </form>

  {if $didLookup}
    {if $error}
      <div class="client-whois-alert client-whois-alert-error">{$error|escape}</div>
    {else}
      <div class="client-whois-result">
        <h3 class="client-whois-subtitle">WHOIS Result</h3>
        <pre class="client-whois-pre">{$whoisText|escape}</pre>
      </div>
    {/if}
  {/if}
</div>