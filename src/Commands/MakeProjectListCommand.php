<?php

namespace App\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use phpseclib\Net\SSH2;
use phpseclib\Net\SFTP;
use phpseclib\Crypt\RSA;
use DOMDocument;
use InvalidArgumentException;
use RuntimeException;

class MakeProjectListCommand extends Command
{
  protected $input;

  protected $output;

  protected $cacheBaseDirectory;
  protected $cacheDuration;

  protected $domainHints = [];
  protected $urlHints = [];
  protected $markedAddresses = [];

  protected $address;

  const HTML_TABLE_STYLE = <<<CSS
body
{
  font-family: sans-serif;
  font-size: 12px;
}

table
{
  border-collapse: collapse;
  font-size: 1em;

  margin: 0 auto;

  min-width: 100%;
}

td
{
  border: solid 1px black;
  padding: 4px;
}

.fatal
{
  background-color: red;
  color: white;
  font-weight: bold;
}

.error
{
  background-color: #FFCC99;
  font-weight: bold;
}

.success
{
  background-color: #99FF99;
  color: black;
  font-weight: bold;
}

.hinted-domain, .hinted-url
{
  background-color: #FFFF99;
}

.hinted-domain.hinted-url
{
  background-color: #C5FF99;
}

.header
{
  font-weight: bold;
}

table td a
{
  display: inline-block;

  padding: 2px 6px;
  background-color: white;
  border: solid 1px black;

  color: #0000EE;
  text-decoration: underline;
}

table td code.status
{
  display: inline-block;

  padding: 2px 6px;
  background-color: white;
  border: solid 1px black;

  color: black;
}

.emphasis
{
  text-decoration: underline;
  display: inline-block;

  padding: 2px;
  margin: 0px 6px;
}

.emphasis.home
{
  background-color: #FFCCCC;
}

.emphasis.domain, .emphasis.public
{
  font-weight: bold;

  background-color: #CCFFCC;
}
CSS;

  protected function configure()
  {
    $this
      ->setName('project-list')
      ->setDescription('Helps to retrieve a list of projects on a remote server.')

      ->addOption('username', 'u', InputOption::VALUE_REQUIRED, 'Username used to connect to remote server.', 'root')
      ->addOption('password', null, InputOption::VALUE_REQUIRED, 'Password used to connect to remote server if using password authentication, or password for the key if using key authentication.'. null)
      ->addOption('key', 'k', InputOption::VALUE_REQUIRED, 'Key used to connect to remote server.')
      // ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'The type for the given key.', 'rsa')

      ->addOption('port', 'p', InputOption::VALUE_REQUIRED, 'Port to use for connection.', 22)

      ->addOption('hint', null, InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED, 'Domain/URL to hint in the result.')
      ->addOption('mark', null, InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED, 'Will mark projects resolved to this IP.')

      ->addOption('cache', null, InputOption::VALUE_REQUIRED, 'Base directory to use for cache.', getcwd())
      ->addOption('cache-ttl', null, InputOption::VALUE_REQUIRED, 'Cache TTL (in seconds).', 60 * 60 * 5)

      // ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Format used to export results.', 'html')

      ->addArgument('address', InputArgument::REQUIRED, 'Remote server address to connect to.')

      ->addArgument('root', InputArgument::IS_ARRAY | InputArgument::REQUIRED, 'Absolute path to remote directory to search for projects.')
    ;
  }

  protected function globalizeSettings(InputInterface $input, OutputInterface $output)
  {
    $this->input = $input;
    $this->output = $output;

    $this->cacheBaseDirectory = $this->input->getOption('cache');
    $output->writeln(sprintf('<info>Cache directory: %s</info>', $this->cacheBaseDirectory));

    $cacheDuration = $this->input->getOption('cache-ttl');

    if (!is_numeric($cacheDuration)) {
      throw new InvalidArgumentException(sprintf('Cache duration is not a number (%s).', $cacheDuration));
    } else {
      $this->cacheDuration = (float) $cacheDuration;
    }

    $this->setupHints();
    $this->setupMarks();
  }

  protected function setupHints()
  {
    $hints = $this->input->getOption('hint');

    $urls = [];
    $domains = [];

    foreach ($hints as $hint) {
      if (strpos($hint, 'http') === 0) {
        $urls[] = $hint;
      } else {
        $urls[] = $domains;
      }
    }

    $this->domainHints = $domains;
    $this->urlHints = $urls;
  }

  protected function setupMarks()
  {
    $marks = $this->input->getOption('mark');

    $ips = [];

    foreach ($marks as $mark) {
      $ip4 = filter_var($mark, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE);

      if ($ip4 !== false) {
        $ips[] = $ip4;
      } else {
        $this->output->writeln(sprintf('<error>Cannot resolve marked address (%s). Skipping.</error>', $mark));
      }
    }

    $this->markedAddresses = $ips;
  }

  protected function execute(InputInterface $input, OutputInterface $output)
  {
    set_time_limit(0);

    $key = $input->getOption('key');
    $password = $input->getOption('password');

    if (!$key && !$password) {
      throw new InvalidArgumentException('You have to specify key or password to connect to the remote.');
    }

    $address = $input->getArgument('address');
    $port = intval($input->getOption('port'), 10);

    $sftp = new SFTP($address, $port);

    $access = null;

    if ($key) {
      $access = $this->loadKey($key, $password);
    } else {
      $access = $password;
    }

    if (!$sftp->login($username = $input->getOption('username'), $access)) {
      throw new RuntimeException(sprintf('Could not connect to remote host (%s:%d) using the given username (%s) and access method (%s).', $address, $port, $username, ($access instanceof RSA) ? 'key:' . realpath($key) : 'password'));
    }

    $this->globalizeSettings($input, $output);
    $this->address = $address;

    $destination = implode(':', [$address, $port]);
    $output->writeln(sprintf('<info>Connected to %s</info>', $destination));

    $roots = [];

    foreach ($input->getArgument('root') as $root) {
      $folder = $root;
      $baseUrl = null;

      if (count($parts = explode(':', $root)) === 2) {
        $folder = $parts[0];
        $baseUrl = $parts[1];
      }

      if ($folder[0] !== '/') {
        $output->writeln(sprintf('<error>Folder (%s) specified with a relative path instead of absolute. Skipping.</error>', $folder));
        continue;
      }

      // Resolve realpath and exclude if not found.
      if (!($realpath = $sftp->realpath($folder))) {
        $output->writeln(sprintf('<error>The folder (%s) could not be found on the remote server. Skipping.</error>', $folder));
        continue;
      }

      $roots[] = [
        'realpath' => $realpath,
        'baseUrl' => $baseUrl
      ];
    }

    // Go through all of the provided roots and resolve folders.
    foreach ($roots as &$root) {
      foreach ($sftp->rawlist($folder = $root['realpath']) as $entry) {
        $filename = $entry['filename'];

        // Ignore dot paths and files.
        if ($filename === '.' || $filename === '..' || $entry['type'] === 1) {
          continue;
        }

        // Construct a relative path and resolve to realpath.
        $path = $sftp->realpath($folder . '/' . $filename);

        $resolveLink = function ($path, &$hops = null) use ($sftp, &$resolveLink) {
          $link = $sftp->readlink($path);

          // If absolute path gets resolved, it's already resolved.
          if ($link[0] === '/') {
            $linkPath = $link;
          // Relative path. We match it against the dirname of base path.
          // Also resolve.
          } else {
            $dirname = dirname($path);
            $linkPath = $sftp->realpath($dirname . '/' . $link);
          }

          // Link resolved, lstat it, in case it's another link.
          $stat = $sftp->lstat($linkPath);

          // On first request, initialize hops.
          if (is_null($hops)) {
            $hops = [];
          }

          $hops[] = ['realpath' => $linkPath, 'stat' => $stat];

          // Still a link? Recurse.
          if ($stat['type'] === 3) {
            $resolveLink($linkPath, $hops);
          }

          return $hops;
        };

        $normalizedEntry = ['realpath' => $path, 'stat' => $entry, 'root' => false];

        if ($entry['type'] === 3) {
          $hops = $resolveLink($path);
          $lastHop = &$hops[count($hops) - 1];

          // We have resolved to a file, not interested.
          if ($lastHop['stat']['type'] === 1) {
            continue;
          }

          $normalizedEntry['hops'] = $hops;
          $normalizedEntry['real'] = &$lastHop;
        }

        foreach ($roots as $_root) {
          if ($_root['realpath'] === $normalizedEntry['realpath']
              || (array_key_exists('real', $normalizedEntry)
                && $root === $normalizedEntry['real']['realpath'])) {
            $normalizedEntry['root'] = true;
            break;
          }
        }

        // Do not test roots themselves.
        if ($normalizedEntry['root']) {
          continue;
        }

        if (!array_key_exists('entries', $root)) {
          $root['entries'] = [];
        }

        $root['entries'][] = $normalizedEntry;
      }

      usort($root['entries'], function ($a, $b) {
        return strcmp($a['realpath'], $b['realpath']);
      });
    }

    $urls = [];

    foreach ($roots as $root) {
      $baseUrl = $root['baseUrl'];

      foreach ($root['entries'] as $entry) {
        $origin = basename($entry['realpath']);

        $result = [
          'path' => $entry['realpath'],
          'origin' => $origin,
          'baseUrl' => $baseUrl,
          'url' => $this->combineUrl($origin, $baseUrl),
        ];

        if (array_key_exists('real', $entry) && $entry['real']['realpath'] !== $entry['realpath']) {
          $result['sourcepath'] = $entry['real']['realpath'];
        }

        $urls[] = $result;
      }
    }

    $results = [];

    foreach ($urls as $url) {
      $directory = array_key_exists('directory', $url) ? $url['directory'] : $url['url'];

      $data = $this->testUrlsData($url['url']);

      if (!empty($data['url']) && empty($directory)) {
        $directory = $data['url'];
      }

      $results[] = [
        'url' => $url,
        'data' => $data,
        'directory' => $directory
      ];
    }

    $this->generateResultHtml($results, $this->markedAddresses, $this->domainHints, $this->urlHints);
  }

  protected function loadKey($key, $password = null)
  {
    $rsa = new RSA();

    if (!is_null($password)) {
      $rsa->setPassword($password);
    }

    if (!$rsa->loadKey(file_get_contents($key))) {
      throw new RuntimeException('Could not load RSA key.');
    }

    return $rsa;

    /*$keyType = $this->getOption('key-type');

    if (!$keyType) {
      $rsa = new RSA();
      $rsa->loadKey($this->getOption('key'));
    } else {
      switch (strtolower($keyType)) {
        case ''
      }
    }*/
  }

  protected function testUrlsData($url)
  {
    $output = [
      'url' => $url,
      'fatal' => [],
      'hints' => [],
      'addresses' => [],
      'hostname' => null,
      'http' => null,
      'https' => null
    ];

    if (strpos($url, '.') === false)
    {
      $output['fatal'][] = 'Not checking URLs without dots.';
      $output['hints'][] = 'Probably a system URL.';
    }
    else
    {
      $http = filter_var('http://' . $url, FILTER_VALIDATE_URL);
      $https = filter_var('https://' . $url, FILTER_VALIDATE_URL);

      $parsed = parse_url($http);

      if (!empty($parsed['host'])) {
        $output['addresses'] = $this->testHost($parsed['host']);
        $output['hostname'] = $parsed['host'];
      }

      $any = false;

      if (!empty($http))
      {
        $any = true;
        $output['http'] = $this->testUrl($http);
      }

      if (!empty($https))
      {
        $any = true;
        $output['https'] = $this->testUrl($https);
      }

      if (!$any)
      {
        $output['fatal'][] = 'No valid URLs resolved.';
      }
    }

    return $output;
  }

  protected function getCachedResult($store, callable $callback)
  {
    $directory = dirname($store);

    if (!file_exists($directory))
    {
      mkdir($directory, 0755, true);
    }

    if (file_exists($store) && $this->cacheDuration > 0 && time() - filemtime($store) < $this->cacheDuration)
    {
      return json_decode(file_get_contents($store), true);
    }

    // Does not exist.
    $data = $callback();

    file_put_contents($store, json_encode($data));

    return $data;
  }

  protected function testUrl($url)
  {
    return $this->getCachedResult($this->cacheBaseDirectory . '/uc/' . str_slug($url), function () use ($url) {
      $handle = curl_init($url);

      $ua = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36';
      curl_setopt($handle, CURLOPT_USERAGENT, $ua);

      curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($handle, CURLOPT_HEADER, true);
      curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($handle, CURLOPT_FRESH_CONNECT, true);

      $response = curl_exec($handle);

      $status = curl_getinfo($handle, CURLINFO_HTTP_CODE);
      $effective_url = curl_getinfo($handle, CURLINFO_EFFECTIVE_URL);

      $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
      $headers = substr($response, 0, $header_size);
      $body = substr($response, $header_size);

      $errno = curl_errno($handle);
      $error = curl_error($handle);

      $data = [
        'status' => $status,
        'headers' => $headers,
        'body' => substr($body, 0, 1024),
        'errno' => $errno,
        'error' => $error,
        'initial_url' => $url,
        'effective_url' => $effective_url
      ];

      return $data;
    });
  }

  protected function testHost($host)
  {
    return $this->getCachedResult($this->cacheBaseDirectory . '/hc/' . str_slug($host), function () use ($host) {
      return gethostbynamel($host);
    });
  }

  protected function combineUrl($origin, $base = '')
  {
    $url = $origin;

    if (!empty($base))
    {
      $url = $base . '/' . $url;
    }

    return $this->replaceDoubleSlashes($url);
  }

  protected function replaceDoubleSlashes($entry)
  {
    $forward = preg_replace('/\/\/+/', '/', $entry);
    $back = preg_replace('/\\\\+/', '\\', $forward);

    return $back;
  }

  protected function generateResultHtml($urls, $ourAddresses = array(), $hintedDomains = array(), $hintedUrls = array())
  {
    $originalDomainHints = $hintedDomains;
    $originalUrlHints = $hintedUrls;

    $totalUrls = count($urls);
    $currentUrl = 1;

    $dom = new DOMDocument;
    $dom->preserveWhiteSpace = true;
    $dom->formatOutput = true;

    $dom->loadHTML('<body></body>');

    $body = $dom->getElementsByTagName('body')->item(0);

    $head = $dom->createElement('head');
    $dom->documentElement->insertBefore($head, $body);

    // Embed.
    $stylesheet = $dom->createElement('style');
    $stylesheet->setAttribute('type', 'text/css');
    $stylesheet->nodeValue = static::HTML_TABLE_STYLE;
    $head->appendChild($stylesheet);

    $siteTable = $this->generateTableHeaders('Servera Mape', $dom);
    $body->appendChild($siteTable);
    $this->generateResultRows($urls, $currentUrl, $totalUrls, $dom, $siteTable, $ourAddresses, $hintedDomains, $hintedUrls);

    if (count($hintedDomains))
    {
      $remainderDomainHeader = $dom->createElement('h2');
      $remainderDomainHeader->nodeValue = 'Neatrasta domēnu saikne ar servera mapēm:';
      $body->appendChild($remainderDomainHeader);

      $totalDomainHints = count($hintedDomains);
      $currentDomainHint = 1;

      $leftOverHintedDomainTable = $this->generateTableHeaders('Domēns', $dom);
      $body->appendChild($leftOverHintedDomainTable);
      $this->generateResultRows(array_map(array($this, 'folderizeDomain'), $hintedDomains), $currentDomainHint, $totalDomainHints, $dom, $leftOverHintedDomainTable, $ourAddresses, $hintedDomains, $hintedUrls);
    }

    if (count($originalDomainHints))
    {
      $requestedDomainHeader = $dom->createElement('h2');
      $requestedDomainHeader->nodeValue = 'Kopā tika pieprasīta domēnu saikne šādiem domēniem:';
      $body->appendChild($requestedDomainHeader);

      $requestedList = $dom->createElement('ul');
      $body->appendChild($requestedList);

      foreach ($originalDomainHints as $originalHint)
      {
        $listItem = $dom->createElement('li');
        $listItem->nodeValue = $originalHint;
        $requestedList->appendChild($listItem);
      }
    }

    if (count($hintedUrls))
    {
      $remainderUrlHeader = $dom->createElement('h2');
      $remainderUrlHeader->nodeValue = 'Neatrasta ceļu saikne ar servera mapēm:';
      $body->appendChild($remainderUrlHeader);

      $totalUrlHints = count($hintedUrls);
      $currentUrlHint = 1;

      $leftOverHintedUrlTable = $this->generateTableHeaders('Mape', $dom);
      $body->appendChild($leftOverHintedUrlTable);
      $this->generateResultRows(array_map(array($this, 'folderizeUrl'), $hintedUrls), $currentUrlHint, $totalUrlHints, $dom, $leftOverHintedUrlTable, $ourAddresses, $hintedDomains, $hintedUrls);
    }

    if (count($originalUrlHints))
    {
      $requestedUrlHeader = $dom->createElement('h2');
      $requestedUrlHeader->nodeValue = 'Kopā tika pieprasīta ceļu saikne šādiem ceļiem:';
      $body->appendChild($requestedUrlHeader);

      $requestedList = $dom->createElement('ul');
      $body->appendChild($requestedList);

      foreach ($originalUrlHints as $originalHint)
      {
        $listItem = $dom->createElement('li');
        $listItem->nodeValue = $originalHint;
        $requestedList->appendChild($listItem);
      }
    }

    $dom->saveHTMLFile($this->address . '-' . time() . '.html');
  }

  protected function generateTableHeaders($firstColumn, $dom)
  {
    $table = $dom->createElement('table');

    $headerRow = $dom->createElement('tr');
    $headerRow->setAttribute('class', 'headers');
    $table->appendChild($headerRow);

    // Directory header.
    $directoryHeading = $dom->createElement('th');
    $directoryHeading->nodeValue = $firstColumn;
    $directoryHeading->setAttribute('class', 'directory');

    // HTTP header.
    $httpHeader = $dom->createElement('th');
    $httpHeader->nodeValue = 'HTTP';
    $httpHeader->setAttribute('class', 'http');

    // HTTPS header.
    $httpsHeader = $dom->createElement('th');
    $httpsHeader->nodeValue = 'HTTPS';
    $httpsHeader->setAttribute('class', 'https');

    // Addresses header.
    $addressesHeader = $dom->createElement('th');
    $addressesHeader->nodeValue = 'Adreses';
    $addressesHeader->setAttribute('class', 'addresses');

    $headerRow->appendChild($directoryHeading);
    $headerRow->appendChild($httpHeader);
    $headerRow->appendChild($httpsHeader);
    $headerRow->appendChild($addressesHeader);

    return $table;
  }

  protected function generateResultRows($urls, &$current, $total, $dom, $table, $ourAddresses, &$hintedDomains, &$hintedUrls)
  {
    $singleLineInfoFormat = '<code class="info">%s</code>';
    $multiLineInfoFormat = '<pre class="info">%s</pre>';
    $unsetMessage = htmlspecialchars('<unset>');
    $invalidUrlMessage = htmlspecialchars('<invalid URL>');
    $noAddressesMessage = htmlspecialchars('<no addresses>');

    foreach ($urls as $url)
    {
      $row = $dom->createElement('tr');
      $row->setAttribute('class', 'entry');
      $table->appendChild($row);

      $urlData = $url['data'];
      $directory = $url['directory'];

      $current++;

      $hintedDomain = empty($urlData['error']) ? in_array($urlData['hostname'], $hintedDomains) : false;

      if ($hintedDomain) {
        if (($hintedDomainKey = array_search($urlData['hostname'], $hintedDomains)) >= 0) {
          unset($hintedDomains[$hintedDomainKey]);
        }
      }

      $urlForHinting = preg_replace('/^https?:\/\//', 'http://', $urlData['url']);
      if (stripos($urlForHinting, 'http://') !== 0) {
        $urlForHinting = 'http://' . $urlForHinting;
      }

      $hintedUrl = in_array($urlForHinting, $hintedUrls);

      if ($hintedUrl) {
        if (($hintedUrlKey = array_search($urlForHinting, $hintedUrls)) >= 0) {
          unset($hintedUrls[$hintedUrlKey]);
        }
      }

      $directoryNode = $dom->createElement('td');
      $directoryFragment = $dom->createDocumentFragment();
      $directoryFragment->appendXML($this->extractDirectoryPageData($directory, $url));
      $directoryNode->appendChild($directoryFragment);
      $directoryNode->setAttribute('class', implode(' ', array_filter(['directory', $hintedDomain ? 'hinted-domain' : null, $hintedUrl ? 'hinted-url' : null])));
      $row->appendChild($directoryNode);

      $httpValue = $httpsValue = sprintf($singleLineInfoFormat, $unsetMessage);
      $httpClass = $httpsClass = '';

      if (!empty($urlData['fatal']))
      {
        $httpValue = $httpsValue = sprintf($multiLineInfoFormat, implode("\n", $urlData['fatal']));
        $httpClass = $httpsClass = $addressesClass = 'fatal';
        $addressesValue = sprintf($multiLineInfoFormat, $unsetMessage);
      }
      else
      {
        if (array_key_exists('http', $urlData))
        {
          $httpValue = $this->getHttpValue($urlData['http']);
          $httpClass = $this->getHttpClass($urlData['http']);
        }
        else
        {
          $httpValue = sprintf($singleLineInfoFormat, $invalidUrlMessage);
          $httpClass = 'fatal';
        }

        if (array_key_exists('https', $urlData))
        {
          $httpsValue = $this->getHttpValue($urlData['https']);
          $httpsClass = $this->getHttpClass($urlData['https']);
        }
        else
        {
          $httpsValue = sprintf($singleLineInfoFormat, $invalidUrlMessage);
          $httpsClass = 'fatal';
        }

        if (array_key_exists('addresses', $urlData) && !empty($urlData['addresses']))
        {
          $addressesValue = sprintf($multiLineInfoFormat, $this->getAddressesValue($urlData['addresses']));
          $addressesClass = $this->getAddressesClass($ourAddresses, $urlData['addresses']);
        }
        else
        {
          $addressesValue = sprintf($multiLineInfoFormat, $unsetMessage);
          $addressesClass = 'fatal';
        }
      }

      $httpNode = $dom->createElement('td');
      $httpFragment = $dom->createDocumentFragment();
      $httpFragment->appendXML($httpValue);
      $httpNode->appendChild($httpFragment);
      $httpNode->setAttribute('class', $httpClass . ' http');
      $row->appendChild($httpNode);

      $httpsNode = $dom->createElement('td');
      $httpsFragment = $dom->createDocumentFragment();
      $httpsFragment->appendXML($httpsValue);
      $httpsNode->appendChild($httpsFragment);
      $httpsNode->setAttribute('class', $httpsClass . ' https');
      $row->appendChild($httpsNode);

      $addressesNode = $dom->createElement('td');
      $addressesFragment = $dom->createDocumentFragment();
      $addressesFragment->appendXML($addressesValue);
      $addressesNode->appendChild($addressesFragment);
      $addressesNode->setAttribute('class', $addressesClass . ' addresses');
      $row->appendChild($addressesNode);
    }
  }

  protected function getHttpValue($data)
  {
    if ($data['errno'])
    {
      return sprintf('<code class="info">[%d] %s</code>', $data['errno'], $data['error']);
    }
    else
    {
      if ($data['initial_url'] === $data['effective_url'] || $data['initial_url'] . '/' === $data['effective_url'])
      {
        return sprintf('<a href="%1$s" target="preview">%1$s</a> <code class="status">%2$d</code>', $data['initial_url'], $data['status']);
      }
      else
      {
        return sprintf('<a href="%1$s" target="preview">%1$s</a> => <a href="%2$s">%2$s</a> <code class="status">%3$d</code>', $data['initial_url'], $data['effective_url'], $data['status']);
      }
    }
  }

  protected function getHttpClass($data)
  {
    if ($data['errno'])
    {
      return 'error';
    }
    else
    {
      if ($data['status'] >= 300)
      {
        return 'error';
      }
      else
      {
        return 'success';
      }
    }
  }

  protected function getAddressesValue($addresses)
  {
    ob_start();

    foreach ($addresses as $address)
    {
      printf("%s\n", $address);
    }

    return ob_get_clean();
  }

  protected function getAddressesClass($ours, $theirs)
  {
    if (empty($theirs))
      return 'fatal';

    if (count($ours) > 0)
      if (count(array_intersect($ours, $theirs)) > 0)
        return 'success';

    return 'error';
  }

  // TODO: Dynamic replacement (letdigsin doesn't apply to all hosts)
  protected function extractDirectoryPageData($directory, $url)
  {
    $result = preg_replace(array(
      '/(?<=\/home\/)(.+?)(?=\/|$)/',
      '/(?<=\/public_html\/)(.+?)(?=\/|$)/',
      '/(?<=\/domains\/)(.+?)(?=\/|$)/',
      '/(?<=letdigsin.com\/)(.+?)(?=\/|$)/',
    ), array(
      '<span class="emphasis home">$1</span>',
      '<span class="emphasis public">$1</span>',
      '<span class="emphasis domain">$1</span>',
      '<span class="emphasis public">$1</span>'
    ), $directory);

    if (array_key_exists('sourcepath', $url['url'])) {
      $result .= ' <samp>=&gt;</samp> ' . $url['url']['sourcepath'];
    }

    return $result;
  }
}
