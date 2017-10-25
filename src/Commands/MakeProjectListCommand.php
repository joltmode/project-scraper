<?php

namespace App\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Question\ConfirmationQuestion;
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

  protected $force = false;

  protected $hints = [];
  protected $markedAddresses = [];

  protected $sftp;

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

.hinted {
  background-color: #FFFF99;
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

var.size {
  white-space: nowrap;
  font-style: normal;
  font-family: monospace;
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

      ->addOption('overwrite', null, InputOption::VALUE_NONE, 'Should the output file be overwritten in if exists?')

      ->addOption('force', null, InputOption::VALUE_NONE, 'Ignore caches')

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
    $this->output->writeln(sprintf('<info>Cache directory: %s</info>', $this->cacheBaseDirectory));

    $cacheDuration = $this->input->getOption('cache-ttl');

    if (!is_numeric($cacheDuration)) {
      throw new InvalidArgumentException(sprintf('Cache duration is not a number (%s).', $cacheDuration));
    } else {
      $this->cacheDuration = (float) $cacheDuration;
    }

    $this->force = !empty($this->input->getOption('force'));

    $this->setupHints();
    $this->setupMarks();
  }

  protected function setupHints()
  {
    $hints = $this->input->getOption('hint');

    $formattedHints = [];

    $registerHint = function($type, array $options) use (&$formattedHints) {
      $definition = [
        'type' => $type,
        'options' => $options,
        'results' => []
      ];

      $formattedHints[] = $definition;
    };

    foreach ($hints as $hint) {
      if (starts_with($hint, 'r/')) {
        $registerHint('regex', [
          'pattern' => substr($hint, 1)
        ]);
      } else {
        $parsed = parse_url($hint);

        if ($parsed === false) {
          $this->output->writeln(sprintf('<error>Cannot extract usable hint from (%s). Skipping.</error>', $hint));
          continue;
        }

        if (array_key_exists('scheme', $parsed)) {
          if (!in_array($parsed['scheme'], ['http', 'https'])) {
            $this->output->writeln(sprintf('<error>Cannot hint url with non HTTP scheme (%s; %s). Skipping.', $hint, $parsed['scheme']));
            continue;
          }

          $registerHint('url', [
            // We don't need scheme further on.
            'url' => $parsed['host'] . (array_key_exists('path', $parsed) ? $parsed['path'] : '')
          ]);
        } elseif (array_key_exists('path', $parsed) && count($parsed) === 1) {
          $path = $parsed['path'];

          // Check for domain.
          if (strpos($path, '/') === false && substr_count($path, '.') >= 1) {
            $registerHint('domain', [
              'domain' => $path
            ]);
          } else {
            $registerHint('substring', [
              'needle' => $path
            ]);
          }
        }
      }
    }

    $this->hints = $formattedHints;
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
        continue;
      }
    }

    $this->markedAddresses = $ips;
  }

  protected function execute(InputInterface $input, OutputInterface $output)
  {
    set_time_limit(0);

    $this->globalizeSettings($input, $output);
    $this->connect();

    $roots = $this->resolveRoots();

    $populatedRoots = $this->populateRoots($roots);

    $urls = $this->extractUrls($populatedRoots);

    $results = $this->testUrls($urls);

    $this->generateResultHtml($results);
  }

  protected function connect()
  {
    $key = $this->input->getOption('key');
    $password = $this->input->getOption('password');

    if (!$key && !$password) {
      throw new InvalidArgumentException('You have to specify key or password to connect to the remote.');
    }

    $address = $this->input->getArgument('address');
    $port = intval($this->input->getOption('port'), 10);

    $sftp = new SFTP($address, $port);

    $access = null;

    if ($key) {
      $access = $this->loadKey($key, $password);
    } else {
      $access = $password;
    }

    if (!$sftp->login($username = $this->input->getOption('username'), $access)) {
      throw new RuntimeException(sprintf('Could not connect to remote host (%s:%d) using the given username (%s) and access method (%s).', $address, $port, $username, ($access instanceof RSA) ? 'key:' . realpath($key) : 'password'));
    }

    $this->address = $address;

    $destination = implode(':', [$address, $port]);
    $this->output->writeln(sprintf('<info>Connected to %s</info>', $destination));

    $this->sftp = $sftp;
  }

  protected function resolveRoots() {
    $roots = [];

    $this->output->writeln('Resolving roots...');

    foreach ($this->input->getArgument('root') as $root) {
      $folder = $root;
      $baseUrl = null;

      if (count($parts = explode(':', $root)) === 2) {
        $folder = $parts[0];
        $baseUrl = $parts[1];
      }

      if ($folder[0] !== '/') {
        $this->output->writeln(sprintf('<error>Folder (%s) specified with a relative path instead of absolute. Skipping.</error>', $folder));
        continue;
      }

      // Resolve realpath and exclude if not found.
      if (!($realpath = $this->sftp->realpath($folder))) {
        $this->output->writeln(sprintf('<error>The folder (%s) could not be found on the remote server. Skipping.</error>', $folder));
        continue;
      }

      $this->output->writeln(sprintf('Resolved %s to %s.', $root, $realpath));

      $roots[] = [
        'realpath' => $realpath,
        'baseUrl' => $baseUrl
      ];
    }

    $this->output->writeln('Roots resolved.');

    return $roots;
  }

  protected function populateRoots(array $roots) {
    $populatedRoots = [];

    $this->output->writeln('Populating roots...');

    // Go through all of the provided roots and resolve folders.
    foreach ($roots as $root) {
      $entries = $this->sftp->rawlist($folder = $root['realpath']);

      if (!is_array($entries)) {
        $this->output->writeln(sprintf('<error>No entries could be found under (%s), maybe inexistant root? Skipping.</error>', $folder));
        continue;
      }

      $this->output->writeln(sprintf('Found %d entries under %s, filtering...', count($entries), $folder));

      foreach ($entries as $entry) {
        $filename = $entry['filename'];

        // Ignore dot paths and files.
        if ($filename === '.' || $filename === '..' || $entry['type'] === 1) {
          continue;
        }

        // Construct a relative path and resolve to realpath.
        $path = $this->sftp->realpath($folder . '/' . $filename);

        $resolveLink = function ($path, &$hops = null) use (&$resolveLink) {
          $link = $this->sftp->readlink($path);

          // If absolute path gets resolved, it's already resolved.
          if ($link[0] === '/') {
            $linkPath = $link;
          // Relative path. We match it against the dirname of base path.
          // Also resolve.
          } else {
            $dirname = dirname($path);
            $linkPath = $this->sftp->realpath($dirname . '/' . $link);
          }

          // Link resolved, lstat it, in case it's another link.
          $stat = $this->sftp->lstat($linkPath);

          // On first request, initialize hops.
          if (is_null($hops)) {
            $hops = [];
          }

          array_push($hops, ['realpath' => $linkPath, 'stat' => $stat]);

          // Still a link? Recurse.
          if ($stat['type'] === 3) {
            $resolveLink($linkPath, $hops);
          }

          return $hops;
        };

        $normalizedEntry = ['realpath' => $path, 'stat' => $entry, 'root' => false];
        $duPath = $path;
        $link = $entry['type'] === 3;

        if ($entry['type'] === 3) {
          $hops = $resolveLink($path);
          $lastHop = $hops[count($hops) - 1];

          // We have resolved to a file, not interested.
          if ($lastHop['stat']['type'] === 1) {
            continue;
          }

          $normalizedEntry['hops'] = $hops;
          $normalizedEntry['real'] = $lastHop;
          $duPath = $normalizedEntry['real']['realpath'];

          $this->output->writeln(sprintf('Resolved %s as a shortcut to %s.', $path, $duPath));
        }

        $size = $this->getCachedResult($this->cacheBaseDirectory . '/' . str_slug('s-' . $this->address . '_' . $duPath), function () use ($path) {
          return $this->getRemoteSize($this->sftp, $path);
        });

        $link ? ($normalizedEntry['real']['size'] = $size) : ($normalizedEntry['size'] = $size);

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
          $this->output->writeln(sprintf('%s is a root itself. Skipping.', $path));
          continue;
        }

        if (!array_key_exists('entries', $root)) {
          $root['entries'] = [];
        }

        $root['entries'][] = $normalizedEntry;
      }

      $this->output->writeln(sprintf('%d%% (%d/%d; -%d) usable in %s.', round(($usableEntries = count($root['entries'])) / ($totalEntries = count($entries)) * 100, 2), $usableEntries, $totalEntries, $totalEntries - $usableEntries, $folder));

      usort($root['entries'], function ($a, $b) {
        return strcmp($a['realpath'], $b['realpath']);
      });

      $populatedRoots[] = $root;
    }

    return $populatedRoots;
  }

  protected function extractUrls(array $populatedRoots)
  {
    $urls = [];

    foreach ($populatedRoots as $root) {
      $baseUrl = $root['baseUrl'];

      foreach ($root['entries'] as $entry) {
        $origin = basename($entry['realpath']);

        $result = [
          'path' => $entry['realpath'],
          'origin' => $origin,
          'baseUrl' => $baseUrl,
          'url' => $this->combineUrl($origin, $baseUrl),
          'entry' => $entry
        ];

        if (array_key_exists('real', $entry) && $entry['real']['realpath'] !== $entry['realpath']) {
          $result['sourcepath'] = $entry['real']['realpath'];
        }

        $urls[] = $result;
      }
    }

    return $urls;
  }

  protected function testUrls(array $urls)
  {
    $results = [];

    $total = count($urls);

    foreach ($urls as $index => $url) {
      $directory = array_key_exists('directory', $url) ? $url['directory'] : $url['url'];

      $this->output->writeln(sprintf('Testing URL (%d/%d): %s', $index + 1, $total, $url['url']));

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

    return $results;
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

    if (!$this->force && file_exists($store) && $this->cacheDuration > 0 && time() - filemtime($store) < $this->cacheDuration)
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
    return $this->getCachedResult($this->cacheBaseDirectory . '/' . str_slug('u-' . $this->address . '_' .$url), function () use ($url) {
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
    return $this->getCachedResult($this->cacheBaseDirectory . '/' . str_slug('h-' . $this->address . '_' . $host), function () use ($host) {
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

  protected function getHumanHintType($type)
  {
    switch ($type) {
      case 'substring':
        return 'virkne';
        break;

      case 'regex':
        return 'datorizteiksme';
        break;

      case 'domain':
        return 'domēns';
        break;

      case 'url':
        return 'saite';
    }
  }

  protected function generateHintDefinitionDisplay($definition)
  {
    $type = $definition['type'];
    $humanType = ucfirst($this->getHumanHintType($type));

    switch ($type) {
      case 'substring':
        return $humanType . ': <var class="hint substring">' . $definition['options']['needle'] . '</var>';
        break;

      case 'regex':
        return $humanType . ': <var class="hint regex">'. $definition['options']['pattern'] .'</var>';
        break;

      case 'domain':
        return $humanType . ': <var class="hint domain">'. $definition['options']['domain'] .'</var>';
        break;

      case 'url':
        return $humanType . ': <var class="hint url">'. $definition['options']['url'] .'</var>';
    }
  }

  protected function generateResultHtml($urls)
  {
    $totalUrls = count($urls);
    $currentUrl = 1;

    $dom = new DOMDocument;
    $dom->preserveWhiteSpace = true;
    $dom->formatOutput = true;

    $dom->loadHTML('<body></body>');

    $body = $dom->getElementsByTagName('body')->item(0);

    $head = $dom->createElement('head');
    $dom->documentElement->insertBefore($head, $body);

    // Title.
    $title = $dom->createElement('title');
    $title->nodeValue = sprintf('Servera %s projektu izraksts @ %s', $this->address, date('H:i:s Y.m.d.'));
    $head->appendChild($title);

    // Embed.
    $stylesheet = $dom->createElement('style');
    $stylesheet->setAttribute('type', 'text/css');
    $stylesheet->nodeValue = static::HTML_TABLE_STYLE;
    $head->appendChild($stylesheet);

    $siteTable = $this->generateTableHeaders('Servera Mape', $dom);
    $body->appendChild($siteTable);
    $this->generateResultRows($urls, $currentUrl, $totalUrls, $dom, $siteTable);

    $siteTable->appendChild($this->generateSizeRow($urls, 'Kopā:', $dom));

    $hintedUrls = array_flatten(array_filter(array_map(function ($hintDefinition) {
      return $hintDefinition['results'];
    }, $this->hints)), 1);

    if (count($hintedUrls) > 0) {
      $siteTable->appendChild($this->generateSizeRow($hintedUrls, 'Atzīmētās:', $dom));
    }

    if (count($this->hints) > 0) {
      $requestedHintHeader = $dom->createElement('h2');
      $requestedHintHeader->nodeValue = 'Kopā tika pieprasīta saikne ar šādiem nosacījumiem:';
      $body->appendChild($requestedHintHeader);

      $requestedList = $dom->createElement('ul');
      $body->appendChild($requestedList);

      foreach ($this->hints as $hintDefinition)
      {
        $listItem = $dom->createElement('li');
        $hintFragment = $dom->createDocumentFragment();
        $hintFragment->appendXML($this->generateHintDefinitionDisplay($hintDefinition));
        $listItem->appendChild($hintFragment);
        $requestedList->appendChild($listItem);
      }
    }

    /*
    foreach (['url', 'domain', 'substring', 'regex'] as $hintType) {
      $hintsOfType = array_filter($this->hints, function ($hintDefinition) use ($hintType) {
        return $value['type'] === $hintType;
      });

      $resolvedOfType = array_filter($hintsOfType, function ($hintDefinition) {
        return count($hintDefinition['results']) > 0;
      });

      $unresolvedOfType = array_diff_key($hintsOfType, $resolvedOfType);

      $resolvedHintHeader = $dom->createElement('h2');
      $resolvedHintHeader->nodeValue = '('. ucfirst($hintType) .') Atrasta saikne šiem nosacījumiem:';
      $body->appendChild($resolvedHintHeader);

      $totalDomainHints = count($hintedDomains);
      $currentDomainHint = 1;

      $leftOverHintedDomainTable = $this->generateTableHeaders('Domēns', $dom);
      $body->appendChild($leftOverHintedDomainTable);
      $hintedDomainUrls = array_map(array($this, 'generateUrlDataFromDomain'), array_keys($hintedDomains));
      $this->generateResultRows($hintedDomainUrls, $currentDomainHint, $totalDomainHints, $dom, $leftOverHintedDomainTable);
    }

    if (count($resolvedHints) > 0) {
      $resolvedHintHeader = $dom->createElement('h2');
      $resolvedHintHeader->nodeValue = 'Atrasta saikne šiem nosacījumiem:';
      $body->appendChild($resolvedHintHeader);

      $totalDomainHints = count($hintedDomains);
      $currentDomainHint = 1;

      $leftOverHintedDomainTable = $this->generateTableHeaders('Domēns', $dom);
      $body->appendChild($leftOverHintedDomainTable);
      $hintedDomainUrls = array_map(array($this, 'generateUrlDataFromDomain'), array_keys($hintedDomains));
      $this->generateResultRows($hintedDomainUrls, $currentDomainHint, $totalDomainHints, $dom, $leftOverHintedDomainTable);
    }

    $unresolvedHints = array_diff_key($this->hints, $resolvedHints);

    if (count($unresolvedHints) > 0) {

    }
    */

    /*
    $hintedDomains = array_filter($this->domainHints, function ($resolvedProjects) {
      return count($domain) > 0;
    });

    if (count($hintedDomains))
    {
      $remainderDomainHeader = $dom->createElement('h2');
      $remainderDomainHeader->nodeValue = 'Neatrasta domēnu saikne ar servera mapēm:';
      $body->appendChild($remainderDomainHeader);

      $totalDomainHints = count($hintedDomains);
      $currentDomainHint = 1;

      $leftOverHintedDomainTable = $this->generateTableHeaders('Domēns', $dom);
      $body->appendChild($leftOverHintedDomainTable);
      $hintedDomainUrls = array_map(array($this, 'generateUrlDataFromDomain'), array_keys($hintedDomains));
      $this->generateResultRows($hintedDomainUrls, $currentDomainHint, $totalDomainHints, $dom, $leftOverHintedDomainTable);
    }

    if (count($this->domainHints))
    {
      $requestedDomainHeader = $dom->createElement('h2');
      $requestedDomainHeader->nodeValue = 'Kopā tika pieprasīta domēnu saikne šādiem domēniem:';
      $body->appendChild($requestedDomainHeader);

      $requestedList = $dom->createElement('ul');
      $body->appendChild($requestedList);

      foreach ($originalDomainHints as $originalHint => $resolvedHints)
      {
        $listItem = $dom->createElement('li');
        $listItem->nodeValue = $originalHint;
        $requestedList->appendChild($listItem);
      }
    }

    $hintedUrls = array_filter($this->urlHints, function ($resolvedProjects) {
      return count($resolvedProjects) > 0;
    });

    if (count($hintedUrls))
    {
      $remainderUrlHeader = $dom->createElement('h2');
      $remainderUrlHeader->nodeValue = 'Neatrasta ceļu saikne ar servera mapēm:';
      $body->appendChild($remainderUrlHeader);

      $totalUrlHints = count($hintedUrls);
      $currentUrlHint = 1;

      $leftOverHintedUrlTable = $this->generateTableHeaders('Mape', $dom);
      $body->appendChild($leftOverHintedUrlTable);
      $hintedUrlUrls = array_map(array($this, 'generateUrlDataFromUrl'), array_keys($hintedUrls));
      $this->generateResultRows($hintedUrlUrls, $currentUrlHint, $totalUrlHints, $dom, $leftOverHintedUrlTable);
    }

    if (count($this->urlHints))
    {
      $requestedUrlHeader = $dom->createElement('h2');
      $requestedUrlHeader->nodeValue = 'Kopā tika pieprasīta ceļu saikne šādiem ceļiem:';
      $body->appendChild($requestedUrlHeader);

      $requestedList = $dom->createElement('ul');
      $body->appendChild($requestedList);

      foreach ($originalUrlHints as $originalHint => $resolvedHints)
      {
        $listItem = $dom->createElement('li');
        $listItem->nodeValue = $originalHint;
        $requestedList->appendChild($listItem);
      }
    }
    */

    $file = $this->address . '.html';
    $save = true;

    if (file_exists($file) && empty($this->input->getOption('overwrite'))) {
      $questionHelper = $this->getHelper('question');

      $question = new ConfirmationQuestion('File already exists, overwrite? ', true);

      if (!$questionHelper->ask($this->input, $this->output, $question)) {
        $save = false;
      }
    }

    if ($save) {
      $dom->saveHTMLFile($this->address . '.html');
    }
  }

  protected function generateSizeRow($urls, $firstColumn, $dom)
  {
    $totalsRow = $dom->createElement('tr');
    $totalsDirectoryNode = $dom->createElement('td');
    $totalsDirectoryNode->nodeValue = $firstColumn;
    $totalsRow->appendChild($totalsDirectoryNode);

    $totalSizeNode = $dom->createElement('td');
    $totalSize = array_reduce($urls, function ($accumulated, $currentUrl) {
      $urlSize = (
        isset($currentUrl['url']['entry']['real']) ?
        $currentUrl['url']['entry']['real']['size'] :
        $currentUrl['url']['entry']['size']
      )['size'];

      return $accumulated + $urlSize;
    }, 0);

    $totalSizeFragment = $dom->createDocumentFragment();
    $totalSizeFragment->appendXML('<var class="size">'. $this->formatBytes($totalSize) .'</var>');
    $totalSizeNode->appendChild($totalSizeFragment);
    $totalSizeNode->setAttribute('class', 'size');
    $totalsRow->appendChild($totalSizeNode);

    $fillerNode = $dom->createElement('td');
    $fillerNode->setAttribute('colspan', 3);
    $totalsRow->appendChild($fillerNode);

    return $totalsRow;
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
    $headerRow->appendChild($directoryHeading);

    // Size header.
    $sizeHeading = $dom->createElement('th');
    $sizeHeading->nodeValue = 'Izmērs';
    $sizeHeading->setAttribute('class', 'size');
    $headerRow->appendChild($sizeHeading);

    // HTTP header.
    $httpHeader = $dom->createElement('th');
    $httpHeader->nodeValue = 'HTTP';
    $httpHeader->setAttribute('class', 'http');
    $headerRow->appendChild($httpHeader);

    // HTTPS header.
    $httpsHeader = $dom->createElement('th');
    $httpsHeader->nodeValue = 'HTTPS';
    $httpsHeader->setAttribute('class', 'https');
    $headerRow->appendChild($httpsHeader);

    // Addresses header.
    $addressesHeader = $dom->createElement('th');
    $addressesHeader->nodeValue = 'Adreses';
    $addressesHeader->setAttribute('class', 'addresses');
    $headerRow->appendChild($addressesHeader);

    return $table;
  }

  protected function generateResultRows($urls, &$current, $total, $dom, $table)
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
      $external = array_key_exists('external', $url) ? $url['external'] : false;

      $current++;

      $directoryNode = $dom->createElement('td');
      $directoryFragment = $dom->createDocumentFragment();
      $directoryFragment->appendXML($this->extractDirectoryPageData($directory, $url));
      $directoryNode->appendChild($directoryFragment);

      $directoryClasses = ['directory'];
      $this->appendHintClasses($directoryClasses, $this->checkHints($url));

      $directoryNode->setAttribute('class', implode(' ', $directoryClasses));
      $row->appendChild($directoryNode);

      $sizeNode = $dom->createElement('td');
      $sizeData = $external ? ['size' => null] : (
        isset($url['url']['entry']['real']) ?
        $url['url']['entry']['real']['size'] :
        $url['url']['entry']['size']
      );
      $sizeFragment = $dom->createDocumentFragment();
      $sizeFragment->appendXML('<var class="size">'. $this->formatBytes($sizeData['size']) .'</var>');
      $sizeNode->appendChild($sizeFragment);
      $sizeNode->setAttribute('class', 'size');
      if (array_key_exists('error', $sizeData)) {
        $sizeNode->setAttribute('title', $sizeData['error']);
      }
      $row->appendChild($sizeNode);

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
          $addressesClass = $this->getAddressesClass($this->markedAddresses, $urlData['addresses']);
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

  protected function checkHints($url)
  {
    $data = $url['data'];

    $hints = [];

    // No hints if error.
    if (!empty($data['fatal'])) {
      return $hints;
    }

    $urlStructure = parse_url('http://' . $data['url']);

    foreach ($this->hints as $hintIndex => $hintDefinition) {
      $found = false;

      switch ($type = $hintDefinition['type']) {
        case 'substring':
          $found = str_contains($data['url'], $hintDefinition['options']['needle']);
          break;

        case 'regex':
          $found = preg_match($hintDefinition['options']['pattern'], $data['url']);
          break;

        case 'domain':
          $found = $urlStructure['host'] === $hintDefinition['options']['domain'];
          break;

        case 'url':
          $found = starts_with($data['url'], $hintDefinition['options']['url']);
          break;
      }

      if ($found) {
        $hints[] = $hintDefinition;
        $this->hints[$hintIndex]['results'][] = $url;
      }
    }

    return $hints;
  }

  protected function appendHintClasses(&$classList, $hints)
  {
    if (count($hints) > 0) {
      array_push($classList, 'hinted');

      foreach ($hints as $hintDefinition) {
        array_push($classList, 'hinted-' . $hintDefinition['type']);
      }
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

    $external = array_key_exists('external', $url) ? $url['external'] : false;

    if (!$external) {
      $directoryPath = array_key_exists('sourcepath', $url['url']) ? $url['url']['sourcepath'] : $url['url']['path'];
      $result = '<span title="Uz servera: '. $directoryPath .'">'. $result .'</span>';
    }

    return $result;
  }

  protected function formatBytes($bytes, $precision = 2, $si = false)
  {
    if (is_null($bytes)) {
      return htmlspecialchars('<NULL>');
    }

    $groupSize = $si ? 1000 : 1024;
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];

    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log($groupSize));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow($groupSize, $pow);

    return round($bytes, $precision) . ' ' . $units[$pow];
  }

  protected function getRemoteSize(SFTP $sftp, $path)
  {
    $sftp->enableQuietMode();

    $stdout = $sftp->exec('du -sb ' . $path);

    $exit = $sftp->getExitStatus();

    if ($exit) {
      $error = $sftp->getStdError();
      $sftp->disableQuietMode();

      $this->output->writeln(sprintf('Failed to resolved remote size for %s.', $path));

      return ['size' => 0, 'error' => $error];
    }

    $sftp->disableQuietMode();

    $parts = preg_split('/\s+?/', $stdout);
    $size = intval($parts[0], 10);

    $this->output->writeln(sprintf('Resolved remote size: %s takes up %s.', $path, $this->formatBytes($size)));

    return ['size' => $size];
  }

  protected function generateUrlDataFromDomain($domain)
  {
    $normalizedUrl = $this->combineUrl($domain);

    return [
      'url' => [
        'origin' => $domain,
        'baseUrl' => '',
        'url' => $normalizedUrl
      ],
      'data' => $this->testUrlsData($normalizedUrl),
      'directory' => $normalizedUrl,
      'external' => true
    ];
  }

  protected function generateUrlDataFromUrl($url)
  {
    $parsed = parse_url($url);

    $normalizedUrl = $this->combineUrl($parsed['path'], $parsed['host']);

    return [
      'url' => [
        'origin' => $parsed['path'],
        'baseUrl' => $parsed['host'],
        'url' => $normalizedUrl
      ],
      'data' => $this->testUrlsData($normalizedUrl),
      'directory' => $normalizedUrl,
      'external' => true
    ];
  }
}
