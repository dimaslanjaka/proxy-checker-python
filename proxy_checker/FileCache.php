<?php

declare(strict_types=1);

namespace ProxyChecker;

/**
 * Simple file-based cache helper with expiration.
 */
class FileCache
{
  /**
   * Path to the cache file.
   *
   * @var string
   */
  private $filePath;

  public function __construct(string $filePath)
  {
    $this->filePath = $filePath;
  }

  /**
   * Write a value to the cache with expiration (seconds).
   *
   * @param mixed $value
   * @param int $expiresIn Seconds until expiration
   *
   * @throws \RuntimeException on write/encode failures
   */
  public function writeCache($value, int $expiresIn): void {
    $dir = dirname($this->filePath);
    if (!is_dir($dir)) {
      if (!mkdir($dir, 0777, true) && !is_dir($dir)) {
        throw new \RuntimeException('Unable to create cache directory: ' . $dir);
      }
    }

    $cacheData = [
      'value'      => $value,
      'timestamp'  => microtime(true),
      'expires_in' => $expiresIn,
    ];

    $json = json_encode($cacheData, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
      throw new \RuntimeException('Failed to encode cache data to JSON: ' . json_last_error_msg());
    }

    $fp = fopen($this->filePath, 'c');
    if ($fp === false) {
      throw new \RuntimeException('Unable to open cache file for writing: ' . $this->filePath);
    }

    try {
      if (!flock($fp, LOCK_EX)) {
        throw new \RuntimeException('Unable to obtain exclusive lock for cache file.');
      }

      ftruncate($fp, 0);
      rewind($fp);
      fwrite($fp, $json);
      fflush($fp);
      flock($fp, LOCK_UN);
    } finally {
      fclose($fp);
    }
  }

  /**
   * Read cached value if not expired, otherwise return null.
   *
   * @return mixed|null
   */
  public function readCache() {
    if (!file_exists($this->filePath) || !is_readable($this->filePath)) {
      return null;
    }

    $fp = fopen($this->filePath, 'r');
    if ($fp === false) {
      return null;
    }

    try {
      if (!flock($fp, LOCK_SH)) {
        return null;
      }

      $contents = stream_get_contents($fp);
      flock($fp, LOCK_UN);
    } finally {
      fclose($fp);
    }

    if ($contents === false || $contents === '') {
      return null;
    }

    $data = json_decode($contents, true);
    if (!is_array($data) || !isset($data['timestamp'], $data['expires_in'], $data['value'])) {
      return null;
    }

    $current = microtime(true);
    if (($current - (float) $data['timestamp']) > (int) $data['expires_in']) {
      return null;
    }

    return $data['value'];
  }
}
