<?php
/**
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

namespace Colorpack\Plugin\System\ColorpackShield\AdminProtect;

\defined('_JEXEC') || \defined('COLORPACK_SHIELD_TEST') || die;

/**
 * {@see StateStore} on a few small JSON files, one per shard, guarded by flock.
 *
 * Bounds: at most {@see $maxEntries} entries and {@see $maxBytes} bytes per
 * shard (oldest-expiring entries are dropped first; one entry bigger than the
 * whole shard is not kept at all), so an attacker who fills
 * it with random IPs cannot exhaust disk or memory. A corrupt file, or one larger than twice
 * the bound (reads stop there), is treated as empty. Nothing here throws; see {@see StateStore}.
 *
 * The files are written only when a login fails, a lock is set or an alert is
 * claimed — never on an ordinary request. Deleting the folder resets everything
 * safely (locks lift, learning restarts).
 */
final class FileStateStore implements StateStore
{
    /**
     * First line of every shard. The files hold IP addresses and sit under the
     * web root; named ".php" with this line they answer 404 to anybody who asks
     * for them, whatever the web server does with the extension.
     */
    public const HEADER = "<?php http_response_code(404); exit; ?>\n";

    private bool $ok = true;

    public function __construct(
        private readonly string $dir,
        private readonly int $maxEntries = 1000,
        private readonly int $maxBytes = 262144,
        private readonly int $shards = 16
    ) {
    }

    public function get(string $key, int $now): ?array
    {
        $this->ok = true;
        $file     = $this->file($key);

        if (!is_file($file)) {
            return null;
        }

        $fh = @fopen($file, 'rb');

        if ($fh === false) {
            $this->ok = false;

            return null;
        }

        try {
            if (!@flock($fh, LOCK_SH)) {
                $this->ok = false;

                return null;
            }

            $e = $this->decode((string) @stream_get_contents($fh, $this->maxBytes * 2 + \strlen(self::HEADER)))[$key] ?? null;
            @flock($fh, LOCK_UN);

            return \is_array($e) && (int) ($e['exp'] ?? 0) > $now ? $e : null;
        } finally {
            fclose($fh);
        }
    }

    public function mutate(string $key, int $now, callable $fn): ?array
    {
        $this->ok = true;

        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            $this->ok = false;

            return null;
        }

        $file  = $this->file($key);
        $fresh = !is_file($file);
        $fh    = @fopen($file, 'c+b');

        if ($fh === false) {
            $this->ok = false;

            return null;
        }

        try {
            if (!@flock($fh, LOCK_EX)) {
                $this->ok = false;

                return null;
            }

            if ($fresh) {
                @chmod($file, 0600);
            }

            $all = $this->decode((string) @stream_get_contents($fh, $this->maxBytes * 2 + \strlen(self::HEADER)));

            foreach ($all as $k => $e) {
                if (!\is_array($e) || (int) ($e['exp'] ?? 0) <= $now) {
                    unset($all[$k]);
                }
            }

            $new = $fn($all[$key] ?? null);

            if ($new === null) {
                unset($all[$key]);
            } else {
                $new['exp'] = (int) ($new['exp'] ?? $now + 3600);
                $all[$key]  = $new;
            }

            $all  = $this->bound($all);
            $json = (string) json_encode($all, JSON_UNESCAPED_SLASHES);

            if (!@ftruncate($fh, 0) || @fseek($fh, 0) !== 0 || @fwrite($fh, self::HEADER . $json) === false || !@fflush($fh)) {
                $this->ok = false;

                return null;
            }

            @flock($fh, LOCK_UN);

            return $all[$key] ?? null;
        } catch (\Throwable) {
            $this->ok = false;

            return null;
        } finally {
            fclose($fh);
        }
    }

    /**
     * Live entries whose key starts with $prefix (for the unlock tool and the dashboard).
     *
     * @return array<string,array<string,mixed>>
     */
    public function entries(string $prefix, int $now): array
    {
        $this->ok = true;
        $out      = [];

        foreach (glob($this->dir . '/s*.php') ?: [] as $file) {
            $fh = @fopen($file, 'rb');

            if ($fh === false) {
                $this->ok = false;

                continue;
            }

            try {
                if (@flock($fh, LOCK_SH)) {
                    foreach ($this->decode((string) @stream_get_contents($fh, $this->maxBytes * 2 + \strlen(self::HEADER))) as $k => $e) {
                        if (\is_array($e) && str_starts_with((string) $k, $prefix) && (int) ($e['exp'] ?? 0) > $now) {
                            $out[(string) $k] = $e;
                        }
                    }

                    @flock($fh, LOCK_UN);
                } else {
                    $this->ok = false;
                }
            } finally {
                fclose($fh);
            }
        }

        ksort($out);

        return $out;
    }

    public function purge(string $prefix, int $now): int
    {
        $this->ok = true;
        $removed  = 0;

        foreach (glob($this->dir . '/s*.php') ?: [] as $file) {
            $fh = @fopen($file, 'c+b');

            if ($fh === false) {
                $this->ok = false;

                continue;
            }

            try {
                if (!@flock($fh, LOCK_EX)) {
                    $this->ok = false;

                    continue;
                }

                $all = $this->decode((string) @stream_get_contents($fh, $this->maxBytes * 2 + \strlen(self::HEADER)));

                foreach (array_keys($all) as $k) {
                    if (str_starts_with((string) $k, $prefix)) {
                        unset($all[$k]);
                        $removed++;
                    }
                }

                if (!@ftruncate($fh, 0) || @fseek($fh, 0) !== 0 || @fwrite($fh, self::HEADER . (string) json_encode($all, JSON_UNESCAPED_SLASHES)) === false || !@fflush($fh)) {
                    $this->ok = false;
                }

                @flock($fh, LOCK_UN);
            } finally {
                fclose($fh);
            }
        }

        return $removed;
    }

    public function healthy(): bool
    {
        return $this->ok;
    }

    private function file(string $key): string
    {
        $shard = hexdec(substr(hash('sha256', $key), 0, 4)) % max(1, $this->shards);

        return $this->dir . '/s' . $shard . '.php';
    }

    /**
     * @return array<string,array<string,mixed>>
     */
    private function decode(string $raw): array
    {
        if (!str_starts_with($raw, self::HEADER)) {
            return [];
        }

        $d = json_decode(substr($raw, \strlen(self::HEADER)), true);

        return \is_array($d) ? $d : [];
    }

    /**
     * @param  array<string,array<string,mixed>>  $all
     *
     * @return array<string,array<string,mixed>>
     */
    private function bound(array $all): array
    {
        $byExp = static fn (array $a, array $b): int => ((int) ($a['exp'] ?? 0)) <=> ((int) ($b['exp'] ?? 0));

        if (\count($all) > $this->maxEntries) {
            uasort($all, $byExp);
            $all = \array_slice($all, \count($all) - $this->maxEntries, null, true);
        }

        while (\count($all) > 1 && \strlen((string) json_encode($all, JSON_UNESCAPED_SLASHES)) > $this->maxBytes) {
            uasort($all, $byExp);
            array_shift($all);
        }

        // A lone entry larger than the whole shard may not be kept either: it could never be read back.
        if (\strlen((string) json_encode($all, JSON_UNESCAPED_SLASHES)) > $this->maxBytes) {
            return [];
        }

        return $all;
    }
}
