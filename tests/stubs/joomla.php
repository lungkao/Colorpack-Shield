<?php
/**
 * Minimal stand-ins for the few Joomla classes the system plugin touches, so
 * the plugin's guard flow can be exercised without a Joomla install. These
 * model only what the plugin calls; they prove OUR logic, not Joomla's.
 *
 * @package     Colorpack Shield
 * @copyright   Copyright (C) 2026 COLORPACK CREATION CO., LTD. All rights reserved.
 * @license     GNU General Public License version 3 or later
 */

namespace Joomla\Registry {
    class Registry
    {
        private array $data;

        public function __construct($data = [])
        {
            if (\is_string($data)) {
                $data = json_decode($data, true) ?: [];
            }

            $this->data = (array) $data;
        }

        public function get(string $key, $default = null)
        {
            return \array_key_exists($key, $this->data) ? $this->data[$key] : $default;
        }

        public function set(string $key, $value): void
        {
            $this->data[$key] = $value;
        }

        public function toString(): string
        {
            return json_encode($this->data);
        }

        public function toArray(): array
        {
            return $this->data;
        }
    }
}

namespace Joomla\Event {
    interface SubscriberInterface
    {
        public static function getSubscribedEvents(): array;
    }

    class Event
    {
        public function __construct(public string $name = '', private array $args = [])
        {
        }

        public function getArgument($name, $default = null)
        {
            return $this->args[$name] ?? $default;
        }
    }
}

namespace Joomla\CMS\Plugin {
    abstract class CMSPlugin
    {
        public $params;

        protected $autoloadLanguage = false;

        private $app = null;

        public function __construct(&$subject, $config = [])
        {
            $this->params = new \Joomla\Registry\Registry($config['params'] ?? []);
        }

        public function setApplication($app): void
        {
            $this->app = $app;
        }

        public function getApplication()
        {
            return $this->app;
        }
    }
}

namespace Joomla\CMS\Language {
    class Text
    {
        public static function _(string $key): string
        {
            return $key;
        }

        public static function sprintf(string $key, ...$args): string
        {
            return $key . ' ' . implode(' ', $args);
        }
    }
}

namespace Joomla\CMS\Log {
    class Log
    {
        public const ALL     = 30719;
        public const WARNING = 16;

        /** @var string[] */
        public static array $messages = [];

        public static function addLogger(array $options, int $level = self::ALL, array $categories = []): void
        {
        }

        public static function add(string $message, int $level = self::WARNING, string $category = ''): void
        {
            self::$messages[] = $message;
        }
    }
}


namespace Joomla\CMS {
    class Factory
    {
        /** @var object|null Set by tests: records mails. */
        public static $mailer = null;

        public static function getContainer()
        {
            return new class () {
                public function get(string $id)
                {
                    return new class () {
                        public function createMailer()
                        {
                            return \Joomla\CMS\Factory::$mailer;
                        }
                    };
                }
            };
        }
    }
}

namespace Joomla\CMS\Mail {
    interface MailerFactoryInterface
    {
    }
}

namespace Colorpack\Tests {
    /** Thrown by the fake app's close(): the request was ended by the plugin. */
    class RequestEnded extends \RuntimeException
    {
    }

    class FakeInput
    {
        public function __construct(private array $data = [])
        {
        }

        public function getCmd(string $key, string $default = ''): string
        {
            return (string) ($this->data[$key] ?? $default);
        }
    }

    class FakeApp
    {
        /** @var array<string,string> */
        public array $headers = [];

        /** @var array<int,array{0:string,1:string}> */
        public array $messages = [];

        public function __construct(private string $client = "site", public array $config = [])
        {
        }

        public function isClient(string $name): bool
        {
            return $name === $this->client;
        }

        public function getInput(): FakeInput
        {
            return new FakeInput($this->config['input'] ?? []);
        }

        public function setHeader(string $name, string $value, bool $replace = false): void
        {
            $this->headers[$name] = $value;
        }

        public function sendHeaders(): void
        {
        }

        public function enqueueMessage(string $msg, string $type = 'message'): void
        {
            $this->messages[] = [$msg, $type];
        }
        public function get(string $key, $default = null)
        {
            return $this->config[$key] ?? $default;
        }


        public function getIdentity()
        {
            return $this->config['identity'] ?? null;
        }

        /** @var array<int,array{0:string,1:int}> */
        public array $redirects = [];

        public function redirect(string $url, int $code = 303): void
        {
            $this->redirects[] = [$url, $code];

            throw new RequestEnded();
        }

        public function isSSLConnection(): bool
        {
            return (bool) ($this->config['ssl'] ?? false);
        }

        public function isMultiFactorAuthenticationPage(bool $onlyCaptive = false): bool
        {
            return ($this->config['input']['option'] ?? '') === 'com_users' && in_array($this->config['input']['view'] ?? '', ['captive', 'methods'], true);
        }

        public function close(): void
        {
            throw new RequestEnded();
        }
    }

    class FakeMailer
    {
        /** @var array<int,array{to:string,subject:string,body:string}> */
        public array $sent = [];

        private string $to = '';
        private string $subject = '';
        private string $body = '';

        public function addRecipient(string $to): void
        {
            $this->to = $to;
        }

        public function setSubject(string $s): void
        {
            $this->subject = $s;
        }

        public function setBody(string $b): void
        {
            $this->body = $b;
        }

        public function Send(): bool
        {
            $this->sent[] = ['to' => $this->to, 'subject' => $this->subject, 'body' => $this->body];

            return true;
        }
    }
}
