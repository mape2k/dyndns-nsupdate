<?php

namespace DynDNS;

class DynDNS
{
    // configuration
    private $config;

    // hostname, ip
    private $hostname;
    private $zone;
    private $ip;
    private $ipVersion;

    /**
     * Constructor
     *
     * Run DynDNS server part instantly
     */
    public function __construct(array $config)
    {
        $this->config = $config;

        // Get parameters
        if ($this->checkParameters() === false) {
            return null;
        }

        // Force HTTP Basic Auth and stop on failure
        if ($this->forceHttpBasicAuth() === false) {
            http_response_code(401);
            echo 'badauth';
            return null;
        }

        // Check if update is needed
        if ($this->checkEntryNeedsUpdate() === false) {
            // IP address not changed
            http_response_code(200);
            echo 'nochg '.$this->ip;
            return;
        };

        $this->updateNameserver();
    }

    /**
     * Force HTTP Basic Authentication without htaccess file
     * and authenticate user
     *
     * @return boolean User authentified
     */
    private function forceHttpBasicAuth()
    {
        if (!isset($_SERVER['PHP_AUTH_USER'])
            || !isset($_SERVER['PHP_AUTH_PW'])
            || $_SERVER['PHP_AUTH_USER'] === ''
            || $_SERVER['PHP_AUTH_PW'] === '') {
            header('WWW-Authenticate: Basic realm="DynDNS"');
            return false;
        }

        // Search user in record list and use entry for config
        if (is_array($this->config['user'])) {
            if (isset($this->config['user'][$this->hostname])) {
                $this->config['user'] = $this->config['user'][$this->hostname];
            } else {
                // No entry found for hostname
                   return false;
            }
        }

        // Try to authenticate user
        $userConfiguration = explode(' ', $this->config['user']);
        if (count($userConfiguration) === 2) {
            $passwordHash = $userConfiguration[1];
        } else {
            return false;
        }

        return password_verify($_SERVER['PHP_AUTH_PW'], $passwordHash);
    }

    /**
     * Check GET parameters
     *
     * @return boolean Determine parameters successfull
     */
    private function checkParameters()
    {
        // Check hostname parameter
        if (isset($_GET['hostname'])) {
            $this->hostname = $_GET['hostname'];
        } else {
            http_response_code(400);
            echo "nohost";
            return false;
        }

        // Get zone from hostname (after first dot)
        $this->zone = substr($this->hostname, strcspn($this->hostname, '.') + 1);

        // Get IP Address
        $this->ip = $_SERVER['REMOTE_ADDR'];
        if (isset($_GET['myip'])
            && filter_var($_GET['myip'], FILTER_VALIDATE_IP)) {
            $this->ip = $_GET['myip'];
        }

        // Get IP Address Version
        if (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4 address detected, A record required
            $this->ipVersion = 4;
        } elseif (filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 address detected, AAAA record required
            $this->ipVersion = 6;
        } else {
            // No valid ip address
            http_response_code(500);
            echo '911 No valid ip address';
            return false;
        }
    }

    /**
     * Return nameserver for zone
     *
     * @param string $zone Zone name
     * @return string Nameserver ip address
     */
    private function getNameserver($zone)
    {
        if (isset($this->config['nameserver'])) {
            if (!is_array($this->config['nameserver'])) {
                return $this->config['nameserver'];
            } else {
                return (isset($this->config['nameserver'][$zone])) ? $this->config['nameserver'][$zone] : '127.0.0.1';
            }
        } else {
            return '127.0.0.1';
        }
    }

    /**
     * Return tsig informations for zone
     *
     * @param string $zone Zone name
     * @return array|null TSIG information or null if TSIG is not available
     */
    private function getTsig($zone)
    {
        // Set default values
        $result = ['algorithm' => 'hmac-sha512', 'key_name' => 'dyndns'];

        // Try to determine TSIG key, return null if not found
        if (!isset($this->config['tsig'])) {
            // TSIG not configured and unavailable
            return null;
        } else {
            if (!is_array($this->config['tsig'])) {
                // Single TSIG key for any zone
                $result['key'] = $this->config['tsig'];
            } else {
                // Zone based TSIG keys configured
                if (isset($this->config['tsig'][$zone])) {
                    $result['key'] = $this->config['tsig'][$zone];
                } else {
                    return null;
                }
            }
        }

        // Try to determine TSIG alorithm
        if (isset($this->config['tsig_algorithm'])) {
            if (!is_array($this->config['tsig_algorithm'])) {
                $result['algorithm'] = $this->config['tsig_algorithm'];
            } elseif (isset($this->config['tsig_algorithm'][$zone])) {
                $result['algorithm'] = $this->config['tsig_algorithm'][$zone];
            }
        }

        // Check TSIG algorithm, return null if invalid
        if (preg_match('/hmac-(md5|sha(1|224|256|384|512))/', $result['algorithm']) !== 1) {
            return null;
        }

        // Try to determine TSIG key name
        if (isset($this->config['tsig_key_name'])) {
            if (!is_array($this->config['tsig_key_name'])) {
                $result['key_name'] = $this->config['tsig_key_name'];
            } elseif (isset($this->config['tsig_key_name'][$zone])) {
                $result['key_name'] = $this->config['tsig_key_name'][$zone];
            }
        }

        return $result;
    }

    /**
     * Check if current entry on nameserver needs update
     *
     * @return boolean Update required
     */
    private function checkEntryNeedsUpdate()
    {
        // Resolve record to check for update
        $resolver = new \Net_DNS2_Resolver(array('nameservers' => array($this->getNameserver($this->zone))));
        try {
            $resolverResult = $resolver->query($this->hostname, ($this->ipVersion === 4) ? 'A' : 'AAAA');
        } catch (\Net_DNS2_Exception $e) {
            // Record not found, but nameserver is authorative
            if (isset($e->getResponse()->authority[0])
                && $e->getResponse()->authority[0] instanceof \Net_DNS2_RR_SOA) {
                return true;
            }

            // Resolving failed and nameserver not authorative, fatal error
            http_response_code(500);
            echo 'dnserr'."\n";
            if ($e->getResponse() === null) {
                echo 'Nameserver did not response.';
            } else {
                echo $e->getMessage();
            }
            exit;
        }

        // Loop through all entries, return false if found
        foreach ($resolverResult->answer as $rr) {
            // Use inet_pton, because \Net_DNS2_Resolver returns uncompressed IPv6 addresses
            if (inet_pton($rr->address) === inet_pton($this->ip)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Update nameserver via RFC2136 mechanism
     *
     * @return boolean Update successfull
     */
    private function updateNameserver()
    {
        // Update needed
        $nsupdate = new \Net_DNS2_Updater(
            $this->zone,
            array('nameservers' => array($this->getNameserver($this->zone)))
        );

        try {
            // Create resource record
            $_record = ($this->ipVersion === 4) ? new \Net_DNS2_RR_A() : new \Net_DNS2_RR_AAAA();

            // Add record information
            $_record->name = $this->hostname;
            $_record->ttl = 60;
            $_record->address = $this->ip;

            // Remove old entries and add new one
            $nsupdate->deleteAny($this->hostname, $_record->type);
            $nsupdate->add($_record);

            // Add TSIG if available
            $tsig = $this->getTsig($this->zone);
            if (is_array($tsig)) {
                $nsupdate->signTSIG($tsig['key_name'], $tsig['key'], $tsig['algorithm']);
            }

            // Send update
            $nsupdate->update();
        } catch (\Net_DNS2_Exception $e) {
            // Output dns error
            http_response_code(500);
            echo 'dnserr'."\n";
            echo $e->getMessage();
            return false;
        }

        http_response_code(200);
        echo 'noch '.$this->ip;

        return true;
    }

    /**
     * Create password hash
     *
     * @param string $password Password to hash
     * @return string BCrypt hash of password
     */
    public static function passwordHash($password)
    {
        return password_hash($password, PASSWORD_BCRYPT, [ 'cost' => 12 ]);
    }
}
