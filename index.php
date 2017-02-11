<?php

use DynDNS\DynDNS;

set_include_path(get_include_path() . PATH_SEPARATOR . 'PEAR' . DIRECTORY_SEPARATOR);
require_once 'DynDNS/DynDNS.php';
require_once 'PEAR/Net/DNS2.php';

// Load configuration
$config = array();
include_once 'config/config.php';

if (php_sapi_name() === 'cli') {
    // Create password hash on CLI usage
    if ($_SERVER['argc'] === 2) {
        echo 'Your password hash is:'."\n";
        echo DynDNS::passwordHash($_SERVER['argv'][1])."\n";
    } else {
        echo 'Create password hash for config using'."\n\n";
        echo $_SERVER['_'].' '.$_SERVER['argv'][0].' PASSWORD'."\n";
    }
} else {
    // Start DynDNS server client
    $dyndns = new DynDNS($config);
}
