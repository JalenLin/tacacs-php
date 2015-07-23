<?php
/**
* Tacacs_Client is a sample TACACS+ client for authentication purposes.
*
* This source code is provided as a demostration for TACACS+ authentication.
*
* PHP Version 5
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @version  GIT: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();

require_once __DIR__ . '/../vendor/autoload.php';

use TACACS\Client;

// RUNTIME
$tacacs_server_addr         ='192.168.197.150';
$tacacs_server_port         = 49;
$tacacs_server_secret       = 'testing123';

$tacacs_user_username       = 'testuser';
$tacacs_user_password       = 'test1234';
$tacacs_user_port           = 'http';
$tacacs_user_remote_addr    = '192.168.197.122';

$srv = new Client(true);
$srv->setServer(
    $tacacs_server_addr,
    $tacacs_server_port,
    $tacacs_server_secret
);
$srv->connect();
$res = $srv->authenticate(
    $tacacs_user_username,
    $tacacs_user_password,
    $tacacs_user_port,
    $tacacs_user_remote_addr
);
if ($res) {
    echo "\nAUTHENTICATION SUCCESS!\n\n";
} else {
    echo "\nAUTHENTICATION FAILED!\n\n";
}
$srv->disconnect();

