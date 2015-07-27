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
use Monolog\Logger;
use Monolog\Handler\ErrorLogHandler;

// RUNTIME
$tacacs_server_addr         ='127.0.0.1';
$tacacs_server_port         = 4949;
$tacacs_server_secret       = 'MYKEY';

$tacacs_user_username       = 'testuser';
$tacacs_user_password       = 'test1234';
$tacacs_user_port           = '80';
$tacacs_user_remote_addr    = '';

$logger = new Logger('tacacs');

$srv = new Client($logger);
$srv->setServer(
    $tacacs_server_addr,
    $tacacs_server_port,
    $tacacs_server_secret
);

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