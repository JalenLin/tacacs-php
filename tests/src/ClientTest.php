<?php
/**
 * Tacacs_Client is a sample TACACS+ client for authentication purposes.
 *
 * This source code is provided as a demostration for TACACS+ authentication.
 *
 * PHP version 5
 *
 * @category Tests
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
use TACACS\Client;
/**
 * Client represents a TACACS+ Client.
 *
 * @category Tests
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class ClientTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test construct
     *
     * @return void
     */
    public function testConstruct()
    {
        $cli = new Client();

        $obj = new ReflectionClass('\TACACS\Client');
        $property = $obj->getProperty('logger');
        $property->setAccessible(true);

        $this->assertNull($property->getValue($cli));
    }

    /**
     * Test setServer
     *
     * @return void
     */
    public function testSetServer()
    {
        $addr = '127.0.0.1';
        $port = '49';
        $secret = 'secret';

        $cli = new Client();
        $cli->setServer($addr, $port, $secret);

        $obj = new ReflectionClass('\TACACS\Client');

        $addrProp = $obj->getProperty('addr');
        $addrProp->setAccessible(true);
        $this->assertEquals($addr, $addrProp->getValue($cli));

        $portProp = $obj->getProperty('port');
        $portProp->setAccessible(true);
        $this->assertEquals($port, $portProp->getValue($cli));

        $secretProp = $obj->getProperty('secret');
        $secretProp->setAccessible(true);
        $this->assertEquals($secret, $secretProp->getValue($cli));
    }
}