<?php
/**
 * Tacacs_Client is a sample TACACS+ client for authentication purposes.
 *
 * This source code is provided as a demostration for TACACS+ authentication.
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
namespace TACACS\Common\Packet;
/**
 * Util implements TACACS+ Packet utilities.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class Util
{
    /**
     * Gets binary length of a binary stream.
     *
     * @param string $binaryData The binary data
     *
     * @return Integer
     */
    public static function binaryLength($binaryData)
    {
        return strlen(bin2hex($binaryData))/2;
    }
}
