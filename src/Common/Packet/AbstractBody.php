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
 * PacketHeader represents a TACACS+ Packet Header.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class AbstractBody implements BinarizableInterface
{
    /**
     * Parse binary data
     *
     * @param string $binaryData The binary data
     *
     * @return void
     */
    public function parseBinary($binaryData)
    {
    }

    /**
     * To binary
     *
     * @return string
     */
    public function toBinary()
    {
    }
}
