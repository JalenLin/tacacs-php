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
namespace TACACS\Authentication\Builder;

use TACACS\Common\Builder\AbstractPacketBuilder;
use TACACS\Common\Packet\Header;
use TACACS\Common\Packet\Packet;
use TACACS\Authentication\Packet\ReplyBody;
/**
 * PacketHeader represents a TACACS+ Packet Header.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class ReplyPacketBuilder extends AbstractPacketBuilder
{
    /**
     * Build
     *
     * @return Packet
     */
    public function build()
    {
        $header = new Header();
        $body = new ReplyBody();

        $packet = new Packet($header, $body);
        $packet->setSecret($this->secret);

        return $packet;
    }
}
