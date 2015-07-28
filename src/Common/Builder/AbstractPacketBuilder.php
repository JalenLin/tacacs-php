<?php
/**
 * Tacacs_Client is a sample TACACS+ client for authentication purposes.
 *
 * This source code is provided as a demostration for TACACS+ authentication.
 *
 * PHP version 5
 *
 * @category Common
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
namespace TACACS\Common\Builder;
/**
 * PacketHeader represents a TACACS+ Packet Header.
 *
 * @category Common
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
abstract class AbstractPacketBuilder implements PacketBuilderInterface
{
    protected $secret;

    /**
     * Build
     *
     * @return Packet
     */
    abstract public function build();

    /**
     * Gets the value of secret.
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Sets the value of secret.
     *
     * @param string $secret the secret
     *
     * @return self
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }
}
