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
namespace TACACS\Authentication;

use TACACS\Authentication\Packet\StartBody;
use TACACS\Common\Packet\Header;
use TACACS\Common\Packet\Packet;
/**
 * PacketHeader represents a TACACS+ Packet Header.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class StartPacketBuilder
{
    protected $secret;
    protected $username;
    protected $password;
    protected $port;
    protected $remoteAddress;
    protected $sequenceNumber;
    protected $sessionId;

    /**
     * Build
     *
     * @return Packet
     */
    public function build()
    {
        $body = new StartBody();
        $body->setUser($this->username);
        $body->setPort($this->port);
        $body->setRemoteAddress(@inet_pton($this->remoteAddress));
        $body->setData($this->password);

        $header = new Header();
        $header->setVersion(TAC_PLUS_VER_ONE);
        $header->setSequenceNumber($this->sequenceNumber);
        $header->setSessionId($this->sessionId);

        $packet = new Packet($header, $body);
        $packet->setSecret($this->secret);

        return $packet;
    }

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

    /**
     * Gets the value of username.
     *
     * @return mixed
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Sets the value of username.
     *
     * @param mixed $username the username
     *
     * @return self
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * Gets the value of password.
     *
     * @return mixed
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Sets the value of password.
     *
     * @param mixed $password the password
     *
     * @return self
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Gets the value of port.
     *
     * @return mixed
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * Sets the value of port.
     *
     * @param mixed $port the port
     *
     * @return self
     */
    public function setPort($port)
    {
        $this->port = $port;

        return $this;
    }

    /**
     * Gets the value of remoteAddress.
     *
     * @return mixed
     */
    public function getRemoteAddress()
    {
        return $this->remoteAddress;
    }

    /**
     * Sets the value of remoteAddress.
     *
     * @param mixed $remoteAddress the remote address
     *
     * @return self
     */
    public function setRemoteAddress($remoteAddress)
    {
        $this->remoteAddress = $remoteAddress;

        return $this;
    }

    /**
     * Gets the value of sequenceNumber.
     *
     * @return mixed
     */
    public function getSequenceNumber()
    {
        return $this->sequenceNumber;
    }

    /**
     * Sets the value of sequenceNumber.
     *
     * @param mixed $sequenceNumber the sequence number
     *
     * @return self
     */
    public function setSequenceNumber($sequenceNumber)
    {
        $this->sequenceNumber = $sequenceNumber;

        return $this;
    }

    /**
     * Gets the value of sessionId.
     *
     * @return mixed
     */
    public function getSessionId()
    {
        return $this->sessionId;
    }

    /**
     * Sets the value of sessionId.
     *
     * @param mixed $sessionId the session id
     *
     * @return self
     */
    public function setSessionId($sessionId)
    {
        $this->sessionId = $sessionId;

        return $this;
    }
}
