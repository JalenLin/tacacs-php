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
class Packet
{
    /**
     * @var Header
     */
    protected $header;

    /**
     * @var AbstractBody
     */
    protected $body;

    /**
     * @var string
     */
    protected $secret;

    /**
     * Class contructor
     *
     * @param Header       $header The header
     * @param AbstractBody $body   The body
     */
    public function __construct(Header $header, AbstractBody $body)
    {
        $this->header = $header;
        $this->body = $body;
    }

    /**
     * To binary
     *
     * @return string
     */
    public function toBinary()
    {
        $binBody = $this->body->toBinary();

        $this->header->setLenght(strlen($binBody));
        $binHeader = $this->header->toBinary();

        $pad = $this->header->getPseudoPad($this->secret);

        return $binHeader . ( $binBody ^ $pad );
    }

    /**
     * Parse binary data
     *
     * @param string $binaryData The binary data
     */
    public function parseBinary($binaryData)
    {
        $binHeader = substr($binaryData, 0, TAC_PLUS_HDR_SIZE);
        $this->header->parseBinary($binHeader);

        $pad = $this->header->getPseudoPad($this->secret);

        $binBody = substr($binaryData, TAC_PLUS_HDR_SIZE);
        $reply = $this->body->parseBinary(($binBody ^ $pad));
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
     * Gets the value of header.
     *
     * @return Header
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Gets the value of body.
     *
     * @return AbstractBody
     */
    public function getBody()
    {
        return $this->body;
    }
}
