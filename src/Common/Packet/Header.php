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
class Header implements BinarizableInterface
{
    protected $version = TAC_PLUS_VER_DEFAULT;
    protected $type = TAC_PLUS_AUTHEN;
    protected $sequenceNumber = 0;
    protected $flags = TAC_PLUS_ENCRYPTED_FLAG;
    protected $sessionId = 0;
    protected $lenght = 0;

    /**
     * To binary
     *
     * @return string
     */
    public function toBinary()
    {
        return pack(
            'CCCCNN',
            $this->version,
            $this->type,
            $this->sequenceNumber,
            $this->flags,
            $this->sessionId,
            $this->lenght
        );
    }

    /**
     * Parse binary data
     *
     * @param string $binaryData The binary data
     */
    public function parseBinary($binaryData)
    {
        $binaryLen = Util::binaryLength($binaryData);
        if (!is_null($binaryData) && $binaryLen == TAC_PLUS_HDR_SIZE) {
            $tmp = unpack(
                'C1version/C1type/C1seq_no/C1flags/N1session_id/N1data_len',
                $binaryData
            );

            $this->version = $tmp['version'];
            $this->type = $tmp['type'];
            $this->sequenceNumber = $tmp['seq_no'];
            $this->flags = $tmp['flags'];
            $this->sessionId = $tmp['session_id'];
            $this->lenght = $tmp['data_len'];

        } else if (is_null($binaryData)) {
            // Create from scratch
            $this->_sequenceNumber = 1;
            $this->_flags = TAC_PLUS_SINGLE_CONNECT_FLAG;

        } else {
            throw new \UnexpectedValueException("Binary header failed");
        }
    }

    /**
     * Is encripted
     *
     * @return boolean
     */
    public function isEncrypted()
    {
        $mask = $this->_flags & TAC_PLUS_UNENCRYPTED_FLAG;

        return $mask != TAC_PLUS_UNENCRYPTED_FLAG;
    }

    /**
     * Get pseudo pad
     *
     * @param string $secret The secret
     *
     * @return string
     */
    public function getPseudoPad($secret)
    {
        $md5 = array();
        $n = 1;
        $md5[$n] = hash(
            'md5',
            pack(
                'Na*CC',
                $this->sessionId,
                $secret,
                $this->version,
                $this->sequenceNumber
            ),
            true
        );

        while (Util::binaryLength(implode($md5)) < $this->lenght) {
            $n++;
            $md5[$n] = hash(
                'md5',
                pack(
                    'Na*CC',
                    $this->sessionId,
                    $secret,
                    $this->version,
                    $this->sequenceNumber
                ) .
                $md5[($n - 1)],
                true
            );
        }

        $unpackMask = "a". $this->lenght ."pad";
        $pad = unpack($unpackMask, implode($md5));
        $pseudoPad = $pad['pad'];

        return $pseudoPad;
    }

    /**
     * Gets the value of version.
     *
     * @return mixed
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * Sets the value of version.
     *
     * @param mixed $version the major version
     *
     * @return self
     */
    public function setVersion($version)
    {
        $this->version = $version;

        return $this;
    }

    /**
     * Gets the value of type.
     *
     * @return mixed
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Sets the value of type.
     *
     * @param mixed $type the type
     *
     * @return self
     */
    public function setType($type)
    {
        $this->type = $type;

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
     * @param mixed $sequenceNumber the seq no
     *
     * @return self
     */
    public function setSequenceNumber($sequenceNumber)
    {
        $this->sequenceNumber = $sequenceNumber;

        return $this;
    }

    /**
     * Gets the value of flags.
     *
     * @return mixed
     */
    public function getFlags()
    {
        return $this->flags;
    }

    /**
     * Sets the value of flags.
     *
     * @param mixed $flags the flags
     *
     * @return self
     */
    public function setFlags($flags)
    {
        $this->flags = $flags;

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

    /**
     * Gets the value of lenght.
     *
     * @return mixed
     */
    public function getLenght()
    {
        return $this->lenght;
    }

    /**
     * Sets the value of lenght.
     *
     * @param mixed $lenght the lenght
     *
     * @return self
     */
    public function setLenght($lenght)
    {
        $this->lenght = $lenght;

        return $this;
    }
}
