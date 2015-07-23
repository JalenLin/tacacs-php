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
* @version  GIT: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
namespace TACACS;
/**
* PacketHeader represents a TACACS+ Packet Header.
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @access   public
* @link     https://github.com/martinclaro
*/
class PacketHeader
{
    private $_debug = false;
    private $_version = TAC_PLUS_VER_1;
    private $_type = TAC_PLUS_AUTHEN;
    private $_seqNo = 0;
    private $_flags = 0;
    private $_sessionId = 0;
    private $_dataLen = 0;
    private $_data = null;
    private $_pseudoPad = null;
    private $_isEncrypted = true;

    /**
     * Class constructor
     *
     * @param string $binaryData The binary data
     */
    public function __construct($binaryData = null)
    {
        if (!is_null($binaryData) && strlen($binaryData) >= TAC_PLUS_HDR_SIZE) {
            // Decode from data
            $tmp = unpack(
                'C1version/C1type/C1seq_no/C1flags/N1session_id/N1data_len',
                substr($binaryData, 0, TAC_PLUS_HDR_SIZE)
            );

            $this->_log(print_r($tmp, true));

            $this->_version     = $tmp['version'];
            $this->_type        = $tmp['type'];
            $this->_seqNo       = $tmp['seq_no'];
            $this->_flags       = $tmp['flags'];
            $this->_sessionId   = $tmp['session_id'];
            $this->_dataLen     = $tmp['data_len'];
            $mask = $this->_flags & TAC_PLUS_UNENCRYPTED_FLAG;

            if ($mask == TAC_PLUS_UNENCRYPTED_FLAG) {
                $this->_log("INFO: TAC_PLUS_UNENCRYPTED_FLAG enabled.");
                $this->_isEncrypted = false;
            } else {
                $this->_log("INFO: TAC_PLUS_UNENCRYPTED_FLAG disabled.");
                $this->_isEncrypted = true;
            }
            $this->_log(print_r($this, true));

        } else if (is_null($binaryData)) {
            // Create from scratch
            $this->_seqNo = 1;
            $this->_flags = TAC_PLUS_SINGLE_CONNECT_FLAG;
        } else {
            $this->_log("ERROR: binary data failed!.");
        }
    }

    /**
     * Get sequence number
     *
     * @return string
     */
    public function getSequenceNumber()
    {
        return $this->_seqNo;
    }

    /**
     * Set version
     *
     * @param string $val The val
     *
     * @return void
     */
    public function setVersion($val)
    {
        $this->_version = $val;
    }

    /**
     * Set session id
     *
     * @param string $val The val
     *
     * @return void
     */
    public function setSessionId($val)
    {
        $this->_sessionId = $val;
    }

    /**
     * Set sequence number
     *
     * @param string $seq The seq
     *
     * @return void
     */
    public function setSequenceNumber($seq)
    {
        $this->_seqNo = $seq;
    }

    /**
     * Set data
     *
     * @param string $binaryData The binary data
     *
     * @return void
     */
    public function setData($binaryData)
    {
        $this->_data = $binaryData;
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
        $this->_pseudoPad = hash(
            'md5',
            pack(
                'Na*CC',
                $this->_sessionId,
                $secret,
                $this->_version,
                $this->_seqNo
            ),
            true
        );
        $this->_log(
            'PSEUDO_PAD (MD5_1): '. print_r(
                unpack(
                    'H*',
                    $this->_pseudoPad
                )[1], true
            )
        );
        while (strlen($this->_pseudoPad) < $this->_dataLen) {
            $this->_pseudoPad = $this->_pseudoPad .
                                hash(
                                    'md5',
                                    pack(
                                        'Na*CC',
                                        $this->_sessionId,
                                        $secret,
                                        $this->_version,
                                        $this->_seqNo
                                    ) .
                                    $this->_pseudoPad,
                                    true
                                );
        }

        $this->_log(
            'PSEUDO_PAD (MD5_n): '. print_r(
                unpack(
                    'H*',
                    $this->_pseudoPad
                )[1], true
            )
        );
        $this->_pseudoPad = substr($this->_pseudoPad, 0, $this->_dataLen);
        $this->_log(
            'PSEUDO_PAD (FINAL): '. print_r(
                unpack(
                    'H*',
                    $this->_pseudoPad
                )[1], true
            )
        );
        return $this->_pseudoPad;
    }

    /**
     * To binary
     *
     * @return string
     */
    public function toBinary()
    {
        $this->_calculate();
        $this->_log(print_r($this, true));
        return pack(
            'CCCCNN', $this->_version,
            $this->_type,
            $this->_seqNo,
            $this->_flags,
            $this->_sessionId,
            $this->_dataLen
        );
    }

    /**
     * Set debug
     *
     * @param type $val The val
     *
     * @return void
     */
    public function setDebug($val=true)
    {
        $this->_debug = $val;
    }

    /**
     * Calculate
     *
     * @return void
     */
    private function _calculate()
    {
        $this->_dataLen = strlen($this->_data);
    }

    /**
     * Log
     *
     * @param mixed $obj The record to log
     *
     * @return void
     */
    private function _log($obj="")
    {
        if ($this->_debug) {
            echo "DEBUG: ";
            if (is_string($obj)) {
                echo $obj;
            } else {
                echo print_r($obj, true);
            }
            echo "\n";
        }
    }
}
