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
* AuthReply represents a TACACS+ REPLY Message.
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @access   public
* @link     https://github.com/martinclaro
*/
class AuthReply
{
    private $_debug = false;
    private $_status = 0;
    private $_flags = 0;
    private $_msg_len = 0;
    private $_data_len = 0;
    private $_msg = null;
    private $_data = null;

    /**
     * Class constructor
     *
     * @param string $binaryData The binary data
     */
    public function __construct($binaryData = null)
    {
        if (!is_null($binaryData) && strlen($binaryData) >= TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE) {
            $ptr = 0;
            $reply = unpack(
                'C1status/C1flags/n1server_msg_len/n1data_len',
                substr($binaryData, $ptr, TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE)
            );
            $this->_status      = $reply['status'];
            $this->_flags       = $reply['flags'];
            $this->_msg_len     = $reply['server_msg_len'];
            $this->_data_len    = $reply['data_len'];

            if ($this->_msg_len > 0) {
                $ptr += TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
                $this->_msg = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr,
                        $this->_msg_len
                    )
                )[1];
            }
            if ($this->_data_len > 0) {
                $ptr += $this->_msg_len;
                $this->_data = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr, $this->_data_len
                    )
                )[1];
            }
        }
        $this->_log(print_r($this, true));
    }

    /**
     * Get status
     *
     * @return string
     */
    public function getStatus()
    {
        return $this->_status;
    }

    /**
     * Set debug
     *
     * @param boolean $val The value
     *
     * @return void
     */
    public function setDebug($val=true)
    {
        $this->_debug = $val;
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
