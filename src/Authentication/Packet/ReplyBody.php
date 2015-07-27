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
namespace TACACS\Authentication\Packet;

use TACACS\Common\Packet\AbstractBody;
/**
 * PacketHeader represents a TACACS+ Packet Header.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class ReplyBody extends AbstractBody
{
    protected $status = 0;
    protected $flags = 0;
    protected $msgLenght = 0;
    protected $dataLenght = 0;
    protected $msg = null;
    protected $data = null;

    /**
     * Parse binary data
     *
     * @param string $binaryData The binary data
     */
    public function parseBinary($binaryData)
    {
        if (!is_null($binaryData) && strlen($binaryData) >= TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE) {
            $ptr = 0;
            $reply = unpack(
                'C1status/C1flags/n1server_msgLenght/n1dataLenght',
                substr($binaryData, $ptr, TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE)
            );
            $this->status      = $reply['status'];
            $this->flags       = $reply['flags'];
            $this->msgLenght     = $reply['server_msgLenght'];
            $this->dataLenght    = $reply['dataLenght'];

            if ($this->msgLenght > 0) {
                $ptr += TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
                $this->msg = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr,
                        $this->msgLenght
                    )
                )[1];
            }
            if ($this->dataLenght > 0) {
                $ptr += $this->msgLenght;
                $this->data = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr, $this->dataLenght
                    )
                )[1];
            }
        }
    }

    /**
     * Gets the value of status.
     *
     * @return mixed
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * Sets the value of status.
     *
     * @param mixed $status the status
     *
     * @return self
     */
    public function setStatus($status)
    {
        $this->status = $status;

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
     * Gets the value of msgLenght.
     *
     * @return mixed
     */
    public function getMsgLenght()
    {
        return $this->msgLenght;
    }

    /**
     * Sets the value of msgLenght.
     *
     * @param mixed $msgLenght the msg lenght
     *
     * @return self
     */
    public function setMsgLenght($msgLenght)
    {
        $this->msgLenght = $msgLenght;

        return $this;
    }

    /**
     * Gets the value of dataLenght.
     *
     * @return mixed
     */
    public function getDataLenght()
    {
        return $this->dataLenght;
    }

    /**
     * Sets the value of dataLenght.
     *
     * @param mixed $dataLenght the data lenght
     *
     * @return self
     */
    public function setDataLenght($dataLenght)
    {
        $this->dataLenght = $dataLenght;

        return $this;
    }

    /**
     * Gets the value of msg.
     *
     * @return mixed
     */
    public function getMsg()
    {
        return $this->msg;
    }

    /**
     * Sets the value of msg.
     *
     * @param mixed $msg the msg
     *
     * @return self
     */
    public function setMsg($msg)
    {
        $this->msg = $msg;

        return $this;
    }

    /**
     * Gets the value of data.
     *
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * Sets the value of data.
     *
     * @param mixed $data the data
     *
     * @return self
     */
    public function setData($data)
    {
        $this->data = $data;

        return $this;
    }
}
