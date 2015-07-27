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
class StartBody extends AbstractBody
{
    protected $action = TAC_PLUS_AUTHEN_LOGIN;
    protected $privilegeLevel = TAC_PLUS_PRIV_LVL_USER;
    protected $authenticationType = TAC_PLUS_AUTHEN_TYPE_PAP;
    protected $service = TAC_PLUS_AUTHEN_SVC_LOGIN;
    protected $user = '';
    protected $port = '';
    protected $remoteAddress = '';
    protected $data = '';

    /**
     * Returns the binary representation
     *
     * @return string
     */
    public function toBinary()
    {
        $bin = pack(
            'CCCCCCCC',
            $this->action,
            $this->privilegeLevel,
            $this->authenticationType,
            $this->service,
            strlen($this->user),
            strlen($this->port),
            strlen($this->remoteAddress),
            strlen($this->data)
        );
        if (strlen($this->user) > 0) {
            $bin .= pack('a*', $this->user);
        }
        if (strlen($this->port) > 0) {
            $bin .= pack('a*', $this->port);
        }
        if (strlen($this->remoteAddress) > 0) {
            $bin .= pack('a*', $this->remoteAddress);
        }
        if (strlen($this->data) > 0) {
            $bin .= pack('a*', $this->data);
        }
        return $bin;
    }

    /**
     * Gets the value of action.
     *
     * @return mixed
     */
    public function getAction()
    {
        return $this->action;
    }

    /**
     * Sets the value of action.
     *
     * @param mixed $action the action
     *
     * @return self
     */
    public function setAction($action)
    {
        $this->action = $action;

        return $this;
    }

    /**
     * Gets the value of privilegeLevel.
     *
     * @return mixed
     */
    public function getPrivilegeLevel()
    {
        return $this->privilegeLevel;
    }

    /**
     * Sets the value of privilegeLevel.
     *
     * @param mixed $privilegeLevel the privilege level
     *
     * @return self
     */
    public function setPrivilegeLevel($privilegeLevel)
    {
        $this->privilegeLevel = $privilegeLevel;

        return $this;
    }

    /**
     * Gets the value of authenticationType.
     *
     * @return mixed
     */
    public function getAuthenticationType()
    {
        return $this->authenticationType;
    }

    /**
     * Sets the value of authenticationType.
     *
     * @param mixed $authenticationType the authentication type
     *
     * @return self
     */
    public function setAuthenticationType($authenticationType)
    {
        $this->authenticationType = $authenticationType;

        return $this;
    }

    /**
     * Gets the value of service.
     *
     * @return mixed
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * Sets the value of service.
     *
     * @param mixed $service the service
     *
     * @return self
     */
    public function setService($service)
    {
        $this->service = $service;

        return $this;
    }

    /**
     * Gets the value of user.
     *
     * @return mixed
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Sets the value of user.
     *
     * @param mixed $user the user
     *
     * @return self
     */
    public function setUser($user)
    {
        $this->user = $user;

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
