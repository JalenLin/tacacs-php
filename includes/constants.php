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

// VERSION
define('TAC_PLUS_MAJOR_VER_MASK', 0xf0);
define('TAC_PLUS_MAJOR_VER',      0xc0);
define('TAC_PLUS_MINOR_VER_0',    0x00);
define('TAC_PLUS_VER_0',          (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_0));
define('TAC_PLUS_MINOR_VER_1',    0x01);
define('TAC_PLUS_VER_1',          (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_1));

// TYPE
define('TAC_PLUS_AUTHEN',   0x01);
define('TAC_PLUS_AUTHOR',   0x02);
define('TAC_PLUS_ACCT',     0x03);

// FLAGS
define('TAC_PLUS_ENCRYPTED_FLAG',       0x00);  /* packet is encrypted */
define('TAC_PLUS_UNENCRYPTED_FLAG',     0x01);  /* packet is unencrypted */
define('TAC_PLUS_SINGLE_CONNECT_FLAG',  0x04);  /* multiplexing supported */

// ACTION
define('TAC_PLUS_AUTHEN_LOGIN',     0x01);
define('TAC_PLUS_AUTHEN_CHPASS',    0x02);
define('TAC_PLUS_AUTHEN_SENDPASS',  0x03); /* deprecated */
define('TAC_PLUS_AUTHEN_SENDAUTH',  0x04);

// PRIV LEVELS
define('TAC_PLUS_PRIV_LVL_MIN',     0x00);
define('TAC_PLUS_PRIV_LVL_MAX',     0x0f);
define('TAC_PLUS_PRIV_LVL_USER',    0x01);
define('TAC_PLUS_PRIV_LVL_ROOT',    0x0f);

// AUTH TYPES
define('TAC_PLUS_AUTHEN_TYPE_ASCII',    0x01);
define('TAC_PLUS_AUTHEN_TYPE_PAP',      0x02);
define('TAC_PLUS_AUTHEN_TYPE_CHAP',     0x03);
define('TAC_PLUS_AUTHEN_TYPE_ARAP',     0x04);
define('TAC_PLUS_AUTHEN_TYPE_MSCHAP',   0x05);

// SERVICES
define('TAC_PLUS_AUTHEN_SVC_NONE',      0x00);
define('TAC_PLUS_AUTHEN_SVC_LOGIN',     0x01);
define('TAC_PLUS_AUTHEN_SVC_ENABLE',    0x02);
define('TAC_PLUS_AUTHEN_SVC_PPP',       0x03);
define('TAC_PLUS_AUTHEN_SVC_ARAP',      0x04);
define('TAC_PLUS_AUTHEN_SVC_PT',        0x05);
define('TAC_PLUS_AUTHEN_SVC_RCMD',      0x06);
define('TAC_PLUS_AUTHEN_SVC_X25',       0x07);
define('TAC_PLUS_AUTHEN_SVC_NASI',      0x08);
define('TAC_PLUS_AUTHEN_SVC_FWPROXY',   0x09);

define('TAC_PLUS_CONTINUE_FLAG_ABORT',  0x01);

// AUTHENTICATION STATUS
define('TAC_PLUS_AUTHEN_STATUS_PASS',       0x01);
define('TAC_PLUS_AUTHEN_STATUS_FAIL',       0x02);
define('TAC_PLUS_AUTHEN_STATUS_GETDATA',    0x03);
define('TAC_PLUS_AUTHEN_STATUS_GETUSER',    0x04);
define('TAC_PLUS_AUTHEN_STATUS_GETPASS',    0x05);
define('TAC_PLUS_AUTHEN_STATUS_RESTART',    0x06);
define('TAC_PLUS_AUTHEN_STATUS_ERROR',      0x07);
define('TAC_PLUS_AUTHEN_STATUS_FOLLOW',     0x21);

define('TAC_PLUS_AUTHEN_FLAG_NOECHO',       0x01);

// SIZES
define('TAC_PLUS_HDR_SIZE',                     12);
define('TAC_AUTHEN_START_FIXED_FIELDS_SIZE',    8);
define('TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE',     5);
define('TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE',    6);
