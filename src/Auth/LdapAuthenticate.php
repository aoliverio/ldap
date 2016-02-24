<?php

/**
 * Copyright (c) Antonio Oliverio. (http://aoliverio.com)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Antonio Oliverio. (http://aoliverio.com)
 * @link          https://github.com/aoliverio/ldap
 * @since         1.0
 * @license       http://www.opensource.org/licenses/mit-license.php MIT License
 */

namespace QueenCityCodeFactory\LDAP\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Log\LogTrait;
use Cake\Network\Exception\InternalErrorException;
use Cake\Network\Exception\UnauthorizedException;
use Cake\Network\Request;
use Cake\Network\Response;

/**
 * LDAP Authentication adapter for AuthComponent.
 *
 * Provides LDAP authentication support for AuthComponent. 
 * LDAP will authenticate users against the specified LDAP Server
 */
class LdapAuthenticate extends BaseAuthenticate {

    /**
     * Define $ldapConnection object
     *
     * @var object
     */
    private $ldapConnection;

    /**
     * Set default $usernameField
     *
     * @var type 
     */
    private $usernameField = 'username';

    /**
     * Set default $passwordField
     *
     * @var type 
     */
    private $passwordField = 'password';

    /**
     * Constructor
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, array $ldap_setting = []) {

        /**
         * Construct $config array from $ldap_setting['config]
         */
        $config = $ldap_setting['config'];
        parent::__construct($registry, $config);

        /**
         * Set default LDAP_OPT_DIAGNOSTIC_MESSAGE
         */
        if (!defined('LDAP_OPT_DIAGNOSTIC_MESSAGE'))
            define('LDAP_OPT_DIAGNOSTIC_MESSAGE', 0x0032);

        /**
         * Set $config['host']
         */
        if (isset($config['host']) && is_object($config['host']) && ($config['host'] instanceof \Closure))
            $config['host'] = $config['host']();
        if (empty($config['host']))
            throw new InternalErrorException('LDAP Server not specified!');

        /**
         * Set $config['port']
         */
        if (empty($config['port']))
            $config['port'] = null;

        /**
         * Set usernameField and passwordField fields name from $ldap_setting['fields']
         */
        $fields = $ldap_setting['fields'];
        if (is_array($fields)) {
            if (isset($fields['username']))
                $this->usernameField = trim($fields['username']);
            if (isset($fields['password']))
                $this->passwordField = trim($fields['password']);
        }

        /**
         * Set $this->ldapConnection
         */
        try {
            $this->ldapConnection = ldap_connect($config['host'], $config['port']);
            foreach ($config['options'] as $key => $value)
                ldap_set_option($this->ldapConnection, $key, $value);
        } catch (Exception $e) {
            throw new InternalErrorException('Unable to connect to specified LDAP Server(s)!');
        }
    }

    /**
     * Destructor
     */
    public function __destruct() {
        @ldap_unbind($this->ldapConnection);
        @ldap_close($this->ldapConnection);
    }

    /**
     * Authenticate a user based on the request information.
     *
     * @param \Cake\Network\Request $request The request to authenticate with.
     * @param \Cake\Network\Response $response The response to add headers to.
     * @return mixed Either false on failure, or an array of user data on success.
     */
    public function authenticate(Request $request, Response $response) {

        /**
         * Verify if is provided the username and password
         */
        if (!isset($request->data[$this->usernameField]) || !isset($request->data[$this->passwordField]))
            return false;

        /**
         * Call _findUser function
         */
        return $this->_findUser($request->data[$this->usernameField], $request->data[$this->passwordField]);
    }

    /**
     * Find a user record using the username and password provided.
     *
     * @param string $username The username/identifier.
     * @param string|null $password The password
     * @return bool|array Either false on failure, or an array of user data.
     */
    protected function _findUser($username, $password = null) {

        /**
         * 
         */
        if (!empty($this->_config['domain']) && !empty($username) && strpos($username, '@') === false)
            $username .= '@' . $this->_config['domain'];

        /**
         * Set_error_handler
         */
        set_error_handler(function ($errorNumber, $errorText, $errorFile, $errorLine) {
            throw new \ErrorException($errorText, 0, $errorNumber, $errorFile, $errorLine);
        }, E_ALL
        );

        /**
         * Set LDAP_DN on the fly
         */
        $LDAP_RDN = 'mail=' . $username . ',' . $this->_config['base_dn'];

        /**
         * LDAP BIND
         */
        try {
            $ldapBind = ldap_bind($this->ldapConnection, $LDAP_RDN, $password);
            if ($ldapBind === true) {
                $searchResults = ldap_search($this->ldapConnection, $LDAP_RDN, '(' . $this->_config['search'] . '=' . $username . ')');
                $results = ldap_get_entries($this->ldapConnection, $searchResults);
                $entry = ldap_first_entry($this->ldapConnection, $searchResults);
                return ldap_get_attributes($this->ldapConnection, $entry);
            }
        } catch (\ErrorException $e) {
            $this->log($e->getMessage());
            if (ldap_get_option($this->ldapConnection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extendedError)) {
                if (!empty($extendedError)) {
                    foreach ($this->_config['errors'] as $error => $errorMessage) {
                        if (strpos($extendedError, $error) !== false) {
                            $messages[] = [
                                'message' => $errorMessage,
                                'key' => $this->_config['flash']['key'],
                                'element' => $this->_config['flash']['element'],
                                'params' => $this->_config['flash']['params'],
                            ];
                        }
                    }
                }
            }
        }

        /**
         * 
         */
        restore_error_handler();

        /**
         * 
         */
        if (!empty($messages)) {
            $controller = $this->_registry->getController();
            $controller->request->session()->write('Flash.' . $this->_config['flash']['key'], $messages);
        }
        return false;
    }

}
