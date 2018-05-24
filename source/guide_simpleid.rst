.. author:: J | 927589452.de

.. sidebar:: Logo
  
  .. image:: _static/images/simpleid.png 
      :align: center

#########
SimpleID
#########

SimpleID_ is a simple, personal OpenID_ provider written in PHP.

----

.. note:: For this guide you should be familiar with the basic concepts of 

  * PHP_
  * domains_

Prerequisites
=============

We're using PHP_ in the stable version 7.1:

::

 [isabell@stardust ~]$ uberspace tools version show php
 Using 'PHP' version: '7.1'
 [isabell@stardust ~]$


If you want to use your OpenID with your own domain you need to setup your domain first:

.. include:: includes/web-domain-list.rst

Installation
============

``cd`` to your `document root`_, then download the latest release of the SimpleID and extract it:

.. note:: The link to the lastest version can be found at SimpleID's `release page <https://simpleID.koinic.net/releases/all>`_.

.. code-block:: console
 :emphasize-lines: 1,2,8

 [isabell@stardust ~]$ curl --location --output simpleid.tar.gz https://downloads.sourceforge.net/simpleid/simpleid-42.23.1.tar.gz
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
 100   384  100   384    0     0   1177      0 --:--:-- --:--:-- --:--:--  1181
 100   359  100   359    0     0    732      0 --:--:-- --:--:-- --:--:--   732
 100  167k  100  167k    0     0   6426      0  0:00:26  0:00:26 --:--:-- 43611
 [isabell@stardust ~]$ tar --extract --file simpleid.tar.gz 
 [isabell@stardust ~]$ 


Housekeeping
============

``rm`` the archive:

.. code-block:: console
 :emphasize-lines: 1

 [isabell@stardust ~]$ rm simpleid.tar.gz
 [isabell@stardust ~]$ 


Moving the Folders
==================

Folders that should not be publicly available `cache`, `store`, `identities`.


.. code-block:: console
 :emphasize-lines: 1,2,3,4,5

 [isabell@stardust ~]$ cp --recursive simpleid/cache /var/www/virtual/$USER/
 [isabell@stardust ~]$ cp --recursive simpleid/identities /var/www/virtual/$USER/
 [isabell@stardust ~]$ cp --recursive simpleid/store /var/www/virtual/$USER/
 [isabell@stardust ~]$ cp --recursive simpleid/wwww/* /var/www/virtual/$USER/html
 [isabell@stardust ~]$ 


Configure SimpleID
==================

Copy the standard configuration to the `document root`_ and edit it.


.. code-block:: console
 :emphasize-lines: 1,2,3,4,5

 [isabell@stardust ~]$ cp /var/www/virtual/$USER/html/config.php.dist /var/www/virtual/$USER/html/config.php
 [isabell@stardust ~]$ 


It should look like this, you can even change the language:
.. warning:: Replace ``<domain>`` with your domain!

.. warning:: Replace ``$USER`` with your user!

.. code-block::
 :emphasize-lines: 32,33,61,74,101,161

 <?php
 /**
  * SimpleID configuration file.
  *
  * @package simpleid
  *
  */
 /*
  * $Id$
  *
  */
 
 
 /**
  * Base URL.
  *
  * This is the URL of the location you want to place your SimpleID
  * distribution.  It becomes the URL of the SimpleID server.
  *
  * It is not allowed to have a trailing slash; SimpleID will add it
  * for you.
  *
  * Examples:
  * <code>
  *   define('SIMPLEID_BASE_URL', 'http://www.example.com');
  *   define('SIMPLEID_BASE_URL', 'http://www.example.com:8888');
  *   define('SIMPLEID_BASE_URL', 'http://www.example.com/simpleid');
  *   define('SIMPLEID_BASE_URL', 'https://www.example.com:8888/simpleid');
  * </code>
  *
  */
 define('SIMPLEID_BASE_URL', 'http://<domain>');
 define('SIMPLEID_BASE_URL', 'https://<domain>');
 
 /**
  * Allow clean URLs.
  *
  * URLs used in SimpleID are normally in the form
  * http://www.example.com/index.php?q=foo.  Enabling clean URLs will allow for
  * SimpleID URLs to be in the form http://www.example.com/foo
  *
  * In order to support clean URLs, you must be using Apache with mod_rewrite
  * enabled.  You will need to rename .htaccess.dist in the SimpleID web directory
  * to .htaccess
  *
  * @since 0.8
  *
  */
 define('SIMPLEID_CLEAN_URL', false);
 
 /**
  * Directory to store identity information.
  *
  * This directory must exist and be readable by the web server.
  *
  * For maximum security, it is highly recommended to place this
  * directory outside your web browser's document root directory, so
  * that it is not visible to user agents.
  *
  */
 define('SIMPLEID_IDENTITIES_DIR', '/var/www/virtual/$USER/identities');
 
 /**
  * Directory to store cache data.
  *
  * This directory must exist and be readable and writable by the
  * web server.
  *
  * For maximum security, it is highly recommended to place this
  * directory outside your web browser's document root directory, so
  * that it is not visible to user agents.
  *
  */
 define('SIMPLEID_CACHE_DIR', '/var/www/virtual/$USER/cache');
 
 /**
  * Persistent data storage mechanism.
  *
  * SimpleID provides flexible methods to store and retrieve persistent data.
  * By default, SimpleID uses the file system to store this data, implemented
  * in filesystem.store.inc.  Users can implement other methods by creating
  * a file with extension .store.inc and specifying the file through this
  * setting.
  * 
  * Generally you do not need to change this setting.
  *
  */
 define('SIMPLEID_STORE', 'filesystem');
 
 /**
  * Directory to store persistent data.
  *
  * This directory must exist and be readable and writable by the
  * web server.
  *
  * For maximum security, it is highly recommended to place this
  * directory outside your web browser's document root directory, so
  * that it is not visible to user agents.
  *
  */
 define('SIMPLEID_STORE_DIR', '/var/www/virtual/$USER/store');
 
 /**
  * Allows use of unencrypted connections.
  *
  * Between versions 0.6 and 0.8 (inclusive), SimpleID uses either HTTPS or 
  * a form of digest authentication for its login system.  This allows passwords
  * and other secure information not to be sent to the server as plaintext.
  *
  * From version 0.9, SimpleID mandates the use of HTTPS for all connections
  * (other than direct connections between SimpleID and an OpenID relying
  * party).  However, for debug purposes, it may be necessary to allow
  * unencrypted connections to SimpleID.
  *
  * It is strongly recommended that this is set to false.  Setting this to true
  * will allow passwords to be sent as plaintext.  You should not change this
  * value unless it is absolutely necessary.
  *
  * @since 0.9
  */
 define('SIMPLEID_ALLOW_PLAINTEXT', false);
 
 /**
  * Allows web browsers to save passwords.
  *
  * SimpleID prevents web browsers from saving user passwords entered in a user
  * logs into SimpleID.  Setting this value to true will allow browsers to
  * ask the user whether the password should be saved in the browser's password
  * store.
  *
  * The default is set to false for security reasons.  You should not change
  * this value unless you are certain regarding the security of your browser's
  * password store.
  *
  * @since 0.8
  */
 define('SIMPLEID_ALLOW_AUTOCOMPLETE', false);
 
 /**
  * Performs additional verification of relying party return URLs.
  *
  * When authenticating using OpenID version 2, SimpleID version 0.7 or later
  * can perform additional verification of the relying party's return URLs under
  * section 9.2.1 of the OpenID specification.
  *
  * The default is set to true for security reasons.  However, if your web server
  * is blocked by your web hosting provider's firewall from accessing outside
  * servers, then set this to false.
  *
  * @since 0.7
  *
  */
 define('SIMPLEID_VERIFY_RETURN_URL_USING_REALM', true);
 
 
 /**
  * The locale for the SimpleID user interface.
  *
  * @since 0.9
  */
 define('SIMPLEID_LOCALE', 'en');
 
 /**
  * Date and time format.
  *
  * The date and time format specified using the strftime() syntax.
  *
  * See http://www.php.net/strftime for details.
  * 
  */
 define('SIMPLEID_DATE_TIME_FORMAT', '%Y-%m-%d %H:%M:%S %Z');
 
 /**
  * The number of seconds before associations expire.  This is an advanced
  * option, for which the default setting should work fine.
  *
  * Note that for ICAM compliance, this number must be less than 86400.
  */
 define('SIMPLEID_ASSOC_EXPIRES_IN', 3600);
 
 /**
  * SimpleID extensions.
  *
  * The SimpleID extensions you wish to load.  You should separate the
  * extensions you wish to load with a comma.
  *
  */
 define('SIMPLEID_EXTENSIONS', 'sreg,ui');
 
 /**
  * Log file.
  *
  * You can specify a file into which SimpleID will log various diagnostic
  * messages.
  *
  * The log file's directory must exist and must be writable by the web server.
  *
  * To disable logging, set this as an empty string.
  *
  * @since 0.7
  *
  */
 define('SIMPLEID_LOGFILE', '');
 
 /**
  * The level of detail for log messages.
  *
  * You can determine which messages are captured in the log file by specifying
  * a number between 0 and 5. The higher the number, the more messages are
  * logged.
  *
  * WARNING: Setting the log level to 5 will result in security sensitive
  * information also being logged.
  *
  * This has effect only if logging is enabled.
  *
  * @since 0.7
  *
  */
 define('SIMPLEID_LOGLEVEL', 4);
 ?>


Setting up an Identity
======================

Setting up an identity involves the following three steps.

        1.Decide on your user name, password and identity URL. See the requirements for an identity for more details.
        2.Tell SimpleID about that identity by creating an identity file.
        3.Claim your identifier.

2. Create an identity file ``username.identity`` from the template

.. code-block:: console
 :emphasize-lines: 1

 [isabell@stardust ~]$ cp /var/www/virtual/$USER/identities/example.identity.dist /var/www/virtual/identities/username.identity
 [isabell@stardust ~]$ 

Generate the password hash for the config

.. warning:: Get a random salt and a good password!

.. code-block:: console
 :emphasize-lines: 1,2,3,4,5

 [isabell@stardust ~]$ php -r "print sha1('example password:fricking long salt');"
 [isabell@stardust ~]$ 

Now we can edit it

.. warning:: Replace ``example.com/`` with your identityurl!

.. warning:: Replace the passwordhash with teh one generated before!

.. code-block:: INI
 :emphasize-lines: 32,33,79
 
 ; :mode=ini:
 ; $Id$
 ;
 ;
 ; SimpleID identity file.
 ;
 ; This file contains all the data associated with an identity.  It should
 ; always be named username.identity, where username is the user name to be used
 ; when logging into SimpleID.
 ;
 ; In this file, if a value contains non-numeric characters, you will need to
 ; surround it with quotation characters.
 ;
 
 ;
 ; The OpenID Identifier associated with this identity.  This is typically a
 ; URL, although the OpenID specifications allow the use of URIs and even XRIs.
 ;
 ; Relying parties must be able to resolve the identity to obtain the address
 ; of this SimpleID installation.
 ;
 ; WARNING: If you change the OpenID Identifier after you have used it in
 ; SimpleID, you will need to delete all files named 'identity-*.cache' in the
 ; cache directory.
 ;
 ; Examples:
 ;    http://example.com/
 ;    http://example.com:8888/
 ;    http://example.com/myopenid
 ;    https://example.com:8080/myopenid
 ;
 identity="http://example.com/index.php?q=xrds/username
 identity="https://example.com/index.php?q=xrds/username
 ;
 ; The password associated with this identity.  
 ;
 ; The password is encoded as follows:
 ;
 ;     pass="hash:algorithm:other_params"
 ;
 ; There are three components to the password string.  Only the first component
 ; (the hash) is required, the other two are optional.
 ;
 ; 1. The hash of the password.  For backwards compatibility reasons, the
 ;    default algorithm for hashing the password is MD5.
 ;
 ;    However, you are strongly encouraged to use a much stronger password
 ;    hashing algorithm, such as PBKDF2 with a HMAC-SHA256 function and at least
 ;    100,000 iterations.
 ;
 ; 2. The algorithm used to hash the password.  If this is omitted, 'md5' is assumed.
 ;
 ;    Allowed algorithms are:
 ;
 ;    - md5
 ;    - sha1
 ;    - if the hash module is enabled, pbkdf2 and any algorithms available from that
 ;      module
 ;
 ; 3. Other parameters.
 ;
 ;    For md5 and sha1, this is an optional salt used to hash the password.  If
 ;    used, the password is appended by a colon character (:) then the salt before
 ;    a hash is calculated, that is:
 ;
 ;    hash(password:salt)
 ;
 ;    For pbkdf2, it is the underlying pseudorandom function, the number of
 ;    iterations and the salt, separated by colons.
 ;
 ; Examples (these contain the same password):
 ;    1a79a4d60de6718e8e5b326e338ae533                   ; MD5 hash and no salt
 ;    c3499c2729730a7f807efb8676a92dcb6f8a3f8f:sha1      ; SHA1 hash and no salt
 ;    f5e6ea5714945786623ad3932ccc757d::ideally-a-large-number-of-random-characters-to-use-as-salt                   ; MD5 hash with salt
 ;    9bce4e6997c6f2590717686bd62f99e33d5c6e1c:sha1:ideally-a-large-number-of-random-characters-to-use-as-salt       ; SHA1 hash with salt
 ;    c6e1aa5914c6e4e55fae69093afbc02e180810dcc7d3da9f863aa54f3d76e2c3:pbkdf2:sha256:100000:ideally-a-large-number-of-random-characters-to-use-as-salt ; PBKDF2
 ;
 pass="a66a211c97aaba48027355c8c22d8f63019db458:sha1:fricking long salt"
 ;
 ; Whether this user is given administrative privileges in SimpleID.
 ;
 ; This setting has no effect in the current version of SimpleID.  However,
 ; more functionality may be added to SimpleID in future versions which will
 ; be restricted to SimpleID administrators.
 ;
 ; You should grant administrative privileges to at least one user.
 ;
 ; If you wish this user to be given administrative privileges, uncomment the
 ; line below.
 ;
 ;administrator=1
 
 ;
 ; Advanced users only: SSL client certificates associated with this identity.
 ;
 ; You can associate SSL client certificates to this identity, so that you can
 ; log in using certificates instead of supplying a user name or password.
 ;
 ; The SSL certicate is identified using two parameters:
 ;
 ; - the certificate's serial number
 ; - the distinguished name of the certificate's issuer
 ;
 ; You can find out these two values using OpenSSL by running the following
 ; commands (replacing the file name of the certificate as required):
 ; 
 ;    openssl x509 -noout -serial -in certificate.crt
 ;    openssl x509 -noout -issuer -in certificate.crt
 ;
 ; These two values are then joined together using a semicolon.
 ;
 ; This option is for advanced users only.  Please see the documentation at
 ; http://simpleid.koinic.net/documentation/advanced-topics/logging-using-client-ssl-certificates
 ; for details on how to set this up.
 ;
 ; Note, you must also enable the certauth extension in SimpleID.  To
 ; do this, make sure the SIMPLEID_EXTENSIONS option in config.php contains
 ; certauth
 
 ; Example:
 ;
 ;[certauth]
 ;cert[]="02A97C;/C=XX/O=Example CA/OU=Example CA Certificate Signing/CN=Example Client CA"
 
 
 ;
 ; OpenID Connect user information.
 ;
 ; If you want to provide personal data to OpenID Connect clients, uncomment the
 ; section below and fill in your details.
 ;
 ; Note that you will need to supply your data in this section again even if you
 ; have uncommented and filled in the Simple Registration Extension and/or
 ; Attribute Exchange Extension information in the sections below.  SimpleID
 ; does not pick these up automatically.
 ;
 ; WARNING: The address fields below are only supported by PHP 5.3 or later.
 ; Earlier versions of PHP are not able to read identity files with
 ; associative arrays
 ;
 ;[user_info]
 ;name="Example"
 ;given_name="Example"
 ;family_name="Example"
 ;middle_name="Example"
 ;nickname="Example"
 ;profile="http://example.com/profile/example"
 ;picture="http://example.com/profile/example.jpg"
 ;website="http://example.com/blog/example"
 ;email="example@example.com"
 ;gender="male"
 ;birthday="12/31/2000"
 ;zoneinfo="Australia/Sydney"
 ;locale="en-AU"
 ;phone_number="+61400000000"
 ;address["formatted"]="1 George Street, Sydney NSW 2000, Australia"
 ;address["street_address"]="1 George Street"
 ;address["locality"]="Sydney"
 ;address["region"]="NSW"
 ;address["postal_code"]="2000"
 ;address["country"]="Australia"
 
 
 ;
 ; Simple Registration Extension data.
 ;
 ; If you want to provide registration data to relying parties which support the
 ; Simple Registration Extension, uncomment the section below and fill
 ; in your details.
 ;
 ; Further information on the Simple Registration Extension can be found at
 ; http://simpleid.koinic.net/documentation/using-simpleid/extensions/simple-registration-extension
 ;
 ; Note, you must also enable the Simple Registration Extension in SimpleID.  To
 ; do this, make sure the SIMPLEID_EXTENSIONS option in config.php contains
 ; sreg
 ;
 ;[sreg]
 ;nickname="Example"
 ;email="example@example.com"
 ;fullname="Example"
 ;dob="2000-00-00"
 ;gender="M"
 ;postcode="1234"
 ;country="en"
 ;language="au"
 ;timezone="Australia/Sydney"
 
 
 ;
 ; Attribute Exchange Extension data.
 ;
 ; If you want to provide personal identity information data to relying parties
 ; which support the Attribute Exchange Extension, uncomment the section below
 ; and fill in your details.
 ;
 ; The format of this section is attribute type URI=attribute value.  Examples
 ; are given below.
 ;
 ; For a full list of attributes, see http://openid.net/specs/openid-attribute-properties-list-1_0-01.html
 ;
 ; Note if you have already uncommented and filled out the OpenID Connect user
 ; information and/or Simple Registration Extension data above, you do not need
 ; to fill out the corresponding attributes again in the section below.  SimpleID
 ; will pick these up automatically, including:
 ;
 ;    http://axschema.org/namePerson/friendly
 ;    http://axschema.org/contact/email
 ;    http://axschema.org/namePerson
 ;    http://axschema.org/birthDate
 ;    http://axschema.org/person/gender
 ;    http://axschema.org/contact/postalCode/home
 ;    http://axschema.org/contact/country/home
 ;    http://axschema.org/pref/language
 ;    http://axschema.org/pref/timezone
 ;    http://openid.net/schema/namePerson/friendly
 ;    http://openid.net/schema/contact/internet/email
 ;    http://openid.net/schema/gender
 ;    http://openid.net/schema/contact/postalCode/home
 ;    http://openid.net/schema/contact/country/home
 ;    http://openid.net/schema/language/pref
 ;    http://openid.net/schema/timezone
 ;
 ; Note, you must also enable the Attribute Exchange Extension in SimpleID.  To
 ; do this, make sure the SIMPLEID_EXTENSIONS option in config.php contains
 ; ax
 ;
 ;[ax]
 ;http://openid.net/schema/company/name="Example Company Limited"
 ;http://openid.net/schema/company/title="Managing Director"
 ;http://openid.net/schema/contact/web/blog="http://simpleid.koinic.net/"



Upgrades
=======

For Upgrades see the specific `upgrading page <http://simpleid.koinic.net/docs/1/upgrading/>`_ .

.. note:: Check the `News <http://simpleid.koinic.net/news/>`_ regularly to stay informed about new updates and releases.


.. _PHP: https://manual.uberspace.de/en/lang-php.html
.. _credentials: https://manual.uberspace.de/en/database-mysql.html#login-credentials
.. _domains: https://manual.uberspace.de/en/web-domains.html
.. _document root: https://manual.uberspace.de/en/web-documentroot.html
.. _simpleid: http://simpleid.koinic.net/

----

Tested with Nextcloud 13.0.1, Uberspace 7.1.3
