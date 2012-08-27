<?php
require_once dirname(__FILE__). DIRECTORY_SEPARATOR . 'lib/OAuth2.inc';

/**
 * OAuth2 Library PDO DB Implementation.
 */
class YiiOAuth2 extends OAuth2 {
  
  const TOKEN_TYPE_CODE = 'code';
  const TOKEN_TYPE_ACCESS_TOKEN = 'access';
  const TOKEN_TYPE_REFRESH_TOKEN = 'refresh';
  
  static private $instance = false;

  private $db;
  
  public static function init($options = array(), $forceNewInstance = false)
  {
	  if (!YiiOAuth2::$instance or $forceNewInstance)
	  {
	      YiiOAuth2::$instance = new YiiOAuth2($options['dsn'], $options['username'], $options['password']);
	  }
  }
  
  public static function instance() {
      return YiiOAuth2::$instance;
  }
  
  public static function authorize()
  {
      return YiiOAuth2::$instance->finishClientAuthorization(TRUE, $_POST);
  }
  
  public static function accessToken()
  {
      return YiiOAuth2::$instance->grantAccessToken();
  }
  
  public static function verify()
  {
      if(YiiOAuth2::$instance->verifyAccessToken())
          return YiiOAuth2::$instance->getVariable('user_id');
      return FALSE;
  }
  
  /**
   * Overrides OAuth2::__construct().
   */
  public function __construct($dsn, $user, $pass) {
    parent::__construct();

    try {
      $this->db = new PDO($dsn, $user, $pass);
    } catch (PDOException $e) {
      die('Connection failed: ' . $e->getMessage());
    }
  }

  /**
   * Release DB connection during destruct.
   */
  function __destruct() {
    $this->db = NULL; // Release db connection
  }

  /**
   * Handle PDO exceptional cases.
   */
  private function handleException($e) {
    echo "Database error: " . $e->getMessage();
    exit;
  }

  /**
   * Little helper function to add a new client to the database.
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   *
   * @param $client_id
   *   Client identifier to be stored.
   * @param $client_secret
   *   Client secret to be stored.
   * @param $redirect_uri
   *   Redirect URI to be stored.
   */
  public function addClient($client_id, $client_secret, $redirect_uri) {
    try{
      $sql = "INSERT INTO oauth2_clients (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)";
      $connection=Yii::app()->db; 
      $stmt=$connection->createCommand($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":client_secret", $client_secret, PDO::PARAM_STR);
      $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
      $stmt->execute();
    } catch (Exception $e) {
      $this->handleException($e);
    }
  }
  
  
  public function getClients($client_id)
  {
    try{
      $sql = "SELECT * FROM oauth2_clients WHERE client_id = :client_id";
      $connection=Yii::app()->db; 
      $stmt=$connection->createCommand($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);

      return $stmt->queryRow();
    } catch (Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::checkClientCredentials().
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   */
  protected function checkClientCredentials($client_id, $client_secret = NULL) {
    try {
      $sql = "SELECT client_secret FROM oauth2_clients WHERE client_id = :client_id";
      $connection=Yii::app()->db; 
      $stmt=$connection->createCommand($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);

      $result = $stmt->queryRow();

      if ($client_secret === NULL)
          return $result !== FALSE;

      return $result["client_secret"] == $client_secret;
    } catch (Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getRedirectUri().
   */
  protected function getRedirectUri($client_id) {
    try {
      $sql = "SELECT redirect_uri FROM oauth2_clients WHERE client_id = :client_id";
      $connection=Yii::app()->db; 
      $stmt=$connection->createCommand($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);

      $result = $stmt->queryRow();

      if ($result === FALSE)
          return FALSE;

      return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : NULL;
    } catch (Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getAccessToken().
   */
  protected function getAccessToken($oauth_token) {
        return $this->getToken($oauth_token, YiiOAuth2::TOKEN_TYPE_ACCESS_TOKEN);
  }

  /**
   * Implements OAuth2::setAccessToken().
   */
  protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL) {
      $this->setToken($oauth_token, YiiOAuth2::TOKEN_TYPE_ACCESS_TOKEN , $client_id, $expires, '' , $scope);
  }


  /**
   * Overrides OAuth2::getSupportedGrantTypes().
   */
  protected function getSupportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
    );
  }

  /**
   * Overrides OAuth2::getAuthCode().
   */
  protected function getAuthCode($code) {
    return $this->getToken($code, YiiOAuth2::TOKEN_TYPE_CODE);
  }

  /**
   * Overrides OAuth2::setAuthCode().
   */
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    $this->setToken($code, YiiOAuth2::TOKEN_TYPE_CODE, $client_id, $expires,  $redirect_uri,  $scope );
  }
  
  protected function checkUserCredentials($client_id, $username, $password) {
      $model=new LoginForm;
      $arr = array(
                'username'=>$username,
                'password'=>$password,
      );

      $model->attributes=$arr;
      if($model->validate() && UserIdentity::ERROR_NONE===$model->login())
      {
          $user_id = Yii::app()->user->id;
          $this->setVariable("user_id", $user_id);
          return TRUE;
	  }
      return FALSE;
  }
  
  
  private function getToken($oauth_token, $token_type = YiiOAuth2::TOKEN_TYPE_ACCESS_TOKEN)
  {
     try {
      $sql = "SELECT * FROM oauth2_tokens WHERE oauth_token = :oauth_token AND token_type=:token_type";
      
      $connection=Yii::app()->db; 
      $stmt=$connection->createCommand($sql);
      
      $stmt->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
      $stmt->bindParam(":token_type", $token_type, PDO::PARAM_STR);
      
      $result = $stmt->queryRow();

      return $result !== FALSE ? $result : NULL;
     } catch (PDOException $e) {
         $this->handleException($e);
     }
  }


  private function setToken($oauth_token, $token_type ,$client_id, $expires, $redirect_url = 'oob',  $scope = '')
  {
      $user_id = $this->getVariable('user_id', 0);
      try{
          $connection=Yii::app()->db;   // assuming you have configured a "db" connection
          $sql = "INSERT INTO oauth2_tokens (oauth_token, token_type, client_id, expires, user_id, redirect_uri ,scope) VALUES (:oauth_token, :token_type ,:client_id, :expires, :user_id, :redirect_uri, :scope)";
          $command=$connection->createCommand($sql);
          //replace the placeholder ":username" with the actual username value
    
          $command->bindParam(":oauth_token", $oauth_token, PDO::PARAM_STR);
          $command->bindParam(":token_type", $token_type, PDO::PARAM_STR);
          $command->bindParam(":client_id", $client_id, PDO::PARAM_STR);
          $command->bindParam(":expires", $expires, PDO::PARAM_INT);
          $command->bindParam(":user_id", $user_id, PDO::PARAM_INT);
          $command->bindParam(":redirect_uri", $redirect_url, PDO::PARAM_STR);
          $command->bindParam(":scope", $scope, PDO::PARAM_STR);
          
          $command->execute();
      }catch(Exception $e){
          $this->handleException($e);
      }
  }
  
}
