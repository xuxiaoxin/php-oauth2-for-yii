Very simple php oauth2 server extension for Yii

## Usage ##

### Authorize ###
```

$oauth = YiiOAuth2::instance();
$auth_params = $oauth->getAuthorizeParams();

$app = $oauth->getClients($auth_params['client_id']);

if($_POST){

   //add your verify username and password code here;
   
   //$user_id = User::model()->getIdByUsername($_POST['username']);
   
   $oauth->setVariable("user_id", $user_id);
   $oauth->finishClientAuthorization(TRUE, $_POST);
}
```


### Request Access token ###
```
$oauth = YiiOAuth2::instance();
echo $oauth->grantAccessToken();
```


### Protect Resource ###
```
$oauth = YiiOAuth2::instance();
$user_id = $oauth->verify();
```


## Usage in Yii ##

### add a module ###

```

<?php
class ApiModule extends CWebModule
{

    private $_version = "1.0beta";
    //oauth 机制中当前验证通过的 uid，如果你想取得当前用户的id 使用ApiModule::getUid();
    static private $_uid;
    static private $_oauth;
    private $_debug = false;
	
	public function init()
	{
        Yii::app()->homeUrl = array('/api');
        $api_url = Yii::app()->createAbsoluteUrl('/api');
        
		// import the module-level models and components
		$this->setImport(array(
			'api.models.*',
			'api.components.*',
		));
	}
    
    public function oauth2_init()
    {
        Yii::import('application.modules.api.extensions.oauth2.YiiOAuth2');
        YiiOAuth2::instance();
    }

	public function beforeControllerAction($controller, $action)
	{
		if(parent::beforeControllerAction($controller, $action))
		{
			$array = array("default");
			if(!in_array($controller->id,$array))
			{
                          $this->oauth2_init();
				if($controller->id != 'oAuth2'){
    				$this->authorization();
				}
			}
			return true;
		}
		else
			return false;
	}

	public function authorization()
	{
       $token = YiiOAuth2::instance()->verifyToken();
       // If we have an user_id, then login as that user (for this request)
       if($token && isset($token['user_id']))
       {
          self::setUid($token['user_id']);
          self::$_oauth = true;
       }
	   else
	   {
	        $msg = "Can't verify request, missing oauth_consumer_key or oauth_token";
	        throw new CHttpException(401,$msg);
	        exit();
       }
	}
	
    public static function setUid($uid)
    {
        if(empty($uid))
        {
            $msg =  "authorization failed, missing login user id.";
			throw new CHttpException(401,$msg);
            exit();
        }
        //登录为yii user
        self::$_uid = $uid;
    }

    public static function getUid()
    {
       //return "test";
        
        if(empty(self::$_uid))
        {
            $msg =  "Not found";
			throw new CHttpException(403,$msg);
            exit();
        }
        
        return self::$_uid;
    }
}
```

### add the controller ###

```
class OAuth2Controller extends Controller
{
	public function actionAccess_token()
	{
	    $oauth = YiiOAuth2::instance();
	    echo $oauth->grantAccessToken();
	}

	public function actionAuthorize()
	{
	    $oauth = YiiOAuth2::instance();
	    $model = new LoginForm();
	    $auth_params = $oauth->getAuthorizeParams();
	    $app = $oauth->getClients($auth_params['client_id']);
	    
	    if (isset($_POST) && isset($_POST['LoginForm']))
	    {
	        $model->attributes = $_POST['LoginForm'];
    	        if($model->validate() && UserIdentity::ERROR_NONE===$model->login())
                {
                    $user_id = Yii::app()->user->id;
                    $oauth->setVariable("user_id", $user_id);
                    $oauth->finishClientAuthorization(TRUE, $_POST);
                }
             }
             // render the authorize page
	     $this->render('Authorize', array('model'=>$model, 'app'=>$app, 'auth_params'=>$auth_params));
       }
}

```
