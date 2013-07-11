SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

DROP TABLE IF EXISTS `oauth2_clients`;
CREATE TABLE `oauth2_clients` (
  `client_id` varchar(20) NOT NULL,
  `client_secret` varchar(20) NOT NULL,
  `redirect_uri` varchar(200) NOT NULL,
  `app_owner_user_id` int(10) unsigned NOT NULL,
  `app_title` varchar(255) NOT NULL DEFAULT '',
  `app_desc` text,
  `status`  int(1) unsigned NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO oauth2_clients (client_id, client_secret, redirect_uri, app_owner_user_id, app_title, status) VALUES
('1234567890', '1234567890', 'http://localhost/oauth_callback', 1, '酷动网客户端', 1);

DROP TABLE IF EXISTS `oauth2_tokens`;
CREATE TABLE `oauth2_tokens` (
  `oauth_token` varchar(40) NOT NULL,
  `token_type` enum('code', 'access', 'refresh') default 'code',
  `client_id` varchar(20) NOT NULL,
  `user_id` int(11) unsigned NOT NULL,
  `expires` int(11) NOT NULL,
  `redirect_uri` varchar(200) NOT NULL default 'oob',
  `scope` varchar(200) DEFAULT NULL,
  `created_at` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (`oauth_token`),
  KEY (`user_id`),
  KEY (`refresh_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
