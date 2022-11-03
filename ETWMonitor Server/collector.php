<?php
	if(isset($_POST['hostname'])  && isset($_POST['message']) && isset($_POST['level']) && isset($_POST['token'])){
		try{
		    $db = new PDO('sqlite:./ETWMonitor.sqlite');
		    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
		    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		    try{
			    $stmt = $db->prepare('SELECT token FROM settings');
			    $stmt->execute(); 
			    $req = $stmt->fetch();
			    $server_token = $req['token'];
		    } catch(Exception $e) {
			    echo "Can't retrieve token from server : ".$e->getMessage();
			    die();
				exit();
			}


			$token = preg_replace("/[^a-zA-Z0-9]+/", '', base64_decode($_POST['token']));

			if ($token != $server_token){
				echo "Invalid token";
			    die();
				exit();
			}

			$hostname = preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',base64_decode($_POST['hostname']));
			$message = preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '', base64_decode($_POST['message']));
			$level = preg_replace("/[^0-9]+/", '', base64_decode($_POST['level']));

			$req = $db->prepare('INSERT INTO events (hostname, timedate, event, level) VALUES (?, ?, ?, ?)');
		    $array_of_values = array($hostname, date('Y-m-d H:i:s'), $message, $level);
			$req->execute($array_of_values);
		} catch(Exception $e) {
		    echo "Can't connect to database : ".$e->getMessage();
		    die();
			exit();
		}
	}else{
		echo "No data input";
		exit();
	}
?>