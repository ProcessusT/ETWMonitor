<?php
	if(isset($_POST['hostname']) && isset($_POST['message'])){
		try{
		    $db = new PDO('sqlite:./ETWMonitor.sqlite');
		    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
		    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		    $req = $db->prepare('INSERT INTO events (hostname, timedate, event) VALUES (?, ?, ?)');

			$hostname = preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',base64_decode($_POST['hostname']));
			$message = preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '', base64_decode($_POST['message']));

		    $array_of_values = array($hostname, date('Y-m-d H:i:s'), $message);
			$req->execute($array_of_values);
		} catch(Exception $e) {
		    echo "Impossible d'accéder à la base de données SQLite : ".$e->getMessage();
		    die();
			exit();
		}
	}else{
		echo "No data input";
		exit();
	}
?>