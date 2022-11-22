<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

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


			$token = strip_tags( preg_replace("/[^a-zA-Z0-9]+/", '', base64_decode($_POST['token'])));

			if ($token != $server_token){
				echo "Invalid token";
			    die();
				exit();
			}

			$hostname = strip_tags( preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',base64_decode($_POST['hostname'])));
			$message = strip_tags( preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '', base64_decode($_POST['message'])));
			$level = strip_tags( preg_replace("/[^0-9]+/", '', base64_decode($_POST['level'])));

			$req = $db->prepare('INSERT INTO events (hostname, timedate, event, level) VALUES (?, ?, ?, ?)');
		    $array_of_values = array($hostname, date('Y-m-d H:i:s'), $message, $level);
			$req->execute($array_of_values);


			if($level>4){
				try{
						$db = new PDO('sqlite:./ETWMonitor.sqlite');
						$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
						$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
						$stmt = $db->prepare('SELECT * from smtp');
						$stmt->execute(); 
						$req = $stmt->fetch();

						include "PHPMailer/PHPMailer.php";
						include "PHPMailer/SMTP.php";
						include "PHPMailer/Exception.php";

						// to generate a gmail password, go here : https://myaccount.google.com/u/0/apppasswords
						$mail = new PHPMailer;
						$mail->isSMTP(); 
						$mail->SMTPDebug = 2;
						$mail->Host = $req['smtp_host'];
						$mail->Port = $req['smtp_port'];
						$mail->SMTPSecure = $req['smtp_secure'];
						$mail->SMTPAuth = $req['smtp_auth'];
						$mail->Username = $req['smtp_username'];
						$mail->Password = $req['smtp_password'];
						$mail->setFrom($req['smtp_fromEmail'], $req['smtp_fromEmail']);
						$mail->addAddress($req['smtp_toEmail'], $req['smtp_toEmail']);
						$mail->Subject = "ETW Monitor - Alert from ".$hostname ;
						$mail->msgHTML("<meta charset='utf-8'>New alert from host : ".$hostname."<br />".$message);
						$mail->AltBody = "New alert from host : ".$hostname." \n".$message;

						if(!$mail->send()){
						    echo "Mailer Error: " . $mail->ErrorInfo;
						}
				}catch(Exception $e) {
    				echo "Error while sending : ".$e->getMessage();
    			}			
			}



			// crowsec integration
			try{
				$db = new PDO('sqlite:./ETWMonitor.sqlite');
				$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
				$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			    $stmt = $db->prepare('SELECT active, last_update FROM crowdsec');
			    $stmt->execute(); 
			    $req = $stmt->fetch();
			    $crowdsec_activation = $req['active'];
			    $crowdsec_last_update = $req['last_update'];
			    if($crowdsec_activation==1){
			    	$current_date = date("Y-m-d");
			    	if($crowdsec_last_update != $current_date){
			    		// update current rules file with crowdsec db file
			    		$rules_file = fopen("rules.xml", "r") or die("Unable to open file!");
			    		$rules_content = fread($rules_file,filesize("rules.xml"));
			    		fclose($rules_file);

			    		// TCPIP UUID is {2f07e2ee-15db-40f1-90ef-9d7ba282188a}
			    		// if guid is not present, just add it
			    		if( stripos($rules_beginning, "{2f07e2ee-15db-40f1-90ef-9d7ba282188a}")==0){
			    			$rules_beginning_first_index = stripos($rules_beginning, "</guid>");
			    			$new_rules_beginning = substr($rules_beginning, 0, $rules_beginning_first_index) . "</guid>
			    			<guid>{2f07e2ee-15db-40f1-90ef-9d7ba282188a}" . substr($rules_beginning, $rules_beginning_first_index);
			    			$rules_beginning = $new_rules_beginning;
			    		}
			    		$rules_beginning = explode("</detections>", $rules_content)[0]."</detections>
			    		<crowdsec>";
			    		
			    		$rules_end = "";
			    		if(file_exists("crowdsec.db")){
			    			$crowdsec_db = new PDO('sqlite:./crowdsec.db');
			    			$crowdsec_db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
							$crowdsec_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
							$stmt_crowdsec = $crowdsec_db->prepare('SELECT distinct value as ipaddress FROM decisions');
						    $stmt_crowdsec->execute(); 
						    $i=0;
						    while( $req_crowdsec = $stmt_crowdsec->fetch() ){
						    	$rules_end .= '
<crowdsec-'.$i.'>
'.$req_crowdsec['ipaddress'].'
</crowdsec-'.$i.'>
													';
								$i++;
						    }

						    $new_rules = $rules_beginning . $rules_end . "</crowdsec></root>";
						    $rules_file = fopen("rules.xml", "w+") or die("Unable to open file!");
				    		fwrite($rules_file, $new_rules);
				    		fclose($rules_file);

				    		$req = $db->prepare('UPDATE crowdsec SET last_update=:last_update');
				            $req->bindParam(':last_update',$current_date);
				            $req->execute();	    			
			    		}
			    	}
			    }
		    } catch(Exception $e) {
			    pass;			
			}
			



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