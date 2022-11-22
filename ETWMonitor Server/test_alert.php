<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
 
include "PHPMailer/PHPMailer.php";
include "PHPMailer/SMTP.php";
include "PHPMailer/Exception.php";

try {
    $db = new PDO('sqlite:./ETWMonitor.sqlite');
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $db->prepare('SELECT * from smtp');
    $stmt->execute(); 
    $req = $stmt->fetch();

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
    $mail->Subject = 'ETW Monitor test message';
    $mail->msgHTML("This is a test from ETW Monitor !");
    $mail->AltBody = 'HTML messaging not supported';

    if(!$mail->send()){
        echo "Mailer Error: " . $mail->ErrorInfo;
    }else{
        echo "Message successfully sent !";
    }
} catch (Exception $e) {
    echo "Mailer Error: " . $e->getMessage();
}
?>