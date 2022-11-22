<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>Dashboard - SB Admin</title>
        <link href="https://cdn.jsdelivr.net/npm/simple-datatables@latest/dist/style.css" rel="stylesheet" />
        <link href="css/styles.css" rel="stylesheet" />
        <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>
    </head>
    <body class="sb-nav-fixed">
        <nav class="sb-topnav navbar navbar-expand navbar-dark bg-dark">
            <!-- Navbar Brand-->
            <a class="navbar-brand ps-3" href="index.php">ETWMonitor</a>
            <!-- Sidebar Toggle-->
            <button class="btn btn-link btn-sm order-1 order-lg-0 me-4 me-lg-0" id="sidebarToggle" href="#!"><i class="fas fa-bars"></i></button>
        </nav>
        <div id="layoutSidenav">
            <div id="layoutSidenav_nav">
                <?php
                    include('nav.php');
                ?>
            </div>
            <div id="layoutSidenav_content">
                <main>

                    <div class="container-fluid px-4">
                        <h1 class="mt-4">Settings</h1>
                        
                        <?php
                            if(isset($_GET['error'])){
                                echo '<div style="color:red;font-weight:bold;font-size:25px;">Une erreur s\'est produite.</div><br />';
                            }
                        ?>




                        <!-- Token settings -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-table me-1"></i>
                                Token
                            </div>
                            <div class="card-body">
                                
<?php

    if(isset($_GET['generate_token'])){
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $new_token = '';
        for ($i = 0; $i < 50; $i++) {
            $new_token .= $characters[rand(0, $charactersLength - 1)];
        }

        try{
            $db = new PDO('sqlite:./ETWMonitor.sqlite');
            $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $req = $db->prepare('UPDATE settings SET token=:new_token');
            $req->bindParam(':new_token',$new_token);
            $req->execute();


        }catch (Exception $e) {
            echo '<script>
                  document.location.href="settings.php?error=1"; 
                </script>';
        }
        
    }

    $db = new PDO('sqlite:./ETWMonitor.sqlite');
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $db->prepare('SELECT token FROM settings');
    $stmt->execute(); 
    $req = $stmt->fetch();
    $token = "<NOT_CONFIGURED>";
    if( isset($req['token']) ) {
        $token = $req['token'];
    }
        echo '<br /><br />Token value : 
        <input style="width:500px;border-radius:5px;padding:10px;" type="text" value="'.$token.'" id="token"> 
        <button style="border-radius:5px;padding:10px;" onclick="copyToken()">Copy</button><br /><br />
        <br />
        <button style="color:white;padding:10px;background-color:red;border-radius:5px;" onclick="generate_token()">Regenerate token</button>
        <script>
            function copyToken(){
                var copyText = document.getElementById("token");
                copyText.select();
                copyText.setSelectionRange(0, 99999);
                navigator.clipboard.writeText(copyText.value);
            }
            function generate_token(){
                document.location.href="settings.php?generate_token"; 
            }
        </script>';
        
?>
                                </table>
                            </div>
                        </div>








                        <!-- Crowdsec integration -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-table me-1"></i>
                                Crowdsec integration
                            </div>
                            <div class="card-body">

                                <?php

    if(isset($_POST['activation'])){
        
        try{
            $active=0;
            if($_POST['activation']=="on"){
                $active=1;
            }
            $req = $db->prepare('UPDATE crowdsec SET active=:active');
            $req->bindParam(':active',$active);
            $req->execute();
        }catch (Exception $e) {
            echo '<script>
                  document.location.href="settings.php?error=crowdsec"; 
                </script>';
        }
        
    }

    $db = new PDO('sqlite:./ETWMonitor.sqlite');
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $db->prepare('SELECT active FROM crowdsec');
    $stmt->execute(); 
    $req = $stmt->fetch();
        echo '<form method="POST" action="#"><br />
           <label for="activation" style="margin-right:25px;">Include Crowdsec database in rules : </label>
           <input type="checkbox" name="activation" id="activation" ';
           if($req['active']==1){
                echo "checked ";
           }
        echo '><br />
        
        <br />
        <input type="submit" style="border-radius:5px;padding:10px;background:green;color:white;cursor:pointer;" value="Save changes">
        <br /><br />
        <span style="font-style:italic;">To include Crowdsec IP reputation in rules you need to copy regularly your sqlite crowdsec.db file (located by default in /var/lib/crowdsec/data/) in ETW Monitor server main folder (For example with a cron job).</span>
        </form>'; 
        
        
?>
                            </div>
                        </div>







                        <!-- SMTP settings -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-table me-1"></i>
                                SMTP settings
                            </div>
                            <div class="card-body">
<br />
<?php

    if(isset($_POST['smtp_host'])){
        try{

            $stmt_count = $db->prepare('SELECT count(smtp_host) as counter FROM smtp');
            $stmt_count->execute(); 
            $req_count = $stmt_count->fetch();
            if($req_count['counter'] == "0"){
                $stmt_insert = $db->prepare('insert into smtp (smtp_host) VALUES (?)');
                $array_of_values = array('smtp host');
                $stmt_insert->execute($array_of_values);
            }

            if($_POST['smtp_host']=="on"){
                $smtp_auth = "true";
            }else{
                $smtp_auth = "false";
            }
            $smtp_host = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_host']));
            
            if(is_int((int)$_POST['smtp_port'])){
                $smtp_port = (int)$_POST['smtp_port'];
            }else{
                throw new Exception('SMTP port is not numeric.');
            }

            $smtp_secure = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_secure']));
            $smtp_username = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_username']));
            $smtp_password = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_password']));
            $smtp_fromEmail = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_fromEmail']));
            $smtp_toEmail = strip_tags(preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['smtp_toEmail']));
            
            
            $req_update = $db->prepare('UPDATE smtp SET smtp_host=:smtp_host, smtp_port=:smtp_port, smtp_auth=:smtp_auth, smtp_secure=:smtp_secure, smtp_username=:smtp_username, smtp_password=:smtp_password, smtp_fromEmail=:smtp_fromEmail, smtp_toEmail=:smtp_toEmail WHERE "rowid" = 1');
            $req_update->bindParam(':smtp_host',$smtp_host);
            $req_update->bindParam(':smtp_port',$smtp_port);
            $req_update->bindParam(':smtp_auth',$smtp_auth);
            $req_update->bindParam(':smtp_secure',$smtp_secure);
            $req_update->bindParam(':smtp_username',$smtp_username);
            $req_update->bindParam(':smtp_password',$smtp_password);
            $req_update->bindParam(':smtp_fromEmail',$smtp_fromEmail);
            $req_update->bindParam(':smtp_toEmail',$smtp_toEmail);
            $req_update->execute();

        } catch (Exception $e) {
            echo '<div style="color:red;font-weight:bold;font-size:25px;">Error while updating SMTP settings : '.$e->getMessage().'</div>';
        }
    }

    $stmt_select = $db->prepare('SELECT * FROM smtp WHERE "rowid" = 1');
    $stmt_select->execute(); 
    $req_select = $stmt_select->fetch();

echo '
<form method="POST" action="#" id="smtp_settings">
    <label for="smtp_host">SMTP server host : </label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="text" value="'.$req_select['smtp_host'].'" id="smtp_host" name="smtp_host"> 
    <br /><br />

    <label for="smtp_port">SMTP server port : </label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="number" value="'.$req_select['smtp_port'].'" id="smtp_port" name="smtp_port"> 
    <br /><br />

    <label for="smtp_auth">Authentication required : </label> <input style="width:400px;border-radius:5px;padding:10px;" type="checkbox" ';
    if($req_select['smtp_auth']){
        echo 'checked';
    }
    echo ' id="smtp_auth" name="smtp_auth"> 
    <br /><br />

    <label for="smtp_secure">Encryption type : (tls/ssl/none)</label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="text" value="'.$req_select['smtp_secure'].'" id="smtp_secure" name="smtp_secure"> 
    <br /><br />

    <label for="smtp_username">SMTP username : </label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="text" value="'.$req_select['smtp_username'].'" id="smtp_username" name="smtp_username"> 
    <br /><br />

    <label for="smtp_password">SMTP password : 
    </label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="password" value="'.$req_select['smtp_password'].'" id="smtp_password" name="smtp_password"> 
    <br />
    To generate a gmail application password, go here : <a href="https://myaccount.google.com/u/0/apppasswords">https://myaccount.google.com/u/0/apppasswords</a>
    <br /><br />

    <label for="smtp_fromEmail">Sender name : </label> <br /><input style="width:400px;border-radius:5px;padding:10px;" type="text" value="'.$req_select['smtp_fromEmail'].'" id="smtp_fromEmail" name="smtp_fromEmail"> 
    <br /><br />

    <label for="smtp_toEmail">Recipient email : </label><br /> <input style="width:400px;border-radius:5px;padding:10px;" type="text" value="'.$req_select['smtp_toEmail'].'" id="smtp_toEmail" name="smtp_toEmail"> 
    <br /><br />

    <input style="border-radius:5px;padding:10px;background:green;color:white;cursor:pointer;" type="submit" value="Save changes"> 
    <br /><br />
    </form>

    <script type="text/javascript">
        function test_smtp(){
            document.getElementById("result").style.setProperty("visibility", "visible");
            document.getElementById("result").style.setProperty("display", "block");
            const xhttp = new XMLHttpRequest();
            xhttp.open("GET", "test_alert.php", false);
            xhttp.send();
            document.getElementById("result").innerHTML = xhttp.responseText;
        }  
    </script>
    <button style="color:white;padding:10px;background-color:rgb(0,0,180);border-radius:5px;" onclick="test_smtp()" id="test_smtp">Test SMTP connection</button>
    <br /><br />
    <div id="result" style="visibility:hidden;display:none;"><img width="200px" src="assets/img/loading.gif"></div>
';
?>

                           </div>
                        </div>
                    </div> 
                </main>
                <footer class="py-4 bg-light mt-auto">
                    <div class="container-fluid px-4">
                        <div class="d-flex align-items-center justify-content-between small">
                            <div class="text-muted">Copyright &copy; Processus Thief 2022</div>
                        </div>
                    </div>
                </footer>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
        <script src="js/scripts.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js" crossorigin="anonymous"></script>
        <script src="https://cdn.jsdelivr.net/npm/simple-datatables@latest" crossorigin="anonymous"></script>
        <script src="js/datatables-simple-demo.js"></script>
    </body>
</html>
