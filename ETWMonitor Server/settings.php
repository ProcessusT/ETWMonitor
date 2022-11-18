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
            $req = $db->prepare('INSERT INTO settings (token) VALUES (?)');
            $array_of_values = array($new_token);
            $req->execute($array_of_values);
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
            </script>
        </script>';
        
?>
                                </table>
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
