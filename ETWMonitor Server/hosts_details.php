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
                                Hosts details
                            </div>
                            <div class="card-body">
                                
<?php
    $db = new PDO('sqlite:./ETWMonitor.sqlite');
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


    if(isset($_POST['hostname'])){
        try{
            $hostname = strip_tags( preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',base64_decode($_POST['hostname'])));
            $details = strip_tags( preg_replace("/[^a-zA-Z0-9éèà!:,.; ][\n\r]+/", '',$_POST['details']));
            $stmt = $db->prepare('SELECT hostname, details FROM host where hostname="'.$hostname.'"');
            $stmt->execute(); 
            $req = $stmt->fetch();
            if(isset($req['details'])){
                $req = $db->prepare('UPDATE host SET details=:details WHERE hostname=:hostname');
                $req->bindParam(':details',$details);
                $req->bindParam(':hostname',$hostname);
                $req->execute();
            }else{
                $req = $db->prepare('INSERT INTO host (hostname, details) VALUES (?, ?)');
                $array_of_values = array($hostname, $details);
                $req->execute($array_of_values);
            }
        } catch(Exception $e) {
            echo "Can't modify details in database : ".$e->getMessage();
        }
    }
    




    try{
        $stmt = $db->prepare('SELECT DISTINCT events.hostname, host.details FROM events LEFT JOIN host on events.HOSTNAME=host.HOSTNAME ORDER BY events.hostname');
        $stmt->execute(); 
        while($req = $stmt->fetch()){
            echo'
                <form action="hosts_details.php" method="POST">
                    <div style="font-weight:bold;">'.$req['hostname'].'</div>
                    Details :<br />
                    <input type="hidden" name="hostname" value="'.base64_encode($req['hostname']).'">
                    <textarea name="details" rows="5" cols="33">'.$req['details'].'</textarea>
                    <br />
                    <input type="submit" value="Save changes">
                </form><br /><br /><br />
            ';
        }
        
    } catch(Exception $e) {
        echo "Can't retrieve token from server : ".$e->getMessage();
        die();
        exit();
    }

    
        
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
