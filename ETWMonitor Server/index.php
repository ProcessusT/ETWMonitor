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
                        <h1 class="mt-4">Dashboard</h1>
                        
                        <div class="row">
                            <div class="col-xl-6">
                                <div class="card mb-4">
                                    <div class="card-header">
                                        <i class="fas fa-chart-area me-1"></i>
                                        Number of events
                                    </div>
                                    <div class="card-body"><canvas id="numberofevents" width="100%" height="40"></canvas></div>
                                </div>
                            </div>
                            <div class="col-xl-6">
                                <div class="card mb-4">
                                    <div class="card-header">
                                        <i class="fas fa-chart-bar me-1"></i>
                                        Number of events per host
                                    </div>
                                    <div class="card-body"><canvas id="numberofcritical" width="100%" height="40"></canvas></div>
                                </div>
                            </div>
                        </div>
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-table me-1"></i>
                                Latest events
                            </div>
                            <div class="card-body">
                                <table id="datatablesSimple">
                                    <thead>
                                        <tr>
                                            <th>Host</th>
                                            <th>datetime</th>
                                            <th>Event</th>
                                            <th>Level</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody id="get_events">
                                    </tbody>
                                    <script type="text/javascript">
                                            const xhttp = new XMLHttpRequest();
                                            xhttp.open("GET", "get_events.php", false);
                                            xhttp.send();
                                            document.getElementById("get_events").innerHTML = xhttp.responseText;

                                            setInterval(function() {
                                                const xhttp = new XMLHttpRequest();
                                                xhttp.open("GET", "get_events.php", false);
                                                xhttp.send();
                                                document.getElementById("get_events").innerHTML = xhttp.responseText;
                                            }, 1000);
                                    </script>
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
        <script>
                Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
                Chart.defaults.global.defaultFontColor = '#292b2c';

                var ctx = document.getElementById("numberofevents");
                var myLineChart = new Chart(ctx, {
                  type: 'line',
                  data: {
                    

                    <?php
                        $max=0;

                        $db = new PDO('sqlite:./ETWMonitor.sqlite');
                        $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                        $labels = array();
                        for ($i = 7; $i >= 0; $i--) {
                            $that_date = date('Y-m-d',strtotime("-".$i." days"));
                            $stmt = $db->prepare('SELECT count(timedate) as thatdate FROM "events" WHERE timedate like "'.$that_date.'%";');
                            $stmt->execute(); 
                            $req = $stmt->fetch();
                            array_push($labels, [$that_date, $req['thatdate']]);
                        }

                        echo 'labels: [';
                        $i=0;
                        foreach($labels as $label){
                            if($i>0){
                                echo ",";
                            }
                            $i++;
                            echo '"'.$label[0].'"';
                        }
                        echo '],';
                        
                    ?>

                    datasets: [{
                      label: "Events",
                      lineTension: 0.3,
                      backgroundColor: "rgba(2,117,216,0.2)",
                      borderColor: "rgba(2,117,216,1)",
                      pointRadius: 5,
                      pointBackgroundColor: "rgba(2,117,216,1)",
                      pointBorderColor: "rgba(255,255,255,0.8)",
                      pointHoverRadius: 5,
                      pointHoverBackgroundColor: "rgba(2,117,216,1)",
                      pointHitRadius: 50,
                      pointBorderWidth: 2,
                    <?php 
                        echo 'data: [';
                        $i=0;
                        foreach($labels as $label){
                            if($i>0){
                                echo ",";
                            }
                            $i++;
                            echo $label[1];
                            if($max<$label[1]){
                                $max = $label[1];
                            }
                        }
                        echo '],';
                        
                    ?>
                    }],
                  },
                  options: {
                    scales: {
                      xAxes: [{
                        time: {
                          unit: 'date'
                        },
                        gridLines: {
                          display: false
                        },
                        ticks: {
                          maxTicksLimit: 7
                        }
                      }],
                      yAxes: [{
                        ticks: {
                          min: 0,
                          max: <?php echo $max+50; ?>,
                          maxTicksLimit: 5
                        },
                        gridLines: {
                          color: "rgba(0, 0, 0, .125)",
                        }
                      }],
                    },
                    legend: {
                      display: false
                    }
                  }
                });
        </script>
        <script>
                Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
                Chart.defaults.global.defaultFontColor = '#292b2c';

                var ctx = document.getElementById("numberofcritical");
                var myLineChart = new Chart(ctx, {
                  type: 'bar',
                  data: {
                    <?php
                        $max=0;

                        $db = new PDO('sqlite:./ETWMonitor.sqlite');
                        $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                        $labels = array();
                        $that_date = date('Y-m-d');
                        $stmt = $db->prepare('SELECT DISTINCT hostname FROM "events" LIMIT 5');
                        $stmt->execute(); 
                        while($req = $stmt->fetch()){
                            $stmt__count = $db->prepare('SELECT count(timedate) as nbevents FROM "events" where hostname="'.$req['hostname'].'"');
                            $stmt__count->execute();
                            $req_count = $stmt__count->fetch();
                            array_push($labels, [$req['hostname'], $req_count['nbevents']]);
                        }

                        echo 'labels: [';
                        $i=0;
                        foreach($labels as $label){
                            if($i>0){
                                echo ",";
                            }
                            $i++;
                            echo '"'.$label[0].'"';
                        }
                        echo '],';
                        
                    ?>
                    datasets: [{
                      label: "Events",
                      backgroundColor: "rgba(254,0,0,1)",
                      borderColor: "rgba(254,0,0,1)",
                      <?php 
                        echo 'data: [';
                        $i=0;
                        foreach($labels as $label){
                            if($i>0){
                                echo ",";
                            }
                            $i++;
                            echo $label[1];
                            if($max<$label[1]){
                                $max = $label[1];
                            }
                        }
                        echo '],';
                        
                    ?>
                    }],
                  },
                  options: {
                    scales: {
                      xAxes: [{
                        time: {
                          unit: 'month'
                        },
                        gridLines: {
                          display: false
                        },
                        ticks: {
                          maxTicksLimit: 6
                        }
                      }],
                      yAxes: [{
                        ticks: {
                          min: 0,
                          max: <?php echo $max+50; ?>,
                          maxTicksLimit: 5
                        },
                        gridLines: {
                          display: true
                        }
                      }],
                    },
                    legend: {
                      display: false
                    }
                  }
                });

        </script>
        <script src="https://cdn.jsdelivr.net/npm/simple-datatables@latest" crossorigin="anonymous"></script>
        <script src="js/datatables-simple-demo.js"></script>
    </body>
</html>
