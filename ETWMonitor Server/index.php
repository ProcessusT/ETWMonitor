<!DOCTYPE html>
<html>
<head>
	<title>ETWMonitor</title>
</head>
<body>
	<div id="monitor">
		<?php
			$db = new PDO('sqlite:./ETWMonitor.sqlite');
		    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
		    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		    $stmt = $db->prepare('SELECT hostname, timedate, event FROM events order by id asc');
		    $stmt->execute(); 

			while($req = $stmt->fetch()) {
				echo $req['hostname'].' at ['.$req['timedate'].'] : '.$req['event']."<br /><br />";
			}
	    ?>
	</div>
</body>
</html>