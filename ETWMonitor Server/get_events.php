<?php
    $db = new PDO('sqlite:./ETWMonitor.sqlite');
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $db->prepare('SELECT events.hostname, timedate, event, level, host.details FROM events LEFT JOIN host ON host.hostname=events.hostname order by events.id desc');
    $stmt->execute(); 

    while($req = $stmt->fetch()) {
        $event = preg_replace("/[\n\r]/", "<br />", $req['event']);
        echo '<tr>
            <td>'.$req['hostname'].'</td>
            <td>'.$req['timedate'].'</td>
            <td>'.$event.'</td>
            <td>'.$req['level'].'</td>
            <td>'.$req['details'].'</td>
        </tr>';
    }
?>