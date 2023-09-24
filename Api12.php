<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1/api_jsonrpc.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
//solicitud curl latencia en crudo
curl_setopt($ch, CURLOPT_POSTFIELDS, "{\"jsonrpc\": \"2.0\", \"method\": \"item.get\", \"params\": { \"tags\": [{\"tag\": \"latencia\",\"value\": \"ping\",\"operator\": 1}]} ,\"id\": 1, \"auth\":\"a8ff88d71e800950cdea7ab185061b42af54c0ccc79e1da0f2cff0e466f54ee5\"}");

$headers = array();
$headers[] = 'Content-Type: application/json';
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch,CURLOPT_RETURNTRANSFER,TRUE);

$response = curl_exec($ch);
$result = json_decode($response, true);

//solicitud curl cvss en crudo
curl_setopt($ch, CURLOPT_POSTFIELDS, "{\"jsonrpc\": \"2.0\", \"method\": \"item.get\", \"params\": { \"output\": \"extend\",\"hostids\": \"10542\"  } ,\"id\": 1, \"auth\": \"a8ff88d71e800950cdea7ab185061b42af54c0ccc79e1da0f2cff0e466f54ee5\"}");
$response2 = curl_exec($ch);
$result2 = json_decode($response2, true);

array_shift($result['result']); //elimina el primer elemento del array de latencia ya que regresa un host del sistema zabbix

 //cierra conexion curl
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
//cierra conexion curl
curl_close($ch);

$arreglo1 = array();
//busca en el arreglo de latencia solo los campos que queremos y los guarda en el arreglo1
foreach($result['result'] as $results ) {
     
    array_push($arreglo1,["hostid"=> ($results['hostid']),"latency_ms" => ($results['lastvalue']*1000),"timemachine" => ($results['lastclock']),]);

}



$arreglo2 = array();
foreach($result2['result'] as $results2 ) {
    $extract = $results2['name'];
    preg_match('/\[(.*?)\]/', $extract, $matches);
    $devicename = $matches[1];
    
    $hostidcvss = preg_replace("/[^0-9]/","",$results2['key_']);
    
    array_push($arreglo2,["hostid"=> $hostidcvss,"devicename" => $devicename,"cvss" => $results2['lastvalue']]);
 
   
}



$hostid = array_column($arreglo1, 'hostid');

array_multisort($hostid, SORT_ASC, $arreglo1);

$hostid = array_column($arreglo2, 'hostid');

array_multisort($hostid, SORT_ASC, $arreglo2);


$arreglo3 = array_replace_recursive($arreglo1,$arreglo2);



$arreglofinal = json_encode(array_replace_recursive($arreglo1, $arreglo2, array('totalhost' => count($arreglo3))), true);

print_r($arreglofinal);
?>

