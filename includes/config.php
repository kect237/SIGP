<?php
$host = "sql112.infinityfree.com"; // le nom de notre host InfinityFree
$dbname = "if0_42619144_sgip_db"; // le nom de notre  DB
$username = "if0_42619144"; // le nom de notre user
$password = "SgipGroupe2026"; // notre mot de passe DB

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Erreur connexion: " . $e->getMessage());
}
?>